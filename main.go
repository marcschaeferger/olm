package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/fosrl/newt/logger"
	"github.com/fosrl/olm/websocket"
	"github.com/vishvananda/netlink"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type WgData struct {
	Endpoint  string        `json:"endpoint"`
	PublicKey string        `json:"publicKey"`
	ServerIP  string        `json:"serverIP"`
	TunnelIP  string        `json:"tunnelIP"`
	Targets   TargetsByType `json:"targets"`
}

type TargetsByType struct {
	UDP []string `json:"udp"`
	TCP []string `json:"tcp"`
}

type TargetData struct {
	Targets []string `json:"targets"`
}

func fixKey(key string) string {
	// Remove any whitespace
	key = strings.TrimSpace(key)

	// Decode from base64
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		logger.Fatal("Error decoding base64")
	}

	// Convert to hex
	return hex.EncodeToString(decoded)
}

const (
	ENV_WG_TUN_FD             = "WG_TUN_FD"
	ENV_WG_UAPI_FD            = "WG_UAPI_FD"
	ENV_WG_PROCESS_FOREGROUND = "WG_PROCESS_FOREGROUND"
)

// func startPingCheck(serverIP string, stopChan chan struct{}) {
// 	ticker := time.NewTicker(10 * time.Second)
// 	defer ticker.Stop()

// 	go func() {
// 		for {
// 			select {
// 			case <-ticker.C:
// 				err := ping(serverIP)
// 				if err != nil {
// 					logger.Warn("Periodic ping failed: %v", err)
// 					logger.Warn("HINT: Check if the WireGuard tunnel is up and the server is reachable")
// 				}
// 			case <-stopChan:
// 				logger.Info("Stopping ping check")
// 				return
// 			}
// 		}
// 	}()
// }

// func pingWithRetry(dst string) error {
// 	const (
// 		maxAttempts = 5
// 		retryDelay  = 2 * time.Second
// 	)

// 	var lastErr error
// 	for attempt := 1; attempt <= maxAttempts; attempt++ {
// 		logger.Info("Ping attempt %d of %d", attempt, maxAttempts)

// 		if err := ping(dst); err != nil {
// 			lastErr = err
// 			logger.Warn("Ping attempt %d failed: %v", attempt, err)

// 			if attempt < maxAttempts {
// 				time.Sleep(retryDelay)
// 				continue
// 			}
// 			return fmt.Errorf("all ping attempts failed after %d tries, last error: %w",
// 				maxAttempts, lastErr)
// 		}

// 		// Successful ping
// 		return nil
// 	}

// 	return fmt.Errorf("unexpected error: all ping attempts failed")
// }

func parseLogLevel(level string) logger.LogLevel {
	switch strings.ToUpper(level) {
	case "DEBUG":
		return logger.DEBUG
	case "INFO":
		return logger.INFO
	case "WARN":
		return logger.WARN
	case "ERROR":
		return logger.ERROR
	case "FATAL":
		return logger.FATAL
	default:
		return logger.INFO // default to INFO if invalid level provided
	}
}

func mapToWireGuardLogLevel(level logger.LogLevel) int {
	switch level {
	case logger.DEBUG:
		return device.LogLevelVerbose
	// case logger.INFO:
	// return device.LogLevel
	case logger.WARN:
		return device.LogLevelError
	case logger.ERROR, logger.FATAL:
		return device.LogLevelSilent
	default:
		return device.LogLevelSilent
	}
}

func resolveDomain(domain string) (string, error) {
	// Check if there's a port in the domain
	host, port, err := net.SplitHostPort(domain)
	if err != nil {
		// No port found, use the domain as is
		host = domain
		port = ""
	}

	// Remove any protocol prefix if present
	if strings.HasPrefix(host, "http://") {
		host = strings.TrimPrefix(host, "http://")
	} else if strings.HasPrefix(host, "https://") {
		host = strings.TrimPrefix(host, "https://")
	}

	// Lookup IP addresses
	ips, err := net.LookupIP(host)
	if err != nil {
		return "", fmt.Errorf("DNS lookup failed: %v", err)
	}

	if len(ips) == 0 {
		return "", fmt.Errorf("no IP addresses found for domain %s", host)
	}

	// Get the first IPv4 address if available
	var ipAddr string
	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			ipAddr = ipv4.String()
			break
		}
	}

	// If no IPv4 found, use the first IP (might be IPv6)
	if ipAddr == "" {
		ipAddr = ips[0].String()
	}

	// Add port back if it existed
	if port != "" {
		ipAddr = net.JoinHostPort(ipAddr, port)
	}

	return ipAddr, nil
}

// ConfigureInterface configures a network interface with an IP address and brings it up
func ConfigureInterface(interfaceName string, ipAddr string) error {
	// Parse the IP address and network
	ip, ipNet, err := net.ParseCIDR(ipAddr)
	if err != nil {
		return fmt.Errorf("invalid IP address: %v", err)
	}

	switch runtime.GOOS {
	case "linux":
		return configureLinux(interfaceName, ip, ipNet)
	case "darwin":
		return configureDarwin(interfaceName, ip, ipNet)
	default:
		return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
}

func configureDarwin(interfaceName string, ip net.IP, ipNet *net.IPNet) error {
	// Get interface by name
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return fmt.Errorf("failed to get interface %s: %v", interfaceName, err)
	}

	// print something using the iface
	logger.Info("Interface %s: %v", interfaceName, iface)

	// Create socket
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("failed to create socket: %v", err)
	}
	defer syscall.Close(fd)

	// Prepare interface request structure
	ifr := struct {
		Name  [16]byte
		Flags uint16
	}{}
	copy(ifr.Name[:], interfaceName)

	// Get current flags
	if err := ioctl(fd, syscall.SIOCGIFFLAGS, uintptr(unsafe.Pointer(&ifr))); err != nil {
		return fmt.Errorf("failed to get interface flags: %v", err)
	}

	// Set interface up
	ifr.Flags |= syscall.IFF_UP | syscall.IFF_RUNNING
	if err := ioctl(fd, syscall.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&ifr))); err != nil {
		return fmt.Errorf("failed to set interface up: %v", err)
	}

	// Prepare address structure
	var addr syscall.SockaddrInet4
	copy(addr.Addr[:], ip.To4())

	// Create interface address request
	ifra := struct {
		Name [16]byte
		Addr syscall.RawSockaddrInet4
		Mask syscall.RawSockaddrInet4
	}{}
	copy(ifra.Name[:], interfaceName)
	copy(ifra.Addr.Addr[:], ip.To4())
	copy(ifra.Mask.Addr[:], ipNet.Mask)

	// Set IP address
	if err := ioctl(fd, syscall.SIOCSIFADDR, uintptr(unsafe.Pointer(&ifra))); err != nil {
		return fmt.Errorf("failed to set interface address: %v", err)
	}

	// Set netmask
	if err := ioctl(fd, syscall.SIOCSIFNETMASK, uintptr(unsafe.Pointer(&ifra))); err != nil {
		return fmt.Errorf("failed to set interface netmask: %v", err)
	}

	return nil
}

// Helper function for ioctl calls
func ioctl(fd int, request uint, argp uintptr) error {
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(fd),
		uintptr(request),
		argp,
	)
	if errno != 0 {
		return os.NewSyscallError("ioctl", errno)
	}
	return nil
}

func configureLinux(interfaceName string, ip net.IP, ipNet *net.IPNet) error {
	// Get the interface
	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		return fmt.Errorf("failed to get interface %s: %v", interfaceName, err)
	}

	// Create the IP address attributes
	addr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   ip,
			Mask: ipNet.Mask,
		},
	}

	// Add the IP address to the interface
	if err := netlink.AddrAdd(link, addr); err != nil {
		return fmt.Errorf("failed to add IP address: %v", err)
	}

	// Bring up the interface
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to bring up interface: %v", err)
	}

	return nil
}

func main() {
	var (
		endpoint             string
		id                   string
		secret               string
		mtu                  string
		mtuInt               int
		dns                  string
		privateKey           wgtypes.Key
		err                  error
		logLevel             string
		interfaceName        string
		generateAndSaveKeyTo string
		reachableAt          string
	)

	// if PANGOLIN_ENDPOINT, OLM_ID, and OLM_SECRET are set as environment variables, they will be used as default values
	endpoint = os.Getenv("PANGOLIN_ENDPOINT")
	id = os.Getenv("OLM_ID")
	secret = os.Getenv("OLM_SECRET")
	mtu = os.Getenv("MTU")
	dns = os.Getenv("DNS")
	logLevel = os.Getenv("LOG_LEVEL")
	interfaceName = os.Getenv("INTERFACE")
	generateAndSaveKeyTo = os.Getenv("GENERATE_AND_SAVE_KEY_TO")
	reachableAt = os.Getenv("REACHABLE_AT")

	if endpoint == "" {
		flag.StringVar(&endpoint, "endpoint", "", "Endpoint of your pangolin server")
	}
	if id == "" {
		flag.StringVar(&id, "id", "", "Olm ID")
	}
	if secret == "" {
		flag.StringVar(&secret, "secret", "", "Olm secret")
	}
	if mtu == "" {
		flag.StringVar(&mtu, "mtu", "1280", "MTU to use")
	}
	if dns == "" {
		flag.StringVar(&dns, "dns", "8.8.8.8", "DNS server to use")
	}
	if logLevel == "" {
		flag.StringVar(&logLevel, "log-level", "INFO", "Log level (DEBUG, INFO, WARN, ERROR, FATAL)")
	}
	if interfaceName == "" {
		flag.StringVar(&interfaceName, "interface", "wg2", "Name of the WireGuard interface")
	}
	if generateAndSaveKeyTo == "" {
		flag.StringVar(&generateAndSaveKeyTo, "generateAndSaveKeyTo", "", "Path to save generated private key")
	}
	if reachableAt == "" {
		flag.StringVar(&reachableAt, "reachableAt", "", "Endpoint of the http server to tell remote config about")
	}

	// do a --version check
	version := flag.Bool("version", false, "Print the version")

	flag.Parse()

	if *version {
		fmt.Println("Olm version replaceme")
		os.Exit(0)
	}

	logger.Init()
	loggerLevel := parseLogLevel(logLevel)
	logger.GetLogger().SetLevel(parseLogLevel(logLevel))

	// parse the mtu string into an int
	mtuInt, err = strconv.Atoi(mtu)
	if err != nil {
		logger.Fatal("Failed to parse MTU: %v", err)
	}

	privateKey, err = wgtypes.GeneratePrivateKey()
	if err != nil {
		logger.Fatal("Failed to generate private key: %v", err)
	}

	// Create a new olm
	olm, err := websocket.NewClient(
		id,     // CLI arg takes precedence
		secret, // CLI arg takes precedence
		endpoint,
	)
	if err != nil {
		logger.Fatal("Failed to create olm: %v", err)
	}

	// Create TUN device and network stack
	var dev *device.Device
	// var connected bool
	var wgData WgData
	var uapi *os.File

	olm.RegisterHandler("olm/terminate", func(msg websocket.WSMessage) {
		logger.Info("Received terminate message")
		olm.Close()
	})

	pingStopChan := make(chan struct{})
	defer close(pingStopChan)

	// Register handlers for different message types
	olm.RegisterHandler("olm/wg/connect", func(msg websocket.WSMessage) {
		logger.Info("Received registration message")

		// if connected {
		// logger.Info("Already connected! But I will send a ping anyway...")
		// err := pingWithRetry(wgData.ServerIP)
		// 	if err != nil {
		// 		// Handle complete failure after all retries
		// 		logger.Warn("Failed to ping %s: %v", wgData.ServerIP, err)
		// 		logger.Warn("HINT: Do you have UDP port 51280 (or the port in config.yml) open on your Pangolin server?")
		// 	}
		// 	return
		// }

		logger.Info("Received message: %v", msg.Data)

		jsonData, err := json.Marshal(msg.Data)
		if err != nil {
			logger.Info("Error marshaling data: %v", err)
			return
		}

		if err := json.Unmarshal(jsonData, &wgData); err != nil {
			logger.Info("Error unmarshaling target data: %v", err)
			return
		}

		tdev, err := func() (tun.Device, error) {
			tunFdStr := os.Getenv(ENV_WG_TUN_FD)
			if tunFdStr == "" {
				return tun.CreateTUN(interfaceName, mtuInt)
			}

			// construct tun device from supplied fd

			fd, err := strconv.ParseUint(tunFdStr, 10, 32)
			if err != nil {
				return nil, err
			}

			err = unix.SetNonblock(int(fd), true)
			if err != nil {
				return nil, err
			}

			file := os.NewFile(uintptr(fd), "")
			return tun.CreateTUNFromFile(file, mtuInt)
		}()

		if err != nil {
			logger.Error("Failed to create TUN device: %v", err)
			return
		}

		realInterfaceName, err2 := tdev.Name()
		if err2 == nil {
			interfaceName = realInterfaceName
		}

		// open UAPI file (or use supplied fd)

		fileUAPI, err := func() (*os.File, error) {
			uapiFdStr := os.Getenv(ENV_WG_UAPI_FD)
			if uapiFdStr == "" {
				return ipc.UAPIOpen(interfaceName)
			}

			// use supplied fd

			fd, err := strconv.ParseUint(uapiFdStr, 10, 32)
			if err != nil {
				return nil, err
			}

			return os.NewFile(uintptr(fd), ""), nil
		}()
		if err != nil {
			logger.Error("UAPI listen error: %v", err)
			os.Exit(1)
			return
		}

		// Create WireGuard device
		dev = device.NewDevice(tdev, conn.NewDefaultBind(), device.NewLogger(
			mapToWireGuardLogLevel(loggerLevel),
			"wireguard: ",
		))

		errs := make(chan error)

		uapi, err := ipc.UAPIListen(interfaceName, fileUAPI)
		if err != nil {
			logger.Error("Failed to listen on uapi socket: %v", err)
			os.Exit(1)
		}

		go func() {
			for {
				conn, err := uapi.Accept()
				if err != nil {
					errs <- err
					return
				}
				go dev.IpcHandle(conn)
			}
		}()

		logger.Info("UAPI listener started")

		endpoint, err := resolveDomain(wgData.Endpoint)
		if err != nil {
			logger.Error("Failed to resolve endpoint: %v", err)
			return
		}

		// Configure WireGuard
		config := fmt.Sprintf(`private_key=%s
public_key=%s
allowed_ip=%s/32
endpoint=%s
persistent_keepalive_interval=5`, fixKey(privateKey.String()), fixKey(wgData.PublicKey), wgData.ServerIP, endpoint)

		err = dev.IpcSet(config)
		if err != nil {
			logger.Error("Failed to configure WireGuard device: %v", err)
		}

		// Bring up the device
		err = dev.Up()
		if err != nil {
			logger.Error("Failed to bring up WireGuard device: %v", err)
		}

		// configure the interface
		err = ConfigureInterface(realInterfaceName, wgData.TunnelIP)
		if err != nil {
			logger.Error("Failed to configure interface: %v", err)
		}

		logger.Info("WireGuard device created.")
		// Ping to bring the tunnel up on the server side quickly
		// ping(tnet, wgData.ServerIP)
		// err = pingWithRetry(wgData.ServerIP)
		// if err != nil {
		// 	// Handle complete failure after all retries
		// 	logger.Error("Failed to ping %s: %v", wgData.ServerIP, err)
		// }

		// if !connected {
		// 	logger.Info("Starting ping check")
		// 	startPingCheck(wgData.ServerIP, pingStopChan)
		// }
		// connected = true
	})

	olm.OnConnect(func() error {
		publicKey := privateKey.PublicKey()
		logger.Debug("Public key: %s", publicKey)

		err := olm.SendMessage("olm/wg/register", map[string]interface{}{
			"publicKey": publicKey.String(),
		})
		if err != nil {
			logger.Error("Failed to send registration message: %v", err)
			return err
		}

		logger.Info("Sent registration message")
		return nil
	})

	// Connect to the WebSocket server
	if err := olm.Connect(); err != nil {
		logger.Fatal("Failed to connect to server: %v", err)
	}
	defer olm.Close()

	// Wait for interrupt signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	uapi.Close()
	dev.Close()
}
