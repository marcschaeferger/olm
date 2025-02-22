package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

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

var (
	stopHolepunch chan struct{}
	stopRegister  chan struct{}
)

const (
	ENV_WG_TUN_FD             = "WG_TUN_FD"
	ENV_WG_UAPI_FD            = "WG_UAPI_FD"
	ENV_WG_PROCESS_FOREGROUND = "WG_PROCESS_FOREGROUND"
)

type fixedPortBind struct {
	port uint16
	conn.Bind
}

func (b *fixedPortBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	// Ignore the requested port and use our fixed port
	return b.Bind.Open(b.port)
}

func NewFixedPortBind(port uint16) conn.Bind {
	return &fixedPortBind{
		port: port,
		Bind: conn.NewDefaultBind(),
	}
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
func ConfigureInterface(interfaceName string, wgData WgData) error {
	var ipAddr string = wgData.TunnelIP
	var destIP string = wgData.ServerIP

	// Parse the IP address and network
	ip, ipNet, err := net.ParseCIDR(ipAddr)
	if err != nil {
		return fmt.Errorf("invalid IP address: %v", err)
	}

	switch runtime.GOOS {
	case "linux":
		return configureLinux(interfaceName, ip, ipNet)
	case "darwin":
		return configureDarwin(interfaceName, ip, destIP)
	default:
		return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
}

func findUnusedUTUN() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("failed to list interfaces: %v", err)
	}
	used := make(map[int]bool)
	re := regexp.MustCompile(`^utun(\d+)$`)
	for _, iface := range ifaces {
		if matches := re.FindStringSubmatch(iface.Name); len(matches) == 2 {
			if num, err := strconv.Atoi(matches[1]); err == nil {
				used[num] = true
			}
		}
	}
	// Try utun0 up to utun255.
	for i := 0; i < 256; i++ {
		if !used[i] {
			return fmt.Sprintf("utun%d", i), nil
		}
	}
	return "", fmt.Errorf("no unused utun interface found")
}

func configureDarwin(interfaceName string, ip net.IP, destIp string) error {
	logger.Info("Configuring darwin interface: %s", interfaceName)

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return fmt.Errorf("failed to get interface %s: %v", interfaceName, err)
	}
	logger.Info("Interface %s: %v", interfaceName, iface)

	ipStr := ip.String()

	cmd := exec.Command("ifconfig", interfaceName, ipStr+"/24", destIp, "up") // TODO: dont hard code /24
	// print the command used
	logger.Info("Running command: %v", cmd)

	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ifconfig command failed: %v, output: %s", err, out)
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

// TODO: we need to send the token with this probably to verify auth
func sendUDPHolePunch(serverAddr string, olmID string, sourcePort uint16) error {
	// Bind to specific local port
	localAddr := &net.UDPAddr{
		Port: int(sourcePort),
		IP:   net.IPv4zero,
	}

	remoteAddr, err := net.ResolveUDPAddr("udp", serverAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %v", err)
	}

	conn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		return fmt.Errorf("failed to bind UDP socket: %v", err)
	}
	defer conn.Close()

	payload := struct {
		OlmID string `json:"olmId"`
	}{
		OlmID: olmID,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %v", err)
	}

	_, err = conn.WriteToUDP(data, remoteAddr)
	if err != nil {
		return fmt.Errorf("failed to send UDP packet: %v", err)
	}

	return nil
}

func keepSendingUDPHolePunch(endpoint string, olmID string, sourcePort uint16) {
	var host = endpoint
	if strings.HasPrefix(host, "http://") {
		host = strings.TrimPrefix(host, "http://")
	} else if strings.HasPrefix(host, "https://") {
		host = strings.TrimPrefix(host, "https://")
	}

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stopHolepunch:
			logger.Info("Stopping UDP holepunch")
			return
		case <-ticker.C:
			if err := sendUDPHolePunch(host+":21820", olmID, sourcePort); err != nil {
				logger.Error("Failed to send UDP hole punch: %v", err)
			}
		}
	}
}

func sendRegistration(olm *websocket.Client, publicKey string) error {
	err := olm.SendMessage("olm/wg/register", map[string]interface{}{
		"publicKey": publicKey,
	})
	if err != nil {
		logger.Error("Failed to send registration message: %v", err)
		return err
	}
	logger.Info("Sent registration message")
	return nil
}

func keepSendingRegistration(olm *websocket.Client, publicKey string) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stopRegister:
			logger.Info("Stopping registration messages")
			return
		case <-ticker.C:
			if err := sendRegistration(olm, publicKey); err != nil {
				logger.Error("Failed to send periodic registration: %v", err)
			}
		}
	}
}

func FindAvailableUDPPort(minPort, maxPort uint16) (uint16, error) {
	if maxPort < minPort {
		return 0, fmt.Errorf("invalid port range: min=%d, max=%d", minPort, maxPort)
	}

	for port := minPort; port <= maxPort; port++ {
		// Create the UDP address to test
		addr := &net.UDPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: int(port),
		}

		// Attempt to create a UDP listener
		conn, err := net.ListenUDP("udp", addr)
		if err != nil {
			continue // Port is in use or there was an error, try next port
		}

		// Close the connection immediately
		_ = conn.SetDeadline(time.Now())
		conn.Close()

		return port, nil
	}

	return 0, fmt.Errorf("no available UDP ports found in range %d-%d", minPort, maxPort)
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

	stopHolepunch = make(chan struct{})
	stopRegister = make(chan struct{})

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
		flag.StringVar(&endpoint, "endpoint", "", "Endpoint of your Pangolin server")
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

	sourcePort, err := FindAvailableUDPPort(49152, 65535)
	if err != nil {
		fmt.Printf("Error finding available port: %v\n", err)
		os.Exit(1)
	}

	// Create TUN device and network stack
	var dev *device.Device
	var wgData WgData
	var uapi *os.File

	olm.RegisterHandler("olm/terminate", func(msg websocket.WSMessage) {
		logger.Info("Received terminate message")
		olm.Close()
	})

	// Register handlers for different message types
	olm.RegisterHandler("olm/wg/connect", func(msg websocket.WSMessage) {
		logger.Info("Received message: %v", msg.Data)

		close(stopRegister)

		jsonData, err := json.Marshal(msg.Data)
		if err != nil {
			logger.Info("Error marshaling data: %v", err)
			return
		}

		if err := json.Unmarshal(jsonData, &wgData); err != nil {
			logger.Info("Error unmarshaling target data: %v", err)
			return
		}

		// NEED TO DETERMINE AVAILABLE TUN DEVICE HERE
		tdev, err := func() (tun.Device, error) {
			tunFdStr := os.Getenv(ENV_WG_TUN_FD)

			// if on macOS, call findUnusedUTUN to get a new utun device
			if runtime.GOOS == "darwin" {
				interfaceName, err := findUnusedUTUN()
				if err != nil {
					return nil, err
				}
				return tun.CreateTUN(interfaceName, mtuInt)
			}

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

		dev = device.NewDevice(tdev, NewFixedPortBind(uint16(sourcePort)), device.NewLogger(
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
persistent_keepalive_interval=1`, fixKey(privateKey.String()), fixKey(wgData.PublicKey), wgData.ServerIP, endpoint)

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
		err = ConfigureInterface(realInterfaceName, wgData)
		if err != nil {
			logger.Error("Failed to configure interface: %v", err)
		}

		close(stopHolepunch)
		logger.Info("WireGuard device created.")
	})

	olm.OnConnect(func() error {
		publicKey := privateKey.PublicKey()
		logger.Debug("Public key: %s", publicKey)

		go keepSendingRegistration(olm, publicKey.String())

		logger.Info("Sent registration message")
		return nil
	})

	// start sending UDP hole punch
	go keepSendingUDPHolePunch(endpoint, id, sourcePort)

	// Connect to the WebSocket server
	if err := olm.Connect(); err != nil {
		logger.Fatal("Failed to connect to server: %v", err)
	}
	defer olm.Close()

	// Wait for interrupt signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	select {
	case <-stopHolepunch:
		// Channel already closed, do nothing
	default:
		close(stopHolepunch)
	}

	select {
	case <-stopRegister:
		// Channel already closed
	default:
		close(stopRegister)
	}

	uapi.Close()
	dev.Close()
}
