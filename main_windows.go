//go:build windows

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"

	"github.com/fosrl/newt/logger"
	"github.com/fosrl/olm/websocket"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// ConfigureInterface configures a network interface with an IP address and brings it up
func ConfigureInterface(interfaceName string, wgData WgData) error {
	var ipAddr string = wgData.TunnelIP
	var destIP string = wgData.ServerIP

	if runtime.GOOS == "windows" {
		return configureWindows(interfaceName, ipAddr, destIP)
	}

	return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
}

func configureWindows(interfaceName string, ipAddr, destIP string) error {
	logger.Info("Configuring Windows interface: %s", interfaceName)

	// Parse the IP address and network
	ip, ipNet, err := net.ParseCIDR(ipAddr)
	if err != nil {
		return fmt.Errorf("invalid IP address: %v", err)
	}

	// Set the IP address using netsh
	// Windows uses the 'netsh' command to configure network interfaces
	maskBits, _ := ipNet.Mask.Size()

	// create a mask string like 255.255.255.0 from the maskBits
	mask := net.CIDRMask(maskBits, 32)
	maskIP := net.IP(mask)

	cmd := exec.Command("netsh", "interface", "ipv4", "set", "address",
		fmt.Sprintf("name=%s", interfaceName),
		"source=static",
		fmt.Sprintf("addr=%s", ip.String()),
		fmt.Sprintf("mask=%s", maskIP.String()))

	logger.Info("Running command: %v", cmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh command failed: %v, output: %s", err, out)
	}

	// Add a route to the destination IP
	cmd = exec.Command("netsh", "interface", "ipv4", "add", "route",
		fmt.Sprintf("%s/32", destIP),
		fmt.Sprintf("interface=%s", interfaceName),
		"metric=1")

	logger.Info("Running command: %v", cmd)
	out, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh route command failed: %v, output: %s", err, out)
	}

	return nil
}

func main() {
	var (
		endpoint      string
		id            string
		secret        string
		mtu           string
		mtuInt        int
		dns           string
		privateKey    wgtypes.Key
		err           error
		logLevel      string
		interfaceName string
	)

	stopHolepunch = make(chan struct{})
	stopRegister = make(chan struct{})

	// Check OS
	if runtime.GOOS != "windows" {
		fmt.Println("This version of olm is only for Windows systems")
		os.Exit(1)
	}

	// if PANGOLIN_ENDPOINT, OLM_ID, and OLM_SECRET are set as environment variables, they will be used as default values
	endpoint = os.Getenv("PANGOLIN_ENDPOINT")
	id = os.Getenv("OLM_ID")
	secret = os.Getenv("OLM_SECRET")
	mtu = os.Getenv("MTU")
	dns = os.Getenv("DNS")
	logLevel = os.Getenv("LOG_LEVEL")
	interfaceName = os.Getenv("INTERFACE")

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
		flag.StringVar(&interfaceName, "interface", "olm", "Name of the WireGuard interface")
	}

	// do a --version check
	version := flag.Bool("version", false, "Print the version")
	flag.Parse()

	if *version {
		fmt.Println("Olm Windows version replaceme")
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
	var uapi net.Listener
	var tdev tun.Device

	olm.RegisterHandler("olm/terminate", func(msg websocket.WSMessage) {
		logger.Info("Received terminate message")
		olm.Close()
	})

	olm.RegisterHandler("olm/wg/update", func(msg websocket.WSMessage) {
		jsonData, err := json.Marshal(msg.Data)
		if err != nil {
			logger.Info("Error marshaling data: %v", err)
			return
		}
		if err := json.Unmarshal(jsonData, &wgData); err != nil {
			logger.Info("Error unmarshaling target data: %v", err)
			return
		}
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
	})

	// Register handlers for different message types
	olm.RegisterHandler("olm/wg/connect", func(msg websocket.WSMessage) {
		logger.Info("Received message: %v", msg.Data)
		close(stopRegister)
		// if there is an existing tunnel then close it
		if dev != nil {
			logger.Info("Got new message. Closing existing tunnel!")
			dev.Close()
		}
		jsonData, err := json.Marshal(msg.Data)
		if err != nil {
			logger.Info("Error marshaling data: %v", err)
			return
		}
		if err := json.Unmarshal(jsonData, &wgData); err != nil {
			logger.Info("Error unmarshaling target data: %v", err)
			return
		}

		// Windows-specific TUN device creation
		tdev, err = tun.CreateTUN(interfaceName, mtuInt)
		if err != nil {
			logger.Error("Failed to create TUN device: %v", err)
			return
		}

		realInterfaceName, err2 := tdev.Name()
		if err2 == nil {
			interfaceName = realInterfaceName
		}

		// Create the WireGuard device
		dev = device.NewDevice(tdev, NewFixedPortBind(uint16(sourcePort)), device.NewLogger(
			mapToWireGuardLogLevel(loggerLevel),
			"wireguard: ",
		))

		// Setup UAPI for Windows
		uapi, err = ipc.UAPIListen(interfaceName)
		if err != nil {
			logger.Error("Failed to listen on uapi socket: %v", err)
			os.Exit(1)
		}

		errs := make(chan error)
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

		host, err := resolveDomain(wgData.Endpoint)
		if err != nil {
			logger.Error("Failed to resolve endpoint: %v", err)
			return
		}

		// Configure WireGuard
		config := fmt.Sprintf(`private_key=%s
public_key=%s
allowed_ip=%s/32
endpoint=%s
persistent_keepalive_interval=1`, fixKey(privateKey.String()), fixKey(wgData.PublicKey), wgData.ServerIP, host)
		err = dev.IpcSet(config)
		if err != nil {
			logger.Error("Failed to configure WireGuard device: %v", err)
		}

		// Bring up the device
		err = dev.Up()
		if err != nil {
			logger.Error("Failed to bring up WireGuard device: %v", err)
		}

		// Configure the interface
		err = ConfigureInterface(realInterfaceName, wgData)
		if err != nil {
			logger.Error("Failed to configure interface: %v", err)
		}

		close(stopHolepunch)
		// Monitor the connection for activity
		monitorConnection(dev, func() {
			host, err := resolveDomain(endpoint)
			if err != nil {
				logger.Error("Failed to resolve endpoint: %v", err)
				return
			}
			// Configure WireGuard
			config := fmt.Sprintf(`private_key=%s
public_key=%s
allowed_ip=%s/32
endpoint=%s:21820
persistent_keepalive_interval=1`, fixKey(privateKey.String()), fixKey(wgData.PublicKey), wgData.ServerIP, host)
			err = dev.IpcSet(config)
			if err != nil {
				logger.Error("Failed to configure WireGuard device: %v", err)
			}
			logger.Info("Adjusted to point to relay!")
		})
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
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, windows.SIGTERM)
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

	if uapi != nil {
		uapi.Close()
	}

	if dev != nil {
		dev.Close()
	}
}
