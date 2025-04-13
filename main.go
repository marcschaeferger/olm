//go:build !windows

package main

import (
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
	"github.com/fosrl/olm/peermonitor"
	"github.com/fosrl/olm/websocket"
	"github.com/vishvananda/netlink"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// ConfigureInterface configures a network interface with an IP address and brings it up
func ConfigureInterface(interfaceName string, wgData WgData) error {
	var ipAddr string = wgData.TunnelIP

	// Parse the IP address and network
	ip, ipNet, err := net.ParseCIDR(ipAddr)
	if err != nil {
		return fmt.Errorf("invalid IP address: %v", err)
	}

	switch runtime.GOOS {
	case "linux":
		return configureLinux(interfaceName, ip, ipNet)
	case "darwin":
		return configureDarwin(interfaceName, ip, ipNet, wgData.TunnelIP) // TODO: is tunnelip correct here? I think it has to do with the route addition in macos
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

func configureDarwin(interfaceName string, ip net.IP, ipNet *net.IPNet, destIp string) error {
	logger.Info("Configuring darwin interface: %s", interfaceName)

	_, cidr := ipNet.Mask.Size()
	ipStr := fmt.Sprintf("%s/%d", ip.String(), cidr)

	cmd := exec.Command("ifconfig", interfaceName, ipStr, destIp, "up")
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
	stopPing = make(chan struct{})

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
	var wgData WgData
	var holePunchData HolePunchData
	var uapi *os.File
	var tdev tun.Device

	sourcePort, err := FindAvailableUDPPort(49152, 65535)
	if err != nil {
		fmt.Printf("Error finding available port: %v\n", err)
		os.Exit(1)
	}

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
	})

	connectTimes := 0
	// Register handlers for different message types
	olm.RegisterHandler("olm/wg/connect", func(msg websocket.WSMessage) {
		logger.Info("Received message: %v", msg.Data)

		if connectTimes > 0 {
			logger.Info("Already connected. Ignoring new connection request.")
			return
		}

		connectTimes++

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

		// NEED TO DETERMINE AVAILABLE TUN DEVICE HERE
		tdev, err = func() (tun.Device, error) {
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

		primaryRelay, err := resolveDomain(endpoint)
		if err != nil {
			logger.Warn("Failed to resolve endpoint: %v", err)
		}

		peerMonitor = peermonitor.NewPeerMonitor(
			func(siteID int, connected bool, rtt time.Duration) {
				if connected {
					logger.Info("Peer %d is now connected (RTT: %v)", siteID, rtt)
				} else {
					logger.Warn("Peer %d is disconnected", siteID)
				}
			},
			fixKey(privateKey.String()),
			olm,
			dev,
		)

		// Configure WireGuard with all sites as peers
		var configBuilder strings.Builder

		// Start with the private key
		configBuilder.WriteString(fmt.Sprintf("private_key=%s\n", fixKey(privateKey.String())))

		// Add each site as a peer
		for _, site := range wgData.Sites {
			siteHost, err := resolveDomain(site.Endpoint)
			if err != nil {
				logger.Warn("Failed to resolve endpoint for site %d: %v", site.SiteId, err)
				continue
			}

			// split off the cidr of the server ip which is just a string and add /32 for the allowed ip
			allowedIp := strings.Split(site.ServerIP, "/")
			if len(allowedIp) > 1 {
				allowedIp[1] = "32"
			} else {
				allowedIp = append(allowedIp, "32")
			}
			allowedIpStr := strings.Join(allowedIp, "/")

			// Include peer info
			configBuilder.WriteString(fmt.Sprintf("public_key=%s\n", fixKey(site.PublicKey)))
			configBuilder.WriteString(fmt.Sprintf("allowed_ip=%s\n", allowedIpStr))
			configBuilder.WriteString(fmt.Sprintf("endpoint=%s\n", siteHost))
			configBuilder.WriteString("persistent_keepalive_interval=1\n")

			// take the first part of the allowedIp and the port from the endpoint and put them together
			monitorAddress := strings.Split(site.ServerIP, "/")[0]

			monitorPeer := fmt.Sprintf("%s:%d", monitorAddress, site.ServerPort+1) // +1 for the monitor port

			wgConfig := &peermonitor.WireGuardConfig{
				SiteID:       site.SiteId,
				PublicKey:    fixKey(site.PublicKey),
				ServerIP:     strings.Split(site.ServerIP, "/")[0],
				Endpoint:     site.Endpoint,
				PrimaryRelay: primaryRelay, // Use the main endpoint as relay
			}

			err = peerMonitor.AddPeer(site.SiteId, monitorPeer, wgConfig)
			if err != nil {
				logger.Warn("Failed to setup monitoring for site %d: %v", site.SiteId, err)
			} else {
				logger.Info("Started monitoring for site %d at %s", site.SiteId, monitorPeer)
			}
		}

		config := configBuilder.String()
		logger.Debug("WireGuard config: %s", config)

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

		peerMonitor.Start()

		logger.Info("WireGuard device created.")
	})

	olm.RegisterHandler("olm/wg/holepunch", func(msg websocket.WSMessage) {
		logger.Info("Received message: %v", msg.Data)

		jsonData, err := json.Marshal(msg.Data)
		if err != nil {
			logger.Info("Error marshaling data: %v", err)
			return
		}

		if err := json.Unmarshal(jsonData, &holePunchData); err != nil {
			logger.Info("Error unmarshaling target data: %v", err)
			return
		}

		gerbilServerPubKey = holePunchData.ServerPubKey
	})

	olm.OnConnect(func() error {
		publicKey := privateKey.PublicKey()
		logger.Debug("Public key: %s", publicKey)

		go keepSendingRegistration(olm, publicKey.String())
		go keepSendingPing(olm)

		logger.Info("Sent registration message")
		return nil
	})

	olm.OnTokenUpdate(func(token string) {
		olmToken = token
	})

	// Connect to the WebSocket server
	if err := olm.Connect(); err != nil {
		logger.Fatal("Failed to connect to server: %v", err)
	}
	defer olm.Close()

	go keepSendingUDPHolePunch(endpoint, id, sourcePort)

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

	select {
	case <-stopPing:
		// Channel already closed
	default:
		close(stopPing)
	}

	uapi.Close()
	dev.Close()
}
