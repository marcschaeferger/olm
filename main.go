package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/fosrl/newt/logger"
	"github.com/fosrl/newt/websocket"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
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
		logger.Fatal("Error decoding base64:", err)
	}

	// Convert to hex
	return hex.EncodeToString(decoded)
}

const (
	ENV_WG_TUN_FD             = "WG_TUN_FD"
	ENV_WG_UAPI_FD            = "WG_UAPI_FD"
	ENV_WG_PROCESS_FOREGROUND = "WG_PROCESS_FOREGROUND"
)

func ping(dev *device.Device, dst string) error {
	logger.Info("Pinging %s over WireGuard tunnel", dst)

	// Create a raw socket for ICMP
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return fmt.Errorf("failed to create ICMP socket: %w", err)
	}
	defer conn.Close()

	// Parse destination IP
	dstIP := net.ParseIP(dst)
	if dstIP == nil {
		return fmt.Errorf("invalid destination IP: %s", dst)
	}

	// Create ICMP message
	requestPing := icmp.Echo{
		ID:   os.Getpid() & 0xffff,
		Seq:  rand.Intn(1 << 16),
		Data: []byte("wireguard ping"),
	}

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &requestPing,
	}

	// Marshal the message
	icmpBytes, err := msg.Marshal(nil)
	if err != nil {
		return fmt.Errorf("failed to marshal ICMP message: %w", err)
	}

	// Set read deadline
	if err := conn.SetReadDeadline(time.Now().Add(time.Second * 10)); err != nil {
		return fmt.Errorf("failed to set read deadline: %w", err)
	}

	// Send the ping
	start := time.Now()
	_, err = conn.WriteTo(icmpBytes, &net.IPAddr{IP: dstIP})
	if err != nil {
		return fmt.Errorf("failed to write ICMP packet: %w", err)
	}

	// Wait for reply
	reply := make([]byte, 1500)
	n, peer, err := conn.ReadFrom(reply)
	if err != nil {
		return fmt.Errorf("failed to read ICMP packet: %w", err)
	}

	// Parse reply
	replyMsg, err := icmp.ParseMessage(1, reply[:n])
	if err != nil {
		return fmt.Errorf("failed to parse ICMP reply: %w", err)
	}

	// Verify reply
	switch replyMsg.Type {
	case ipv4.ICMPTypeEchoReply:
		replyEcho, ok := replyMsg.Body.(*icmp.Echo)
		if !ok {
			return fmt.Errorf("invalid reply type: got %T, want *icmp.Echo", replyMsg.Body)
		}
		if replyEcho.ID != requestPing.ID || replyEcho.Seq != requestPing.Seq {
			return fmt.Errorf("invalid echo reply: got id=%d seq=%d, want id=%d seq=%d",
				replyEcho.ID, replyEcho.Seq, requestPing.ID, requestPing.Seq)
		}
	default:
		return fmt.Errorf("unexpected ICMP message type: %+v", replyMsg)
	}

	duration := time.Since(start)
	logger.Info("Ping reply from %v: time=%v", peer, duration)
	return nil
}

func startPingCheck(dev *device.Device, serverIP string, stopChan chan struct{}) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	go func() {
		for {
			select {
			case <-ticker.C:
				err := ping(dev, serverIP)
				if err != nil {
					logger.Warn("Periodic ping failed: %v", err)
					logger.Warn("HINT: Check if the WireGuard tunnel is up and the server is reachable")
				}
			case <-stopChan:
				logger.Info("Stopping ping check")
				return
			}
		}
	}()
}

func pingWithRetry(dev *device.Device, dst string) error {
	const (
		maxAttempts = 5
		retryDelay  = 2 * time.Second
	)

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		logger.Info("Ping attempt %d of %d", attempt, maxAttempts)

		if err := ping(dev, dst); err != nil {
			lastErr = err
			logger.Warn("Ping attempt %d failed: %v", attempt, err)

			if attempt < maxAttempts {
				time.Sleep(retryDelay)
				continue
			}
			return fmt.Errorf("all ping attempts failed after %d tries, last error: %w",
				maxAttempts, lastErr)
		}

		// Successful ping
		return nil
	}

	return fmt.Errorf("unexpected error: all ping attempts failed")
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

	// if PANGOLIN_ENDPOINT, NEWT_ID, and NEWT_SECRET are set as environment variables, they will be used as default values
	endpoint = os.Getenv("PANGOLIN_ENDPOINT")
	id = os.Getenv("NEWT_ID")
	secret = os.Getenv("NEWT_SECRET")
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
		flag.StringVar(&id, "id", "", "Newt ID")
	}
	if secret == "" {
		flag.StringVar(&secret, "secret", "", "Newt secret")
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
		flag.StringVar(&interfaceName, "interface", "wg-1", "Name of the WireGuard interface")
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
		fmt.Println("Newt version replaceme")
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

	// Create a new client
	client, err := websocket.NewClient(
		id,     // CLI arg takes precedence
		secret, // CLI arg takes precedence
		endpoint,
	)
	if err != nil {
		logger.Fatal("Failed to create client: %v", err)
	}

	// Create TUN device and network stack
	var dev *device.Device
	var connected bool
	var wgData WgData

	client.RegisterHandler("client/terminate", func(msg websocket.WSMessage) {
		logger.Info("Received terminate message")
		client.Close()
	})

	pingStopChan := make(chan struct{})
	defer close(pingStopChan)

	// Register handlers for different message types
	client.RegisterHandler("client/wg/connect", func(msg websocket.WSMessage) {
		logger.Info("Received registration message")

		if connected {
			logger.Info("Already connected! But I will send a ping anyway...")
			err := pingWithRetry(dev, wgData.ServerIP)
			if err != nil {
				// Handle complete failure after all retries
				logger.Warn("Failed to ping %s: %v", wgData.ServerIP, err)
				logger.Warn("HINT: Do you have UDP port 51280 (or the port in config.yml) open on your Pangolin server?")
			}
			return
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

		// logger.Info("Received: %+v", msg)
		// tun, tnet, err = netstack.CreateNetTUN(
		// 	[]netip.Addr{netip.MustParseAddr(wgData.TunnelIP)},
		// 	[]netip.Addr{netip.MustParseAddr(dns)},
		// 	mtuInt)
		// if err != nil {
		// 	logger.Error("Failed to create TUN device: %v", err)
		// }

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

		// Create WireGuard device
		dev = device.NewDevice(tdev, conn.NewDefaultBind(), device.NewLogger(
			mapToWireGuardLogLevel(loggerLevel),
			"wireguard: ",
		))

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
persistent_keepalive_interval=5`, fixKey(fmt.Sprintf("%s", privateKey)), fixKey(wgData.PublicKey), wgData.ServerIP, endpoint)

		err = dev.IpcSet(config)
		if err != nil {
			logger.Error("Failed to configure WireGuard device: %v", err)
		}

		// Bring up the device
		err = dev.Up()
		if err != nil {
			logger.Error("Failed to bring up WireGuard device: %v", err)
		}

		logger.Info("WireGuard device created. Lets ping the server now...")
		// Ping to bring the tunnel up on the server side quickly
		// ping(tnet, wgData.ServerIP)
		err = pingWithRetry(dev, wgData.ServerIP)
		if err != nil {
			// Handle complete failure after all retries
			logger.Error("Failed to ping %s: %v", wgData.ServerIP, err)
		}

		if !connected {
			logger.Info("Starting ping check")
			startPingCheck(dev, wgData.ServerIP, pingStopChan)
		}
		connected = true
	})

	client.OnConnect(func() error {
		publicKey := privateKey.PublicKey()
		logger.Debug("Public key: %s", publicKey)

		err := client.SendMessage("client/wg/register", map[string]interface{}{
			"publicKey": fmt.Sprintf("%s", publicKey),
		})
		if err != nil {
			logger.Error("Failed to send registration message: %v", err)
			return err
		}

		logger.Info("Sent registration message")
		return nil
	})

	// Connect to the WebSocket server
	if err := client.Connect(); err != nil {
		logger.Fatal("Failed to connect to server: %v", err)
	}
	defer client.Close()

	// Wait for interrupt signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	// Cleanup
	dev.Close()
}
