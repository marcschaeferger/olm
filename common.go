package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/fosrl/newt/logger"
	"github.com/fosrl/olm/peermonitor"
	"github.com/fosrl/olm/websocket"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/exp/rand"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type WgData struct {
	Sites    []SiteConfig `json:"sites"`
	TunnelIP string       `json:"tunnelIP"`
}

type SiteConfig struct {
	SiteId     int    `json:"siteId"`
	Endpoint   string `json:"endpoint"`
	PublicKey  string `json:"publicKey"`
	ServerIP   string `json:"serverIP"`
	ServerPort uint16 `json:"serverPort"`
}

type TargetsByType struct {
	UDP []string `json:"udp"`
	TCP []string `json:"tcp"`
}

type TargetData struct {
	Targets []string `json:"targets"`
}

type HolePunchMessage struct {
	NewtID string `json:"newtId"`
}

type HolePunchData struct {
	ServerPubKey string `json:"serverPubKey"`
}

type EncryptedHolePunchMessage struct {
	EphemeralPublicKey string `json:"ephemeralPublicKey"`
	Nonce              []byte `json:"nonce"`
	Ciphertext         []byte `json:"ciphertext"`
}

var (
	peerMonitor        *peermonitor.PeerMonitor
	stopHolepunch      chan struct{}
	stopRegister       chan struct{}
	olmToken           string
	gerbilServerPubKey string
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
	// First handle any protocol prefix
	domain = strings.TrimPrefix(strings.TrimPrefix(domain, "https://"), "http://")

	// if there are any trailing slashes, remove them
	domain = strings.TrimSuffix(domain, "/")

	// Now split host and port
	host, port, err := net.SplitHostPort(domain)
	if err != nil {
		// No port found, use the domain as is
		host = domain
		port = ""
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

func sendUDPHolePunch(serverAddr string, olmID string, sourcePort uint16) error {

	if gerbilServerPubKey == "" || olmToken == "" {
		return nil
	}

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
		Token string `json:"token"`
	}{
		OlmID: olmID,
		Token: olmToken,
	}

	// Convert payload to JSON
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %v", err)
	}

	// Encrypt the payload using the server's WireGuard public key
	encryptedPayload, err := encryptPayload(payloadBytes, gerbilServerPubKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt payload: %v", err)
	}

	jsonData, err := json.Marshal(encryptedPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal encrypted payload: %v", err)
	}

	_, err = conn.WriteToUDP(jsonData, remoteAddr)
	if err != nil {
		return fmt.Errorf("failed to send UDP packet: %v", err)
	}

	logger.Debug("Sent UDP hole punch to %s: %s", serverAddr, string(jsonData))

	return nil
}

func encryptPayload(payload []byte, serverPublicKey string) (interface{}, error) {
	// Generate an ephemeral keypair for this message
	ephemeralPrivateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral private key: %v", err)
	}
	ephemeralPublicKey := ephemeralPrivateKey.PublicKey()

	// Parse the server's public key
	serverPubKey, err := wgtypes.ParseKey(serverPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse server public key: %v", err)
	}

	// Use X25519 for key exchange (replacing deprecated ScalarMult)
	var ephPrivKeyFixed [32]byte
	copy(ephPrivKeyFixed[:], ephemeralPrivateKey[:])

	// Perform X25519 key exchange
	sharedSecret, err := curve25519.X25519(ephPrivKeyFixed[:], serverPubKey[:])
	if err != nil {
		return nil, fmt.Errorf("failed to perform X25519 key exchange: %v", err)
	}

	// Create an AEAD cipher using the shared secret
	aead, err := chacha20poly1305.New(sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to create AEAD cipher: %v", err)
	}

	// Generate a random nonce
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	// Encrypt the payload
	ciphertext := aead.Seal(nil, nonce, payload, nil)

	// Prepare the final encrypted message
	encryptedMsg := struct {
		EphemeralPublicKey string `json:"ephemeralPublicKey"`
		Nonce              []byte `json:"nonce"`
		Ciphertext         []byte `json:"ciphertext"`
	}{
		EphemeralPublicKey: ephemeralPublicKey.String(),
		Nonce:              nonce,
		Ciphertext:         ciphertext,
	}

	return encryptedMsg, nil
}

func keepSendingUDPHolePunch(endpoint string, olmID string, sourcePort uint16) {
	host, err := resolveDomain(endpoint)
	if err != nil {
		logger.Error("Failed to resolve endpoint: %v", err)
		return
	}

	// Execute once immediately before starting the loop
	if err := sendUDPHolePunch(host+":21820", olmID, sourcePort); err != nil {
		logger.Error("Failed to send UDP hole punch: %v", err)
	}

	ticker := time.NewTicker(250 * time.Millisecond)
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
	ticker := time.NewTicker(1 * time.Second)
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

	// Create a slice of all ports in the range
	portRange := make([]uint16, maxPort-minPort+1)
	for i := range portRange {
		portRange[i] = minPort + uint16(i)
	}

	// Fisher-Yates shuffle to randomize the port order
	rand.Seed(uint64(time.Now().UnixNano()))
	for i := len(portRange) - 1; i > 0; i-- {
		j := rand.Intn(i + 1)
		portRange[i], portRange[j] = portRange[j], portRange[i]
	}

	// Try each port in the randomized order
	for _, port := range portRange {
		addr := &net.UDPAddr{
			IP:   net.ParseIP("127.0.0.1"),
			Port: int(port),
		}
		conn, err := net.ListenUDP("udp", addr)
		if err != nil {
			continue // Port is in use or there was an error, try next port
		}
		_ = conn.SetDeadline(time.Now())
		conn.Close()
		return port, nil
	}

	return 0, fmt.Errorf("no available UDP ports found in range %d-%d", minPort, maxPort)
}
