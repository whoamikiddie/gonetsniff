package fingerprint

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/sirupsen/logrus"
	"github.com/user/gonetsniff/internal/interfaces"
)

// DeviceFingerprint represents a unique device fingerprint
type DeviceFingerprint struct {
	IP              string
	MAC             string
	TTL             uint8
	WindowSize      uint16
	UserAgent       string
	OSType          string
	DeviceType      string
	OpenPorts       []int
	ClosedPorts     []int
	TCPFlags        map[string]bool
	DHCPFingerprint string
	Confidence      float64
	LastUpdated     time.Time
}

// Fingerprinter identifies devices based on various fingerprinting techniques
type Fingerprinter struct {
	interfaces     []interfaces.NetworkInterface
	devices        map[string]*DeviceFingerprint // IP -> Fingerprint
	mutex          sync.RWMutex
	stopChan       chan struct{}
	wg             sync.WaitGroup
	osSignatures   map[string]map[string]string // OS signatures
	deviceDatabase map[string]map[string]string // Device type database
}

// NewFingerprinter creates a new device fingerprinter
func NewFingerprinter(ifaces []interfaces.NetworkInterface) *Fingerprinter {
	return &Fingerprinter{
		interfaces:     ifaces,
		devices:        make(map[string]*DeviceFingerprint),
		stopChan:       make(chan struct{}),
		osSignatures:   loadOSSignatures(),
		deviceDatabase: loadDeviceDatabase(),
	}
}

// Start begins device fingerprinting
func (f *Fingerprinter) Start() {
	logrus.Info("Starting device fingerprinter")

	// Start passive fingerprinting on each interface
	for _, iface := range f.interfaces {
		f.wg.Add(1)
		go func(iface interfaces.NetworkInterface) {
			defer f.wg.Done()
			if err := f.passiveFingerprint(iface); err != nil {
				logrus.Errorf("Error fingerprinting on interface %s: %v", iface.Name, err)
			}
		}(iface)
	}

	// Start active fingerprinting in a separate goroutine
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-f.stopChan:
				return
			case <-ticker.C:
				f.activeFingerprint()
			}
		}
	}()
}

// Stop stops the fingerprinter
func (f *Fingerprinter) Stop() {
	close(f.stopChan)
	f.wg.Wait()
}

// GetDevices returns a copy of the current device fingerprints
func (f *Fingerprinter) GetDevices() map[string]DeviceFingerprint {
	f.mutex.RLock()
	defer f.mutex.RUnlock()

	devices := make(map[string]DeviceFingerprint)
	for ip, device := range f.devices {
		devices[ip] = *device
	}
	return devices
}

// GetDeviceByIP returns a specific device fingerprint
func (f *Fingerprinter) GetDeviceByIP(ip string) (DeviceFingerprint, bool) {
	f.mutex.RLock()
	defer f.mutex.RUnlock()

	device, exists := f.devices[ip]
	if !exists {
		return DeviceFingerprint{}, false
	}
	return *device, true
}

// passiveFingerprint performs passive fingerprinting on an interface
func (f *Fingerprinter) passiveFingerprint(iface interfaces.NetworkInterface) error {
	// Open device for capturing
	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("failed to open interface %s: %v", iface.Name, err)
	}
	defer handle.Close()

	// Set filter to capture TCP, HTTP, and DHCP traffic
	if err := handle.SetBPFFilter("tcp or port 80 or port 67 or port 68"); err != nil {
		return fmt.Errorf("failed to set BPF filter on interface %s: %v", iface.Name, err)
	}

	logrus.Infof("Passive fingerprinting started on interface %s", iface.Name)

	// Start packet processing
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetChan := packetSource.Packets()

	for {
		select {
		case <-f.stopChan:
			return nil
		case packet, ok := <-packetChan:
			if !ok {
				return nil
			}
			f.processPacket(packet)
		}
	}
}

// processPacket analyzes a packet for fingerprinting information
func (f *Fingerprinter) processPacket(packet gopacket.Packet) {
	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		return
	}

	// Get IP layer
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}
	ip := ipLayer.(*layers.IPv4)
	
	// Get TCP layer for TCP fingerprinting
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		f.processTCPFingerprint(ip.SrcIP.String(), ip.TTL, tcp.Window, tcp)
	}
	
	// Check for HTTP User-Agent
	if applicationLayer := packet.ApplicationLayer(); applicationLayer != nil {
		payload := string(applicationLayer.Payload())
		if strings.Contains(payload, "User-Agent:") {
			f.processHTTPUserAgent(ip.SrcIP.String(), payload)
		}
	}
	
	// Check for DHCP fingerprinting
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		if udp.SrcPort == 68 && udp.DstPort == 67 {
			// DHCP request
			if dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4); dhcpLayer != nil {
				dhcp := dhcpLayer.(*layers.DHCPv4)
				f.processDHCPFingerprint(ip.SrcIP.String(), dhcp)
			}
		}
	}
}

// processTCPFingerprint analyzes TCP information for fingerprinting
func (f *Fingerprinter) processTCPFingerprint(ipAddr string, ttl uint8, windowSize uint16, tcp *layers.TCP) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	// Get or create device fingerprint
	device, exists := f.devices[ipAddr]
	if !exists {
		device = &DeviceFingerprint{
			IP:          ipAddr,
			TCPFlags:    make(map[string]bool),
			LastUpdated: time.Now(),
		}
		f.devices[ipAddr] = device
	}

	// Update TTL and window size
	device.TTL = ttl
	device.WindowSize = windowSize
	
	// Record TCP flags
	device.TCPFlags["SYN"] = tcp.SYN
	device.TCPFlags["ACK"] = tcp.ACK
	device.TCPFlags["FIN"] = tcp.FIN
	device.TCPFlags["RST"] = tcp.RST
	device.TCPFlags["PSH"] = tcp.PSH
	device.TCPFlags["URG"] = tcp.URG
	device.TCPFlags["ECE"] = tcp.ECE
	device.TCPFlags["CWR"] = tcp.CWR
	
	// Attempt OS fingerprinting based on TTL and window size
	device.OSType = f.identifyOS(ttl, windowSize)
	device.LastUpdated = time.Now()
}

// processHTTPUserAgent extracts and processes User-Agent information
func (f *Fingerprinter) processHTTPUserAgent(ipAddr string, payload string) {
	// Extract User-Agent
	uaStart := strings.Index(payload, "User-Agent:")
	if uaStart == -1 {
		return
	}
	
	uaStart += 11 // Length of "User-Agent:"
	uaEnd := strings.Index(payload[uaStart:], "\r\n")
	if uaEnd == -1 {
		return
	}
	
	userAgent := strings.TrimSpace(payload[uaStart : uaStart+uaEnd])
	
	f.mutex.Lock()
	defer f.mutex.Unlock()
	
	// Get or create device fingerprint
	device, exists := f.devices[ipAddr]
	if !exists {
		device = &DeviceFingerprint{
			IP:          ipAddr,
			TCPFlags:    make(map[string]bool),
			LastUpdated: time.Now(),
		}
		f.devices[ipAddr] = device
	}
	
	// Update User-Agent
	device.UserAgent = userAgent
	
	// Attempt to identify OS and device type from User-Agent
	osType, deviceType := f.identifyFromUserAgent(userAgent)
	if osType != "" {
		device.OSType = osType
	}
	if deviceType != "" {
		device.DeviceType = deviceType
	}
	
	device.LastUpdated = time.Now()
}

// processDHCPFingerprint extracts and processes DHCP fingerprinting information
func (f *Fingerprinter) processDHCPFingerprint(ipAddr string, dhcp *layers.DHCPv4) {
	// Extract DHCP fingerprint (Option 55 - Parameter Request List)
	var dhcpFingerprint string
	for _, option := range dhcp.Options {
		if option.Type == layers.DHCPOptParamsRequest {
			for _, b := range option.Data {
				dhcpFingerprint += fmt.Sprintf("%d,", b)
			}
			if len(dhcpFingerprint) > 0 {
				dhcpFingerprint = dhcpFingerprint[:len(dhcpFingerprint)-1] // Remove trailing comma
			}
			break
		}
	}
	
	if dhcpFingerprint == "" {
		return
	}
	
	f.mutex.Lock()
	defer f.mutex.Unlock()
	
	// Get or create device fingerprint
	device, exists := f.devices[ipAddr]
	if !exists {
		device = &DeviceFingerprint{
			IP:          ipAddr,
			TCPFlags:    make(map[string]bool),
			LastUpdated: time.Now(),
		}
		f.devices[ipAddr] = device
	}
	
	// Update DHCP fingerprint
	device.DHCPFingerprint = dhcpFingerprint
	
	// Attempt to identify OS from DHCP fingerprint
	osType := f.identifyFromDHCP(dhcpFingerprint)
	if osType != "" {
		device.OSType = osType
	}
	
	device.LastUpdated = time.Now()
}

// activeFingerprint performs active fingerprinting
func (f *Fingerprinter) activeFingerprint() {
	logrus.Info("Starting active fingerprinting scan")
	
	// Get list of devices to scan
	f.mutex.RLock()
	ips := make([]string, 0, len(f.devices))
	for ip := range f.devices {
		ips = append(ips, ip)
	}
	f.mutex.RUnlock()
	
	// Perform port scanning on each device
	for _, ip := range ips {
		// Skip if stopped
		select {
		case <-f.stopChan:
			return
		default:
			// Continue
		}
		
		openPorts, closedPorts := f.scanPorts(ip)
		
		f.mutex.Lock()
		if device, exists := f.devices[ip]; exists {
			device.OpenPorts = openPorts
			device.ClosedPorts = closedPorts
			device.LastUpdated = time.Now()
			
			// Update device type based on open ports
			deviceType := f.identifyFromPorts(openPorts)
			if deviceType != "" {
				device.DeviceType = deviceType
			}
		}
		f.mutex.Unlock()
	}
	
	logrus.Info("Active fingerprinting scan completed")
}

// scanPorts performs a port scan on a target IP
func (f *Fingerprinter) scanPorts(ip string) ([]int, []int) {
	commonPorts := []int{21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995, 3306, 3389, 5900, 8080}
	openPorts := []int{}
	closedPorts := []int{}
	
	for _, port := range commonPorts {
		// Skip if stopped
		select {
		case <-f.stopChan:
			return openPorts, closedPorts
		default:
			// Continue
		}
		
		address := fmt.Sprintf("%s:%d", ip, port)
		conn, err := net.DialTimeout("tcp", address, 500*time.Millisecond)
		
		if err == nil {
			openPorts = append(openPorts, port)
			conn.Close()
		} else {
			closedPorts = append(closedPorts, port)
		}
		
		// Be nice and don't flood the network
		time.Sleep(100 * time.Millisecond)
	}
	
	return openPorts, closedPorts
}

// identifyOS attempts to identify the operating system based on TTL and window size
func (f *Fingerprinter) identifyOS(ttl uint8, windowSize uint16) string {
	// Common TTL values
	switch {
	case ttl <= 64:
		return "Linux/Unix"
	case ttl <= 128:
		return "Windows"
	case ttl <= 255:
		return "Cisco/Network"
	default:
		return "Unknown"
	}
}

// identifyFromUserAgent attempts to identify OS and device type from User-Agent
func (f *Fingerprinter) identifyFromUserAgent(userAgent string) (string, string) {
	userAgent = strings.ToLower(userAgent)
	
	var osType, deviceType string
	
	// OS detection
	switch {
	case strings.Contains(userAgent, "windows"):
		osType = "Windows"
	case strings.Contains(userAgent, "mac os") || strings.Contains(userAgent, "macos"):
		osType = "macOS"
	case strings.Contains(userAgent, "linux"):
		osType = "Linux"
	case strings.Contains(userAgent, "android"):
		osType = "Android"
	case strings.Contains(userAgent, "ios") || strings.Contains(userAgent, "iphone") || strings.Contains(userAgent, "ipad"):
		osType = "iOS"
	}
	
	// Device type detection
	switch {
	case strings.Contains(userAgent, "mobile") || strings.Contains(userAgent, "android") || strings.Contains(userAgent, "iphone"):
		deviceType = "Mobile"
	case strings.Contains(userAgent, "tablet") || strings.Contains(userAgent, "ipad"):
		deviceType = "Tablet"
	case strings.Contains(userAgent, "tv") || strings.Contains(userAgent, "smart-tv"):
		deviceType = "Smart TV"
	case strings.Contains(userAgent, "playstation") || strings.Contains(userAgent, "xbox"):
		deviceType = "Gaming Console"
	default:
		deviceType = "PC/Desktop"
	}
	
	return osType, deviceType
}

// identifyFromDHCP attempts to identify OS from DHCP fingerprint
func (f *Fingerprinter) identifyFromDHCP(fingerprint string) string {
	// Common DHCP fingerprints
	switch fingerprint {
	case "1,3,6,15,31,33,43,44,46,47,119,121,249,252":
		return "Windows 10"
	case "1,3,6,15,31,33,43,44,46,47,119,121,249,252,252":
		return "Windows 11"
	case "1,3,6,15,119,252":
		return "Linux"
	case "1,3,6,15,119,95,252":
		return "Android"
	case "1,3,6,15,119,95,252,44,46":
		return "iOS"
	default:
		return ""
	}
}

// identifyFromPorts attempts to identify device type from open ports
func (f *Fingerprinter) identifyFromPorts(openPorts []int) string {
	// Check for specific port combinations
	hasWeb := contains(openPorts, 80) || contains(openPorts, 443) || contains(openPorts, 8080)
	hasSSH := contains(openPorts, 22)
	hasTelnet := contains(openPorts, 23)
	hasDB := contains(openPorts, 3306) || contains(openPorts, 5432)
	hasFileSharing := contains(openPorts, 139) || contains(openPorts, 445)
	hasRDP := contains(openPorts, 3389)
	hasVNC := contains(openPorts, 5900)
	
	switch {
	case hasWeb && hasSSH && hasDB:
		return "Server"
	case hasWeb && !hasSSH && !hasDB:
		return "IoT Device"
	case hasTelnet && !hasWeb:
		return "Network Device"
	case hasFileSharing && hasRDP:
		return "Windows PC"
	case hasVNC:
		return "Desktop Computer"
	default:
		return ""
	}
}

// loadOSSignatures loads OS signature database
func loadOSSignatures() map[string]map[string]string {
	// In a real implementation, this would load from a file or database
	return map[string]map[string]string{
		"windows": {
			"ttl": "128",
			"window_size": "8192",
		},
		"linux": {
			"ttl": "64",
			"window_size": "5840",
		},
		"macos": {
			"ttl": "64",
			"window_size": "65535",
		},
	}
}

// loadDeviceDatabase loads device signature database
func loadDeviceDatabase() map[string]map[string]string {
	// In a real implementation, this would load from a file or database
	return map[string]map[string]string{
		"router": {
			"ports": "23,80,443",
		},
		"printer": {
			"ports": "9100,515,631",
		},
		"camera": {
			"ports": "80,554",
		},
	}
}

// contains checks if a slice contains a value
func contains(slice []int, val int) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}
