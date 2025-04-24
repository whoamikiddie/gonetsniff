package display

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/whoamikiddie/gonetsniff/internal/analyzer"
	"github.com/whoamikiddie/gonetsniff/internal/arp"
	"github.com/whoamikiddie/gonetsniff/internal/bandwidth"
	"github.com/whoamikiddie/gonetsniff/internal/dns"
	"github.com/whoamikiddie/gonetsniff/internal/fingerprint"
	"github.com/whoamikiddie/gonetsniff/internal/gateway"
	"github.com/whoamikiddie/gonetsniff/internal/geoip"
	"github.com/whoamikiddie/gonetsniff/internal/http"
	"github.com/whoamikiddie/gonetsniff/internal/scanner"
	"github.com/whoamikiddie/gonetsniff/internal/spoof"
	"github.com/whoamikiddie/gonetsniff/internal/tls"
	"github.com/whoamikiddie/gonetsniff/internal/uniqueid"
	"net"
)

// DeviceActivity tracks a device's network activity
type DeviceActivity struct {
	IP           string
	MAC          string
	Vendor       string
	Interface    string
	Hostname     string
	DeviceType   string
	OpenPorts    []int
	IsGateway    bool
	FirstSeen    time.Time
	LastSeen     time.Time
	DNSDomains   map[string]time.Time // Domain -> Last Access Time
	HTTPDomains  map[string]time.Time // Domain -> Last Access Time
	TLSDomains   map[string]time.Time // Domain -> Last Access Time
	// Bandwidth stats
	BytesReceived  uint64
	BytesSent      uint64
	RateReceived   float64
	RateSent       float64
	// Geolocation data
	Country      string
	City         string
	ISP          string
	// Protocol data
	TopProtocols  map[string]uint64 // Protocol -> Bytes
	// Device fingerprinting data
	OSType       string
	DeviceModel  string
	DeviceName   string
	Confidence   float64
	UniqueID     string
	// Spoofing status
	IsARPSpoofed bool
	IsDNSSpoofed bool
	mutex        sync.RWMutex
}

// SummaryDisplay manages the display of network activity
type SummaryDisplay struct {
	devices           map[string]*DeviceActivity // IP -> DeviceActivity
	devicesMutex      sync.RWMutex
	arpScanner        *arp.Scanner
	dnsSniff          *dns.Sniffer
	httpParser        *http.Parser
	tlsSniff          *tls.Sniffer
	gatewayDetector   *gateway.Detector
	networkScanner    *scanner.NetworkScanner
	bandwidthMonitor  *bandwidth.Monitor
	protocolAnalyzer  *analyzer.ProtocolAnalyzer
	ipLocator         *geoip.Locator
	deviceFingerprinter *fingerprint.DeviceFingerprinter
	deviceClassifier  *uniqueid.DeviceClassifier
	arpSpoofer        *spoof.ARPSpoofer
	dnsSpoofer        *spoof.DNSSpoofer
	stopChan          chan struct{}
	updateTicker      *time.Ticker
	displayTicker     *time.Ticker
	showAllDomains    bool // Whether to show all domains or just recent ones
	displayMode       int  // 0 = summary, 1 = detailed, 2 = traffic, 3 = protocols, 4 = device fingerprints
}

// NewSummaryDisplay creates a new summary display
func NewSummaryDisplay(
	arpScanner *arp.Scanner, 
	dnsSniff *dns.Sniffer, 
	httpParser *http.Parser, 
	tlsSniff *tls.Sniffer,
	gatewayDetector *gateway.Detector,
	networkScanner *scanner.NetworkScanner,
	bandwidthMonitor *bandwidth.Monitor,
	protocolAnalyzer *analyzer.ProtocolAnalyzer,
	ipLocator *geoip.Locator,
	deviceFingerprinter *fingerprint.DeviceFingerprinter,
	deviceClassifier *uniqueid.DeviceClassifier) *SummaryDisplay {
	
	return &SummaryDisplay{
		devices:            make(map[string]*DeviceActivity),
		arpScanner:         arpScanner,
		dnsSniff:           dnsSniff,
		httpParser:         httpParser,
		tlsSniff:           tlsSniff,
		gatewayDetector:    gatewayDetector,
		networkScanner:     networkScanner,
		bandwidthMonitor:   bandwidthMonitor,
		protocolAnalyzer:   protocolAnalyzer,
		ipLocator:          ipLocator,
		deviceFingerprinter: deviceFingerprinter,
		deviceClassifier:   deviceClassifier,
		stopChan:           make(chan struct{}),
		updateTicker:       time.NewTicker(3 * time.Second),  // Update data every 3 seconds
		displayTicker:      time.NewTicker(5 * time.Second),  // Display summary every 5 seconds
		showAllDomains:     true,                             // Show all domains by default
		displayMode:        0,                                // Start with summary view
	}
}

// Start begins the summary display
func (s *SummaryDisplay) Start() {
	logrus.Info("Starting network activity summary display")

	// Initial update and display
	s.updateData()
	s.displaySummary()

	go func() {
		for {
			select {
			case <-s.updateTicker.C:
				s.updateData()
			case <-s.displayTicker.C:
				s.displaySummary()
			case <-s.stopChan:
				s.updateTicker.Stop()
				s.displayTicker.Stop()
				return
			}
		}
	}()
}

// Stop stops the summary display
func (s *SummaryDisplay) Stop() {
	close(s.stopChan)
}

// updateData updates the device activity data
func (s *SummaryDisplay) updateData() {
	// Update from ARP scanner
	if s.arpScanner != nil {
		devices := s.arpScanner.GetDevices()
		for _, device := range devices {
			s.updateDevice(device.IP, device.MAC, device.Vendor, device.Interface, "", "", nil, false, device.LastSeen)
		}
	}

	// Update from gateway detector
	if s.gatewayDetector != nil {
		gateway := s.gatewayDetector.GetGateway()
		if gateway.IP != "" {
			s.updateDevice(gateway.IP, gateway.MAC, gateway.Vendor, gateway.Interface, "Gateway", "Router", nil, true, time.Now())
		}
	}

	// Update from network scanner
	if s.networkScanner != nil {
		devices := s.networkScanner.GetDevices()
		for _, device := range devices {
			s.updateDevice(device.IP, device.MAC, device.Vendor, device.Interface, device.Hostname, device.DeviceType, device.OpenPorts, device.IsGateway, device.LastSeen)
		}
	}

	// Update from DNS sniffer
	if s.dnsSniff != nil {
		queries := s.dnsSniff.GetQueries()
		for _, query := range queries {
			s.updateDeviceDNS(query.SourceIP, query.Domain)
		}
	}

	// Update from HTTP parser
	if s.httpParser != nil {
		requests := s.httpParser.GetRequests()
		for _, req := range requests {
			s.updateDeviceHTTP(req.SourceIP, req.Host)
		}
	}

	// Update from TLS sniffer
	if s.tlsSniff != nil {
		connections := s.tlsSniff.GetConnections()
		for _, conn := range connections {
			s.updateDeviceTLS(conn.SourceIP, conn.SNI)
		}
	}

	// Update from bandwidth monitor
	if s.bandwidthMonitor != nil {
		stats := s.bandwidthMonitor.GetDeviceStats()
		for ip, stat := range stats {
			s.updateDeviceBandwidth(ip, stat.BytesReceived, stat.BytesSent, stat.RateReceived, stat.RateSent)
		}
	}
	
	// Update from protocol analyzer
	if s.protocolAnalyzer != nil {
		stats := s.protocolAnalyzer.GetDeviceProtocols()
		for ip, protocols := range stats {
			s.updateDeviceProtocols(ip, protocols)
		}
	}
	
	// Update from GeoIP locator
	if s.ipLocator != nil {
		// Get all device IPs
		s.devicesMutex.RLock()
		ips := make([]string, 0, len(s.devices))
		for ip := range s.devices {
			// Only look up external IPs
			if !isPrivateIP(ip) {
				ips = append(ips, ip)
			}
		}
		s.devicesMutex.RUnlock()
		
		// Look up each IP
		for _, ip := range ips {
			location, err := s.ipLocator.Lookup(ip)
			if err == nil {
				s.updateDeviceLocation(ip, location.Country, location.City, location.ISP)
			}
		}
	}
	
	// Update from device fingerprinter
	if s.deviceFingerprinter != nil {
		fingerprints := s.deviceFingerprinter.GetDeviceFingerprints()
		for ip, fingerprint := range fingerprints {
			s.updateDeviceFingerprint(ip, fingerprint.OS, fingerprint.DeviceType, fingerprint.DeviceName)
		}
	}
	
	// Update from device classifier
	if s.deviceClassifier != nil {
		devices := s.deviceClassifier.GetUniqueDevices()
		for ip, device := range devices {
			s.updateDeviceClassification(ip, device.DeviceType, device.DeviceModel, device.OperatingSystem, device.UniqueID, device.Confidence)
		}
	}
}

// updateDevice updates or creates a device entry
func (s *SummaryDisplay) updateDevice(
	ip, mac, vendor, iface, hostname, deviceType string, 
	openPorts []int, isGateway bool, lastSeen time.Time) {
	
	s.devicesMutex.Lock()
	defer s.devicesMutex.Unlock()

	device, exists := s.devices[ip]
	if !exists {
		// Create new device
		device = &DeviceActivity{
			IP:          ip,
			MAC:         mac,
			Vendor:      vendor,
			Interface:   iface,
			Hostname:    hostname,
			DeviceType:  deviceType,
			OpenPorts:   openPorts,
			IsGateway:   isGateway,
			FirstSeen:   time.Now(),
			LastSeen:    lastSeen,
			DNSDomains:  make(map[string]time.Time),
			HTTPDomains: make(map[string]time.Time),
			TLSDomains:  make(map[string]time.Time),
			TopProtocols: make(map[string]uint64),
		}
		s.devices[ip] = device
	} else {
		// Update existing device
		device.mutex.Lock()
		defer device.mutex.Unlock()

		device.LastSeen = lastSeen

		// Only update non-empty fields
		if mac != "" {
			device.MAC = mac
		}
		if vendor != "" {
			device.Vendor = vendor
		}
		if iface != "" {
			device.Interface = iface
		}
		if hostname != "" {
			device.Hostname = hostname
		}
		if deviceType != "" {
			device.DeviceType = deviceType
		}
		if openPorts != nil {
			device.OpenPorts = openPorts
		}
		if isGateway {
			device.IsGateway = true
		}
	}
}

// updateDeviceDNS updates DNS activity for a device
func (s *SummaryDisplay) updateDeviceDNS(ip, domain string) {
	if domain == "" {
		return
	}

	s.devicesMutex.Lock()
	defer s.devicesMutex.Unlock()

	device, exists := s.devices[ip]
	if !exists {
		// Create new device if it doesn't exist
		device = &DeviceActivity{
			IP:          ip,
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
			DNSDomains:  make(map[string]time.Time),
			HTTPDomains: make(map[string]time.Time),
			TLSDomains:  make(map[string]time.Time),
			TopProtocols: make(map[string]uint64),
		}
		s.devices[ip] = device
	}

	device.mutex.Lock()
	defer device.mutex.Unlock()
	device.DNSDomains[domain] = time.Now()
}

// updateDeviceHTTP updates HTTP activity for a device
func (s *SummaryDisplay) updateDeviceHTTP(ip, domain string) {
	if domain == "" {
		return
	}

	s.devicesMutex.Lock()
	defer s.devicesMutex.Unlock()

	device, exists := s.devices[ip]
	if !exists {
		// Create new device if it doesn't exist
		device = &DeviceActivity{
			IP:          ip,
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
			DNSDomains:  make(map[string]time.Time),
			HTTPDomains: make(map[string]time.Time),
			TLSDomains:  make(map[string]time.Time),
			TopProtocols: make(map[string]uint64),
		}
		s.devices[ip] = device
	}

	device.mutex.Lock()
	defer device.mutex.Unlock()
	device.HTTPDomains[domain] = time.Now()
}

// updateDeviceTLS updates TLS activity for a device
func (s *SummaryDisplay) updateDeviceTLS(ip, domain string) {
	if domain == "" {
		return
	}

	s.devicesMutex.Lock()
	defer s.devicesMutex.Unlock()

	device, exists := s.devices[ip]
	if !exists {
		// Create new device if it doesn't exist
		device = &DeviceActivity{
			IP:          ip,
			FirstSeen:   time.Now(),
			LastSeen:    time.Now(),
			DNSDomains:  make(map[string]time.Time),
			HTTPDomains: make(map[string]time.Time),
			TLSDomains:  make(map[string]time.Time),
			TopProtocols: make(map[string]uint64),
		}
		s.devices[ip] = device
	}

	device.mutex.Lock()
	defer device.mutex.Unlock()
	device.TLSDomains[domain] = time.Now()
}

// updateDeviceBandwidth updates bandwidth statistics for a device
func (s *SummaryDisplay) updateDeviceBandwidth(ip string, bytesReceived, bytesSent uint64, rateReceived, rateSent float64) {
	s.devicesMutex.Lock()
	defer s.devicesMutex.Unlock()

	device, exists := s.devices[ip]
	if !exists {
		// Skip if device doesn't exist yet
		return
	}

	device.mutex.Lock()
	defer device.mutex.Unlock()
	
	device.BytesReceived = bytesReceived
	device.BytesSent = bytesSent
	device.RateReceived = rateReceived
	device.RateSent = rateSent
}

// updateDeviceLocation updates geolocation data for a device
func (s *SummaryDisplay) updateDeviceLocation(ip, country, city, isp string) {
	s.devicesMutex.Lock()
	defer s.devicesMutex.Unlock()

	device, exists := s.devices[ip]
	if !exists {
		// Skip if device doesn't exist yet
		return
	}

	device.mutex.Lock()
	defer device.mutex.Unlock()
	
	device.Country = country
	device.City = city
	device.ISP = isp
}

// updateDeviceProtocols updates protocol statistics for a device
func (s *SummaryDisplay) updateDeviceProtocols(ip string, protocols map[string]uint64) {
	s.devicesMutex.Lock()
	defer s.devicesMutex.Unlock()

	device, exists := s.devices[ip]
	if !exists {
		// Skip if device doesn't exist yet
		return
	}

	device.mutex.Lock()
	defer device.mutex.Unlock()
	
	device.TopProtocols = protocols
}

// updateDeviceFingerprint updates fingerprinting data for a device
func (s *SummaryDisplay) updateDeviceFingerprint(ip, os, deviceType, deviceName string) {
	s.devicesMutex.Lock()
	defer s.devicesMutex.Unlock()
	
	device, exists := s.devices[ip]
	if !exists {
		return
	}
	
	device.mutex.Lock()
	defer device.mutex.Unlock()
	
	if os != "" {
		device.OSType = os
	}
	
	if deviceType != "" {
		device.DeviceType = deviceType
	}
	
	if deviceName != "" {
		device.DeviceName = deviceName
	}
}

// updateDeviceClassification updates classification data for a device
func (s *SummaryDisplay) updateDeviceClassification(ip, deviceType, deviceModel, osType, uniqueID string, confidence float64) {
	s.devicesMutex.Lock()
	defer s.devicesMutex.Unlock()
	
	device, exists := s.devices[ip]
	if !exists {
		return
	}
	
	device.mutex.Lock()
	defer device.mutex.Unlock()
	
	if deviceType != "" {
		device.DeviceType = deviceType
	}
	
	if deviceModel != "" {
		device.DeviceModel = deviceModel
	}
	
	if osType != "" {
		device.OSType = osType
	}
	
	device.UniqueID = uniqueID
	device.Confidence = confidence
}

// displaySummary shows a summary of all devices and their activity
func (s *SummaryDisplay) displaySummary() {
	s.devicesMutex.RLock()
	
	// Get all devices
	devices := make([]*DeviceActivity, 0, len(s.devices))
	for _, device := range s.devices {
		devices = append(devices, device)
	}
	s.devicesMutex.RUnlock()
	
	// Sort devices by IP address
	sort.Slice(devices, func(i, j int) bool {
		return devices[i].IP < devices[j].IP
	})
	
	// Clear screen
	fmt.Print("\033[H\033[2J")
	
	// Print header
	width := 80
	headerBorder := strings.Repeat("═", width-2)
	
	fmt.Printf("╔%s╗\n", headerBorder)
	header := "🕷️  GoNetSniff++ Network Activity Monitor  🕷️"
	headerPadding := (width - 2 - len(header)) / 2
	fmt.Printf("║%s%s%s║\n", strings.Repeat(" ", headerPadding), header, strings.Repeat(" ", width-2-headerPadding-len(header)))
	fmt.Printf("╠%s╣\n", headerBorder)
	
	// Print device count
	deviceCount := fmt.Sprintf("Devices Detected: %d", len(devices))
	fmt.Printf("║ %s%s ║\n", deviceCount, strings.Repeat(" ", width-4-len(deviceCount)))
	fmt.Printf("╠%s╣\n", headerBorder)
	
	// Print each device
	for _, device := range devices {
		device.mutex.RLock()
		
		// Skip devices that haven't been seen in the last 5 minutes
		if time.Since(device.LastSeen) > 5*time.Minute {
			device.mutex.RUnlock()
			continue
		}
		
		// Format device info
		deviceInfo := fmt.Sprintf("%s", device.IP)
		
		if device.MAC != "" {
			deviceInfo += fmt.Sprintf(" (%s)", device.MAC)
		}
		
		if device.Vendor != "" {
			deviceInfo += fmt.Sprintf(" - %s", device.Vendor)
		}
		
		if device.Hostname != "" {
			deviceInfo += fmt.Sprintf(" - %s", device.Hostname)
		}
		
		// Add device type and OS info if available from fingerprinting
		deviceTypeInfo := ""
		if device.DeviceType != "" {
			deviceTypeInfo = device.DeviceType
		}
		
		if device.DeviceModel != "" {
			if deviceTypeInfo != "" {
				deviceTypeInfo += " - "
			}
			deviceTypeInfo += device.DeviceModel
		}
		
		if device.OSType != "" {
			if deviceTypeInfo != "" {
				deviceTypeInfo += " ("
				deviceTypeInfo += device.OSType
				deviceTypeInfo += ")"
			} else {
				deviceTypeInfo = device.OSType
			}
		}
		
		if deviceTypeInfo != "" {
			deviceInfo += fmt.Sprintf(" | %s", deviceTypeInfo)
		}
		
		// Add unique ID confidence if available
		if device.UniqueID != "" && device.Confidence > 0 {
			deviceInfo += fmt.Sprintf(" | ID Confidence: %.1f%%", device.Confidence*100)
		}
		
		// Add gateway indicator
		if device.IsGateway {
			deviceInfo += " | GATEWAY"
		}
		
		// Add spoofing status indicators
		if device.IsARPSpoofed {
			deviceInfo += " | 🔄 ARP SPOOFED"
		}
		
		if device.IsDNSSpoofed {
			deviceInfo += " | 🔄 DNS SPOOFED"
		}
		
		// Add bandwidth if available
		if device.BytesReceived > 0 || device.BytesSent > 0 {
			deviceInfo += fmt.Sprintf(" | ↓%s ↑%s", 
				bandwidth.FormatBytesPerSecond(device.RateReceived),
				bandwidth.FormatBytesPerSecond(device.RateSent))
		}
		
		fmt.Printf("   • %s\n", deviceInfo)
		
		// Show open ports if available
		if len(device.OpenPorts) > 0 {
			// Sort ports
			ports := make([]int, len(device.OpenPorts))
			copy(ports, device.OpenPorts)
			sort.Ints(ports)
			
			// Format ports
			portStrings := make([]string, len(ports))
			for i, port := range ports {
				portName := analyzer.GetCommonPortNames()[uint16(port)]
				if portName != "" {
					portStrings[i] = fmt.Sprintf("%d (%s)", port, portName)
				} else {
					portStrings[i] = fmt.Sprintf("%d", port)
				}
			}
			
			// Show ports
			portsStr := strings.Join(portStrings, ", ")
			if len(portsStr) > 60 {
				portsStr = portsStr[:57] + "..."
			}
			fmt.Printf("     ↳ Ports: %s\n", portsStr)
		}
		
		// Show top protocols if available
		if len(device.TopProtocols) > 0 {
			// Convert map to slice of key-value pairs
			type protocolUsage struct {
				protocol string
				bytes    uint64
			}
			protocols := make([]protocolUsage, 0, len(device.TopProtocols))
			for proto, bytes := range device.TopProtocols {
				protocols = append(protocols, protocolUsage{protocol: proto, bytes: bytes})
			}
			
			// Sort by bytes (descending)
			sort.Slice(protocols, func(i, j int) bool {
				return protocols[i].bytes > protocols[j].bytes
			})
			
			// Format protocols
			protocolStrings := make([]string, 0, len(protocols))
			for i, proto := range protocols {
				if i >= 3 { // Show top 3 protocols
					break
				}
				protocolStrings = append(protocolStrings, fmt.Sprintf("%s (%s)", 
					proto.protocol, bandwidth.FormatBytes(proto.bytes)))
			}
			
			// Show protocols
			if len(protocolStrings) > 0 {
				fmt.Printf("     ↳ Protocols: %s\n", strings.Join(protocolStrings, ", "))
			}
		}
		
		// Show geolocation if available
		if device.Country != "" || device.City != "" || device.ISP != "" {
			geoInfo := ""
			if device.Country != "" {
				geoInfo += device.Country
			}
			if device.City != "" {
				if geoInfo != "" {
					geoInfo += ", "
				}
				geoInfo += device.City
			}
			if device.ISP != "" {
				if geoInfo != "" {
					geoInfo += " - "
				}
				geoInfo += device.ISP
			}
			
			if geoInfo != "" {
				fmt.Printf("     ↳ Location: %s\n", geoInfo)
			}
		}
		
		// Get all domains with their protocols
		domainInfo := make(map[string][]string)
		
		// Add DNS domains
		for domain := range device.DNSDomains {
			if _, exists := domainInfo[domain]; !exists {
				domainInfo[domain] = []string{}
			}
			domainInfo[domain] = append(domainInfo[domain], "DNS")
		}
		
		// Add HTTP domains
		for domain := range device.HTTPDomains {
			if _, exists := domainInfo[domain]; !exists {
				domainInfo[domain] = []string{}
			}
			domainInfo[domain] = append(domainInfo[domain], "HTTP")
		}
		
		// Add TLS domains
		for domain := range device.TLSDomains {
			if _, exists := domainInfo[domain]; !exists {
				domainInfo[domain] = []string{}
			}
			domainInfo[domain] = append(domainInfo[domain], "HTTPS")
		}
		
		// Sort domains
		var domains []string
		for domain := range domainInfo {
			domains = append(domains, domain)
		}
		sort.Strings(domains)
		
		// Display domains (limited to 3 per device in summary view)
		if len(domains) > 0 {
			maxDomains := 3 // Show only top 3 domains in summary view
			if len(domains) > maxDomains {
				domains = domains[:maxDomains]
			}
			
			for _, domain := range domains {
				protocols := domainInfo[domain]
				sort.Strings(protocols)
				
				// Format the domain and protocols
				domainDisplay := domain
				if len(domainDisplay) > 40 {
					domainDisplay = domainDisplay[:37] + "..."
				}
				
				protocolsStr := strings.Join(protocols, ", ")
				fmt.Printf("     ↳ %s [%s]\n", domainDisplay, protocolsStr)
			}
			
			if len(domains) < len(domainInfo) {
				fmt.Printf("     ↳ ... and %d more sites\n", len(domainInfo) - len(domains))
			}
		}
		
		device.mutex.RUnlock()
	}
	
	// Print footer
	fmt.Printf("\n╔%s╗\n", headerBorder)
	footer := fmt.Sprintf("Last Updated: %s | Press Ctrl+C to exit", time.Now().Format("2006-01-02 15:04:05"))
	footerPadding := (width - 2 - len(footer)) / 2
	fmt.Printf("║%s%s%s║\n", strings.Repeat(" ", footerPadding), footer, strings.Repeat(" ", width-2-footerPadding-len(footer)))
	fmt.Printf("╚%s╝\n", headerBorder)
}

// isPrivateIP checks if an IP address is in a private range
func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	
	// Check if IPv4
	ipv4 := ip.To4()
	if ipv4 == nil {
		// IPv6 logic would go here
		return false
	}
	
	// Check private IPv4 ranges
	// 10.0.0.0/8
	if ipv4[0] == 10 {
		return true
	}
	// 172.16.0.0/12
	if ipv4[0] == 172 && ipv4[1] >= 16 && ipv4[1] <= 31 {
		return true
	}
	// 192.168.0.0/16
	if ipv4[0] == 192 && ipv4[1] == 168 {
		return true
	}
	// 169.254.0.0/16 (link local)
	if ipv4[0] == 169 && ipv4[1] == 254 {
		return true
	}
	
	return false
}
