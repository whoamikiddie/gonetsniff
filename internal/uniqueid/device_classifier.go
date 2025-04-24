package uniqueid

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/sirupsen/logrus"
	"github.com/whoamikiddie/gonetsniff/internal/interfaces"
)

// DeviceSignature represents a unique device signature
type DeviceSignature struct {
	IP                string
	MAC               string
	TTL               uint8
	WindowSize        uint16
	MSS               uint16
	UserAgents        []string
	OpenPorts         []int
	PacketSizeProfile []int
	TimingProfile     []int64 // in nanoseconds
	Protocols         map[string]int
	DomainProfile     map[string]int
	LastSeen          time.Time
	Confidence        float64
	DeviceType        string
	DeviceModel       string
	OperatingSystem   string
	UniqueID          string
	FirstSeen         time.Time
	PacketCount       int
	BytesTransferred  uint64
}

// DeviceClassifier identifies and classifies unique devices
type DeviceClassifier struct {
	interfaces      []interfaces.NetworkInterface
	devices         map[string]*DeviceSignature // IP -> Signature
	devicesByMAC    map[string]*DeviceSignature // MAC -> Signature
	mutex           sync.RWMutex
	stopChan        chan struct{}
	wg              sync.WaitGroup
	signatureDB     map[string]map[string]float64 // Signature database
	confidenceThreshold float64
	minPacketsForID int
}

// NewDeviceClassifier creates a new device classifier
func NewDeviceClassifier(ifaces []interfaces.NetworkInterface) *DeviceClassifier {
	return &DeviceClassifier{
		interfaces:         ifaces,
		devices:            make(map[string]*DeviceSignature),
		devicesByMAC:       make(map[string]*DeviceSignature),
		stopChan:           make(chan struct{}),
		signatureDB:        loadSignatureDatabase(),
		confidenceThreshold: 0.75,
		minPacketsForID:    50,
	}
}

// Start begins device classification
func (c *DeviceClassifier) Start() {
	logrus.Info("Starting unique device classifier")

	// Start classification on each interface
	for _, iface := range c.interfaces {
		c.wg.Add(1)
		go func(iface interfaces.NetworkInterface) {
			defer c.wg.Done()
			if err := c.classifyOnInterface(iface); err != nil {
				logrus.Errorf("Error classifying on interface %s: %v", iface.Name, err)
			}
		}(iface)
	}

	// Start periodic analysis in a separate goroutine
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-c.stopChan:
				return
			case <-ticker.C:
				c.analyzeDevices()
			}
		}
	}()
}

// Stop stops the device classifier
func (c *DeviceClassifier) Stop() {
	logrus.Info("Stopping unique device classifier")
	close(c.stopChan)
	c.wg.Wait()
}

// GetDevices returns a copy of the current device signatures
func (c *DeviceClassifier) GetDevices() map[string]DeviceSignature {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	devices := make(map[string]DeviceSignature)
	for ip, device := range c.devices {
		devices[ip] = *device
	}
	return devices
}

// GetUniqueDevices returns only devices with a high confidence unique identification
func (c *DeviceClassifier) GetUniqueDevices() map[string]DeviceSignature {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	devices := make(map[string]DeviceSignature)
	for ip, device := range c.devices {
		if device.Confidence >= c.confidenceThreshold && device.UniqueID != "" {
			devices[ip] = *device
		}
	}
	return devices
}

// GetDeviceByIP returns a specific device signature
func (c *DeviceClassifier) GetDeviceByIP(ip string) (DeviceSignature, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	device, exists := c.devices[ip]
	if !exists {
		return DeviceSignature{}, false
	}
	return *device, true
}

// GetDeviceByMAC returns a specific device signature by MAC address
func (c *DeviceClassifier) GetDeviceByMAC(mac string) (DeviceSignature, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	device, exists := c.devicesByMAC[mac]
	if !exists {
		return DeviceSignature{}, false
	}
	return *device, true
}

// classifyOnInterface performs device classification on an interface
func (c *DeviceClassifier) classifyOnInterface(iface interfaces.NetworkInterface) error {
	// Open device for capturing
	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("failed to open interface %s: %v", iface.Name, err)
	}
	defer handle.Close()

	// No filter - we want to analyze all traffic
	logrus.Infof("Device classification started on interface %s", iface.Name)

	// Start packet processing
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetChan := packetSource.Packets()

	var lastPacketTime time.Time
	packetTimes := make(map[string]time.Time)

	for {
		select {
		case <-c.stopChan:
			return nil
		case packet, ok := <-packetChan:
			if !ok {
				return nil
			}

			// Process packet timing
			now := time.Now()
			if !lastPacketTime.IsZero() {
				// Calculate global inter-packet time
				timeDiff := now.Sub(lastPacketTime).Nanoseconds()
				if timeDiff > 0 && timeDiff < 1000000000 { // Only consider reasonable times (< 1s)
					// We could use this for global traffic analysis
				}
			}
			lastPacketTime = now

			// Process the packet for classification
			c.processPacket(packet, packetTimes)
		}
	}
}

// processPacket analyzes a packet for device classification
func (c *DeviceClassifier) processPacket(packet gopacket.Packet, packetTimes map[string]time.Time) {
	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		return
	}

	// Get Ethernet layer
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer == nil {
		return
	}
	ethernet := ethernetLayer.(*layers.Ethernet)
	srcMAC := ethernet.SrcMAC.String()

	// Get IP layer
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}
	ip := ipLayer.(*layers.IPv4)
	srcIP := ip.SrcIP.String()
	ttl := ip.TTL

	// Get packet size
	packetSize := len(packet.Data())

	// Process packet timing for this source
	now := time.Now()
	if lastTime, exists := packetTimes[srcIP]; exists {
		timeDiff := now.Sub(lastTime).Nanoseconds()
		if timeDiff > 0 && timeDiff < 1000000000 { // Only consider reasonable times (< 1s)
			c.updateTimingProfile(srcIP, timeDiff)
		}
	}
	packetTimes[srcIP] = now

	// Update packet size profile
	c.updatePacketSizeProfile(srcIP, packetSize)

	// Update protocol profile
	c.updateProtocolProfile(srcIP, packet)

	// Get TCP layer if present
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		c.processTCPPacket(srcIP, srcMAC, ttl, tcp, packet)
	}

	// Get UDP layer if present
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		c.processUDPPacket(srcIP, srcMAC, ttl, udp, packet)
	}

	// Update basic device info
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Get or create device signature
	device, exists := c.devices[srcIP]
	if !exists {
		device = &DeviceSignature{
			IP:                srcIP,
			MAC:               srcMAC,
			TTL:               ttl,
			PacketSizeProfile: []int{},
			TimingProfile:     []int64{},
			Protocols:         make(map[string]int),
			DomainProfile:     make(map[string]int),
			UserAgents:        []string{},
			OpenPorts:         []int{},
			FirstSeen:         time.Now(),
			LastSeen:          time.Now(),
		}
		c.devices[srcIP] = device
		c.devicesByMAC[srcMAC] = device
	} else {
		device.LastSeen = time.Now()
		device.TTL = ttl // Update TTL
		device.PacketCount++
		device.BytesTransferred += uint64(packetSize)
	}
}

// processTCPPacket analyzes a TCP packet for device classification
func (c *DeviceClassifier) processTCPPacket(srcIP, srcMAC string, ttl uint8, tcp *layers.TCP, packet gopacket.Packet) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Get or create device signature
	device, exists := c.devices[srcIP]
	if !exists {
		device = &DeviceSignature{
			IP:                srcIP,
			MAC:               srcMAC,
			TTL:               ttl,
			PacketSizeProfile: []int{},
			TimingProfile:     []int64{},
			Protocols:         make(map[string]int),
			DomainProfile:     make(map[string]int),
			UserAgents:        []string{},
			OpenPorts:         []int{},
			FirstSeen:         time.Now(),
			LastSeen:          time.Now(),
		}
		c.devices[srcIP] = device
		c.devicesByMAC[srcMAC] = device
	}

	// Update window size
	device.WindowSize = tcp.Window

	// Check for MSS option
	for _, option := range tcp.Options {
		if option.OptionType == layers.TCPOptionKindMSS {
			if len(option.OptionData) >= 2 {
				mss := uint16(option.OptionData[0])<<8 | uint16(option.OptionData[1])
				device.MSS = mss
			}
		}
	}

	// Check for HTTP User-Agent
	if applicationLayer := packet.ApplicationLayer(); applicationLayer != nil {
		payload := string(applicationLayer.Payload())
		if strings.Contains(payload, "User-Agent:") {
			uaStart := strings.Index(payload, "User-Agent:")
			if uaStart != -1 {
				uaStart += 11 // Length of "User-Agent:"
				uaEnd := strings.Index(payload[uaStart:], "\r\n")
				if uaEnd != -1 {
					userAgent := strings.TrimSpace(payload[uaStart : uaStart+uaEnd])
					// Check if we already have this User-Agent
					found := false
					for _, ua := range device.UserAgents {
						if ua == userAgent {
							found = true
							break
						}
					}
					if !found {
						device.UserAgents = append(device.UserAgents, userAgent)
					}
				}
			}
		}

		// Check for HTTP Host header to build domain profile
		if strings.Contains(payload, "Host:") {
			hostStart := strings.Index(payload, "Host:")
			if hostStart != -1 {
				hostStart += 5 // Length of "Host:"
				hostEnd := strings.Index(payload[hostStart:], "\r\n")
				if hostEnd != -1 {
					host := strings.TrimSpace(payload[hostStart : hostStart+hostEnd])
					device.DomainProfile[host]++
				}
			}
		}
	}
}

// processUDPPacket analyzes a UDP packet for device classification
func (c *DeviceClassifier) processUDPPacket(srcIP, srcMAC string, ttl uint8, udp *layers.UDP, packet gopacket.Packet) {
	// Check for DNS queries to build domain profile
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer != nil {
		dns := dnsLayer.(*layers.DNS)
		for _, question := range dns.Questions {
			domain := string(question.Name)
			
			c.mutex.Lock()
			// Get or create device signature
			device, exists := c.devices[srcIP]
			if !exists {
				device = &DeviceSignature{
					IP:                srcIP,
					MAC:               srcMAC,
					TTL:               ttl,
					PacketSizeProfile: []int{},
					TimingProfile:     []int64{},
					Protocols:         make(map[string]int),
					DomainProfile:     make(map[string]int),
					UserAgents:        []string{},
					OpenPorts:         []int{},
					FirstSeen:         time.Now(),
					LastSeen:          time.Now(),
				}
				c.devices[srcIP] = device
				c.devicesByMAC[srcMAC] = device
			}
			
			// Update domain profile
			device.DomainProfile[domain]++
			c.mutex.Unlock()
		}
	}

	// Check for DHCP packets for device identification
	dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4)
	if dhcpLayer != nil {
		dhcp := dhcpLayer.(*layers.DHCPv4)
		// Extract hostname option
		for _, option := range dhcp.Options {
			if option.Type == layers.DHCPOptHostname {
				hostname := string(option.Data)
				
				c.mutex.Lock()
				// Get or create device signature
				device, exists := c.devices[srcIP]
				if !exists {
					device = &DeviceSignature{
						IP:                srcIP,
						MAC:               srcMAC,
						TTL:               ttl,
						PacketSizeProfile: []int{},
						TimingProfile:     []int64{},
						Protocols:         make(map[string]int),
						DomainProfile:     make(map[string]int),
						UserAgents:        []string{},
						OpenPorts:         []int{},
						FirstSeen:         time.Now(),
						LastSeen:          time.Now(),
					}
					c.devices[srcIP] = device
					c.devicesByMAC[srcMAC] = device
				}
				
				// Use hostname to help identify device
				if device.DeviceModel == "" {
					device.DeviceModel = hostname
				}
				c.mutex.Unlock()
				
				break
			}
		}
	}
}

// updatePacketSizeProfile updates the packet size profile for a device
func (c *DeviceClassifier) updatePacketSizeProfile(ip string, size int) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	device, exists := c.devices[ip]
	if !exists {
		return
	}

	// Add to profile, keeping only the last 100 sizes
	device.PacketSizeProfile = append(device.PacketSizeProfile, size)
	if len(device.PacketSizeProfile) > 100 {
		device.PacketSizeProfile = device.PacketSizeProfile[len(device.PacketSizeProfile)-100:]
	}
}

// updateTimingProfile updates the timing profile for a device
func (c *DeviceClassifier) updateTimingProfile(ip string, timeDiff int64) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	device, exists := c.devices[ip]
	if !exists {
		return
	}

	// Add to profile, keeping only the last 100 timings
	device.TimingProfile = append(device.TimingProfile, timeDiff)
	if len(device.TimingProfile) > 100 {
		device.TimingProfile = device.TimingProfile[len(device.TimingProfile)-100:]
	}
}

// updateProtocolProfile updates the protocol profile for a device
func (c *DeviceClassifier) updateProtocolProfile(ip string, packet gopacket.Packet) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	device, exists := c.devices[ip]
	if !exists {
		return
	}

	// Check for various protocol layers
	if packet.Layer(layers.LayerTypeTCP) != nil {
		device.Protocols["TCP"]++
	}
	if packet.Layer(layers.LayerTypeUDP) != nil {
		device.Protocols["UDP"]++
	}
	if packet.Layer(layers.LayerTypeICMPv4) != nil {
		device.Protocols["ICMP"]++
	}
	if packet.Layer(layers.LayerTypeDNS) != nil {
		device.Protocols["DNS"]++
	}
	if packet.Layer(layers.LayerTypeDHCPv4) != nil {
		device.Protocols["DHCP"]++
	}
	if packet.Layer(layers.LayerTypeARP) != nil {
		device.Protocols["ARP"]++
	}

	// Check for HTTP/HTTPS
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		if tcp.SrcPort == 80 || tcp.DstPort == 80 {
			device.Protocols["HTTP"]++
		}
		if tcp.SrcPort == 443 || tcp.DstPort == 443 {
			device.Protocols["HTTPS"]++
		}
	}
}

// analyzeDevices periodically analyzes device signatures to identify unique devices
func (c *DeviceClassifier) analyzeDevices() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	logrus.Info("Analyzing device signatures")

	for ip, device := range c.devices {
		// Skip devices with too few packets
		if device.PacketCount < c.minPacketsForID {
			continue
		}

		// Calculate fingerprint
		fingerprint := c.calculateFingerprint(device)
		
		// Match against signature database
		bestMatch, confidence := c.matchSignature(fingerprint)
		
		// Update device information
		device.Confidence = confidence
		if confidence >= c.confidenceThreshold {
			// High confidence match
			parts := strings.Split(bestMatch, ":")
			if len(parts) >= 3 {
				device.DeviceType = parts[0]
				device.DeviceModel = parts[1]
				device.OperatingSystem = parts[2]
				device.UniqueID = bestMatch
			}
		}
		
		logrus.Infof("Device %s (%s) identified as %s (confidence: %.2f%%)", 
			ip, device.MAC, bestMatch, confidence*100)
	}
}

// calculateFingerprint generates a fingerprint for a device
func (c *DeviceClassifier) calculateFingerprint(device *DeviceSignature) map[string]float64 {
	fingerprint := make(map[string]float64)
	
	// TTL
	fingerprint["ttl"] = float64(device.TTL)
	
	// Window size
	fingerprint["window_size"] = float64(device.WindowSize)
	
	// MSS
	fingerprint["mss"] = float64(device.MSS)
	
	// Packet size statistics
	if len(device.PacketSizeProfile) > 0 {
		var sum, sumSquares float64
		for _, size := range device.PacketSizeProfile {
			sum += float64(size)
			sumSquares += float64(size) * float64(size)
		}
		mean := sum / float64(len(device.PacketSizeProfile))
		variance := (sumSquares / float64(len(device.PacketSizeProfile))) - (mean * mean)
		stdDev := math.Sqrt(variance)
		
		fingerprint["packet_size_mean"] = mean
		fingerprint["packet_size_stddev"] = stdDev
	}
	
	// Timing statistics
	if len(device.TimingProfile) > 0 {
		var sum, sumSquares float64
		for _, timing := range device.TimingProfile {
			sum += float64(timing)
			sumSquares += float64(timing) * float64(timing)
		}
		mean := sum / float64(len(device.TimingProfile))
		variance := (sumSquares / float64(len(device.TimingProfile))) - (mean * mean)
		stdDev := math.Sqrt(variance)
		
		fingerprint["timing_mean"] = mean
		fingerprint["timing_stddev"] = stdDev
	}
	
	// Protocol distribution
	totalProtocols := 0
	for _, count := range device.Protocols {
		totalProtocols += count
	}
	if totalProtocols > 0 {
		for protocol, count := range device.Protocols {
			fingerprint["protocol_"+protocol] = float64(count) / float64(totalProtocols)
		}
	}
	
	// User-Agent signature
	if len(device.UserAgents) > 0 {
		// Use the most common User-Agent
		fingerprint["user_agent"] = float64(hashString(device.UserAgents[0]))
	}
	
	// Domain profile
	if len(device.DomainProfile) > 0 {
		// Get top domains
		domains := make([]string, 0, len(device.DomainProfile))
		for domain := range device.DomainProfile {
			domains = append(domains, domain)
		}
		sort.Slice(domains, func(i, j int) bool {
			return device.DomainProfile[domains[i]] > device.DomainProfile[domains[j]]
		})
		
		// Use top 5 domains
		for i := 0; i < 5 && i < len(domains); i++ {
			fingerprint["domain_"+strconv.Itoa(i)] = float64(hashString(domains[i]))
		}
	}
	
	return fingerprint
}

// matchSignature matches a fingerprint against the signature database
func (c *DeviceClassifier) matchSignature(fingerprint map[string]float64) (string, float64) {
	bestMatch := ""
	bestScore := 0.0
	
	for signature, features := range c.signatureDB {
		score := c.calculateSimilarity(fingerprint, features)
		if score > bestScore {
			bestScore = score
			bestMatch = signature
		}
	}
	
	return bestMatch, bestScore
}

// calculateSimilarity calculates the similarity between two fingerprints
func (c *DeviceClassifier) calculateSimilarity(fp1, fp2 map[string]float64) float64 {
	// Use a weighted Euclidean distance
	totalWeight := 0.0
	weightedDistance := 0.0
	
	// Weights for different features
	weights := map[string]float64{
		"ttl":              5.0,
		"window_size":      3.0,
		"mss":              3.0,
		"packet_size_mean": 2.0,
		"timing_mean":      1.0,
		"user_agent":       4.0,
	}
	
	// Calculate weighted distance
	for feature, value1 := range fp1 {
		if value2, exists := fp2[feature]; exists {
			weight := 1.0
			if w, exists := weights[feature]; exists {
				weight = w
			}
			
			// For protocol features, use a different distance metric
			if strings.HasPrefix(feature, "protocol_") {
				weightedDistance += weight * math.Abs(value1-value2)
			} else {
				// Normalize the values based on expected ranges
				normalizedValue1 := normalizeFeature(feature, value1)
				normalizedValue2 := normalizeFeature(feature, value2)
				weightedDistance += weight * math.Pow(normalizedValue1-normalizedValue2, 2)
			}
			
			totalWeight += weight
		}
	}
	
	if totalWeight == 0 {
		return 0
	}
	
	// Convert distance to similarity score (0-1)
	distance := math.Sqrt(weightedDistance / totalWeight)
	similarity := 1.0 / (1.0 + distance)
	
	return similarity
}

// normalizeFeature normalizes a feature value to a 0-1 range
func normalizeFeature(feature string, value float64) float64 {
	switch feature {
	case "ttl":
		return value / 255.0
	case "window_size":
		return value / 65535.0
	case "mss":
		return value / 1500.0
	case "packet_size_mean":
		return value / 1500.0
	case "timing_mean":
		return value / 1000000000.0 // 1 second in ns
	default:
		return value
	}
}

// hashString creates a simple hash of a string
func hashString(s string) int {
	h := 0
	for i := 0; i < len(s); i++ {
		h = 31*h + int(s[i])
	}
	return h
}

// loadSignatureDatabase loads the device signature database
func loadSignatureDatabase() map[string]map[string]float64 {
	// In a real implementation, this would load from a file or database
	// For now, we'll return a small sample database
	return map[string]map[string]float64{
		"Smartphone:iPhone:iOS": {
			"ttl":              64,
			"window_size":      65535,
			"mss":              1460,
			"packet_size_mean": 512,
			"timing_mean":      100000000, // 100ms
			"protocol_TCP":     0.7,
			"protocol_UDP":     0.2,
			"protocol_DNS":     0.1,
		},
		"Smartphone:Android:Android": {
			"ttl":              64,
			"window_size":      60000,
			"mss":              1430,
			"packet_size_mean": 480,
			"timing_mean":      120000000, // 120ms
			"protocol_TCP":     0.65,
			"protocol_UDP":     0.25,
			"protocol_DNS":     0.1,
		},
		"Computer:MacBook:macOS": {
			"ttl":              64,
			"window_size":      65535,
			"mss":              1460,
			"packet_size_mean": 800,
			"timing_mean":      50000000, // 50ms
			"protocol_TCP":     0.8,
			"protocol_UDP":     0.1,
			"protocol_DNS":     0.1,
		},
		"Computer:PC:Windows": {
			"ttl":              128,
			"window_size":      8192,
			"mss":              1460,
			"packet_size_mean": 750,
			"timing_mean":      60000000, // 60ms
			"protocol_TCP":     0.75,
			"protocol_UDP":     0.15,
			"protocol_DNS":     0.1,
		},
		"IoT:SmartTV:Android": {
			"ttl":              64,
			"window_size":      14600,
			"mss":              1460,
			"packet_size_mean": 900,
			"timing_mean":      200000000, // 200ms
			"protocol_TCP":     0.9,
			"protocol_UDP":     0.05,
			"protocol_DNS":     0.05,
		},
		"IoT:SmartSpeaker:Linux": {
			"ttl":              64,
			"window_size":      5840,
			"mss":              1460,
			"packet_size_mean": 300,
			"timing_mean":      300000000, // 300ms
			"protocol_TCP":     0.6,
			"protocol_UDP":     0.3,
			"protocol_DNS":     0.1,
		},
		"Network:Router:RouterOS": {
			"ttl":              64,
			"window_size":      4096,
			"mss":              1460,
			"packet_size_mean": 200,
			"timing_mean":      10000000, // 10ms
			"protocol_TCP":     0.4,
			"protocol_UDP":     0.3,
			"protocol_ICMP":    0.3,
		},
	}
}
