package analyzer

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/sirupsen/logrus"
	"github.com/whoamikiddie/gonetsniff/internal/interfaces"
)

// ProtocolStats tracks statistics for a specific protocol
type ProtocolStats struct {
	PacketCount uint64
	ByteCount   uint64
	LastSeen    time.Time
}

// ConnectionKey uniquely identifies a network connection
type ConnectionKey struct {
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
	Proto   string
}

// ConnectionStats tracks statistics for a specific connection
type ConnectionStats struct {
	Key         ConnectionKey
	PacketCount uint64
	ByteCount   uint64
	FirstSeen   time.Time
	LastSeen    time.Time
	State       string // For TCP: SYN, ESTABLISHED, FIN, etc.
}

// ProtocolAnalyzer analyzes network protocols and connections
type ProtocolAnalyzer struct {
	interfaces       []interfaces.NetworkInterface
	protocolStats    map[string]*ProtocolStats // Protocol -> Stats
	connectionStats  map[ConnectionKey]*ConnectionStats
	topPorts         map[uint16]uint64 // Port -> Count
	mutex            sync.RWMutex
	stopChan         chan struct{}
	wg               sync.WaitGroup
	maxConnections   int
	cleanupInterval  time.Duration
	connectionExpiry time.Duration
}

// NewProtocolAnalyzer creates a new protocol analyzer
func NewProtocolAnalyzer(ifaces []interfaces.NetworkInterface) *ProtocolAnalyzer {
	return &ProtocolAnalyzer{
		interfaces:       ifaces,
		protocolStats:    make(map[string]*ProtocolStats),
		connectionStats:  make(map[ConnectionKey]*ConnectionStats),
		topPorts:         make(map[uint16]uint64),
		stopChan:         make(chan struct{}),
		maxConnections:   10000,
		cleanupInterval:  5 * time.Minute,
		connectionExpiry: 30 * time.Minute,
	}
}

// Start begins protocol analysis
func (p *ProtocolAnalyzer) Start() {
	logrus.Info("Starting protocol analyzer")

	// Start analysis on each interface
	for _, iface := range p.interfaces {
		p.wg.Add(1)
		go func(iface interfaces.NetworkInterface) {
			defer p.wg.Done()
			if err := p.analyzeInterface(iface); err != nil {
				logrus.Errorf("Error analyzing interface %s: %v", iface.Name, err)
			}
		}(iface)
	}

	// Start connection cleanup in a separate goroutine
	go p.cleanupOldConnections()
}

// Stop stops protocol analysis
func (p *ProtocolAnalyzer) Stop() {
	close(p.stopChan)
	p.wg.Wait()
}

// GetProtocolStats returns statistics for all protocols
func (p *ProtocolAnalyzer) GetProtocolStats() map[string]ProtocolStats {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	stats := make(map[string]ProtocolStats)
	for proto, stat := range p.protocolStats {
		stats[proto] = ProtocolStats{
			PacketCount: stat.PacketCount,
			ByteCount:   stat.ByteCount,
			LastSeen:    stat.LastSeen,
		}
	}

	return stats
}

// GetTopConnections returns the top N connections by byte count
func (p *ProtocolAnalyzer) GetTopConnections(n int) []ConnectionStats {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	// Convert map to slice
	connections := make([]ConnectionStats, 0, len(p.connectionStats))
	for _, conn := range p.connectionStats {
		connections = append(connections, *conn)
	}

	// Sort by byte count (descending)
	for i := 0; i < len(connections); i++ {
		for j := i + 1; j < len(connections); j++ {
			if connections[i].ByteCount < connections[j].ByteCount {
				connections[i], connections[j] = connections[j], connections[i]
			}
		}
	}

	// Limit to n connections
	if len(connections) > n {
		connections = connections[:n]
	}

	return connections
}

// GetTopPorts returns the top N ports by packet count
func (p *ProtocolAnalyzer) GetTopPorts(n int) map[uint16]uint64 {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	// Convert map to slice of key-value pairs
	type portCount struct {
		port  uint16
		count uint64
	}
	ports := make([]portCount, 0, len(p.topPorts))
	for port, count := range p.topPorts {
		ports = append(ports, portCount{port: port, count: count})
	}

	// Sort by count (descending)
	for i := 0; i < len(ports); i++ {
		for j := i + 1; j < len(ports); j++ {
			if ports[i].count < ports[j].count {
				ports[i], ports[j] = ports[j], ports[i]
			}
		}
	}

	// Limit to n ports and convert back to map
	result := make(map[uint16]uint64)
	limit := n
	if len(ports) < limit {
		limit = len(ports)
	}
	for i := 0; i < limit; i++ {
		result[ports[i].port] = ports[i].count
	}

	return result
}

// GetConnectionsForIP returns all connections for a specific IP
func (p *ProtocolAnalyzer) GetConnectionsForIP(ip string) []ConnectionStats {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	connections := make([]ConnectionStats, 0)
	for _, conn := range p.connectionStats {
		if conn.Key.SrcIP == ip || conn.Key.DstIP == ip {
			connections = append(connections, *conn)
		}
	}

	return connections
}

// analyzeInterface captures and analyzes packets on a specific interface
func (p *ProtocolAnalyzer) analyzeInterface(iface interfaces.NetworkInterface) error {
	// Open the device for capturing
	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("failed to open interface %s: %v", iface.Name, err)
	}
	defer handle.Close()

	// Start packet processing
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetChan := packetSource.Packets()

	for {
		select {
		case <-p.stopChan:
			return nil
		case packet, ok := <-packetChan:
			if !ok {
				return nil
			}
			p.analyzePacket(packet)
		}
	}
}

// analyzePacket processes a packet for protocol analysis
func (p *ProtocolAnalyzer) analyzePacket(packet gopacket.Packet) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	// Get packet size
	packetSize := uint64(len(packet.Data()))

	// Analyze Ethernet layer
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		p.updateProtocolStats("Ethernet", packetSize)
	}

	// Analyze IP layer
	var srcIP, dstIP string
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		p.updateProtocolStats("IPv4", packetSize)
		ip := ipLayer.(*layers.IPv4)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
	} else {
		ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
		if ipv6Layer != nil {
			p.updateProtocolStats("IPv6", packetSize)
			ipv6 := ipv6Layer.(*layers.IPv6)
			srcIP = ipv6.SrcIP.String()
			dstIP = ipv6.DstIP.String()
		}
	}

	// Analyze TCP layer
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		p.updateProtocolStats("TCP", packetSize)
		tcp := tcpLayer.(*layers.TCP)
		
		// Update top ports
		p.topPorts[uint16(tcp.SrcPort)]++
		p.topPorts[uint16(tcp.DstPort)]++
		
		// Create connection key
		key := ConnectionKey{
			SrcIP:   srcIP,
			DstIP:   dstIP,
			SrcPort: uint16(tcp.SrcPort),
			DstPort: uint16(tcp.DstPort),
			Proto:   "TCP",
		}
		
		// Determine TCP state
		state := "UNKNOWN"
		if tcp.SYN && !tcp.ACK {
			state = "SYN"
		} else if tcp.SYN && tcp.ACK {
			state = "SYN-ACK"
		} else if tcp.FIN {
			state = "FIN"
		} else if tcp.RST {
			state = "RST"
		} else if tcp.ACK {
			state = "ESTABLISHED"
		}
		
		// Update connection stats
		p.updateConnectionStats(key, packetSize, state)
		
		// Check for HTTP
		if tcp.SrcPort == 80 || tcp.DstPort == 80 {
			p.updateProtocolStats("HTTP", packetSize)
		}
		
		// Check for HTTPS
		if tcp.SrcPort == 443 || tcp.DstPort == 443 {
			p.updateProtocolStats("HTTPS", packetSize)
		}
	}

	// Analyze UDP layer
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		p.updateProtocolStats("UDP", packetSize)
		udp := udpLayer.(*layers.UDP)
		
		// Update top ports
		p.topPorts[uint16(udp.SrcPort)]++
		p.topPorts[uint16(udp.DstPort)]++
		
		// Create connection key
		key := ConnectionKey{
			SrcIP:   srcIP,
			DstIP:   dstIP,
			SrcPort: uint16(udp.SrcPort),
			DstPort: uint16(udp.DstPort),
			Proto:   "UDP",
		}
		
		// Update connection stats
		p.updateConnectionStats(key, packetSize, "")
		
		// Check for DNS
		if udp.SrcPort == 53 || udp.DstPort == 53 {
			p.updateProtocolStats("DNS", packetSize)
		}
	}

	// Analyze ICMP layer
	icmpLayer := packet.Layer(layers.LayerTypeICMPv4)
	if icmpLayer != nil {
		p.updateProtocolStats("ICMP", packetSize)
	}

	// Analyze ARP layer
	arpLayer := packet.Layer(layers.LayerTypeARP)
	if arpLayer != nil {
		p.updateProtocolStats("ARP", packetSize)
	}

	// Analyze application layer protocols
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		// Check for common application protocols based on payload
		payload := applicationLayer.Payload()
		
		// Simple protocol detection based on payload signatures
		if len(payload) > 4 {
			// HTTP detection
			if string(payload[:4]) == "HTTP" || 
			   string(payload[:3]) == "GET" || 
			   string(payload[:4]) == "POST" || 
			   string(payload[:4]) == "HEAD" {
				p.updateProtocolStats("HTTP", packetSize)
			}
			
			// DNS detection (simplified)
			if len(payload) > 12 && (payload[2] & 0x80) == 0 {
				p.updateProtocolStats("DNS", packetSize)
			}
		}
	}
}

// updateProtocolStats updates statistics for a protocol
func (p *ProtocolAnalyzer) updateProtocolStats(protocol string, bytes uint64) {
	stats, exists := p.protocolStats[protocol]
	if !exists {
		stats = &ProtocolStats{}
		p.protocolStats[protocol] = stats
	}
	
	stats.PacketCount++
	stats.ByteCount += bytes
	stats.LastSeen = time.Now()
}

// updateConnectionStats updates statistics for a connection
func (p *ProtocolAnalyzer) updateConnectionStats(key ConnectionKey, bytes uint64, state string) {
	// Check if we need to clean up connections to stay under limit
	if len(p.connectionStats) >= p.maxConnections {
		p.cleanupOldestConnection()
	}
	
	conn, exists := p.connectionStats[key]
	if !exists {
		conn = &ConnectionStats{
			Key:       key,
			FirstSeen: time.Now(),
		}
		p.connectionStats[key] = conn
	}
	
	conn.PacketCount++
	conn.ByteCount += bytes
	conn.LastSeen = time.Now()
	
	// Only update state if provided and not empty
	if state != "" {
		conn.State = state
	}
}

// cleanupOldestConnection removes the oldest connection
func (p *ProtocolAnalyzer) cleanupOldestConnection() {
	var oldestKey ConnectionKey
	var oldestTime time.Time
	
	// Find the oldest connection
	first := true
	for key, conn := range p.connectionStats {
		if first || conn.LastSeen.Before(oldestTime) {
			oldestKey = key
			oldestTime = conn.LastSeen
			first = false
		}
	}
	
	// Remove the oldest connection
	if !first {
		delete(p.connectionStats, oldestKey)
	}
}

// cleanupOldConnections periodically removes expired connections
func (p *ProtocolAnalyzer) cleanupOldConnections() {
	ticker := time.NewTicker(p.cleanupInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-p.stopChan:
			return
		case <-ticker.C:
			p.mutex.Lock()
			
			expireTime := time.Now().Add(-p.connectionExpiry)
			for key, conn := range p.connectionStats {
				if conn.LastSeen.Before(expireTime) {
					delete(p.connectionStats, key)
				}
			}
			
			p.mutex.Unlock()
		}
	}
}

// GetCommonPortNames returns names for common port numbers
func GetCommonPortNames() map[uint16]string {
	return map[uint16]string{
		20:    "FTP Data",
		21:    "FTP Control",
		22:    "SSH",
		23:    "Telnet",
		25:    "SMTP",
		53:    "DNS",
		67:    "DHCP Server",
		68:    "DHCP Client",
		69:    "TFTP",
		80:    "HTTP",
		110:   "POP3",
		123:   "NTP",
		143:   "IMAP",
		161:   "SNMP",
		443:   "HTTPS",
		445:   "SMB",
		465:   "SMTPS",
		514:   "Syslog",
		587:   "SMTP Submission",
		993:   "IMAPS",
		995:   "POP3S",
		1080:  "SOCKS Proxy",
		1194:  "OpenVPN",
		1433:  "MS SQL",
		1723:  "PPTP",
		3306:  "MySQL",
		3389:  "RDP",
		5060:  "SIP",
		5222:  "XMPP",
		5432:  "PostgreSQL",
		5900:  "VNC",
		6379:  "Redis",
		8080:  "HTTP Alternate",
		8443:  "HTTPS Alternate",
		9000:  "Jenkins",
		9090:  "Prometheus",
		9200:  "Elasticsearch",
		27017: "MongoDB",
	}
}
