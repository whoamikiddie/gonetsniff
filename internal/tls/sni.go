package tls

import (
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/sirupsen/logrus"
	"github.com/whoamikiddie/gonetsniff/internal/interfaces"
)

// TLSConnection represents a captured TLS connection with SNI information
type TLSConnection struct {
	Timestamp time.Time
	SourceIP  string
	SourceMAC string
	DestIP    string
	DestPort  uint16
	SNI       string // Server Name Indication
}

// Sniffer handles TLS packet capture and SNI extraction
type Sniffer struct {
	interfaces    []interfaces.NetworkInterface
	connections   []TLSConnection
	mutex         sync.RWMutex
	stopChan      chan struct{}
	maxConnections int
}

// NewSniffer creates a new TLS sniffer
func NewSniffer(ifaces []interfaces.NetworkInterface) *Sniffer {
	return &Sniffer{
		interfaces:     ifaces,
		connections:    make([]TLSConnection, 0, 1000),
		stopChan:       make(chan struct{}),
		maxConnections: 1000, // Keep last 1000 connections
	}
}

// Start begins TLS sniffing on all interfaces
func (s *Sniffer) Start() {
	logrus.Info("Starting TLS SNI sniffer")

	for _, iface := range s.interfaces {
		go s.sniffInterface(iface)
	}
}

// Stop stops the TLS sniffer
func (s *Sniffer) Stop() {
	close(s.stopChan)
}

// GetConnections returns a copy of the current TLS connections
func (s *Sniffer) GetConnections() []TLSConnection {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	connections := make([]TLSConnection, len(s.connections))
	copy(connections, s.connections)
	return connections
}

// GetSummary returns a summary of the TLS connections
func (s *Sniffer) GetSummary() map[string]map[string]int {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// Map of source IP -> SNI -> count
	summary := make(map[string]map[string]int)
	
	for _, conn := range s.connections {
		if conn.SNI == "" {
			continue
		}
		
		if _, exists := summary[conn.SourceIP]; !exists {
			summary[conn.SourceIP] = make(map[string]int)
		}
		summary[conn.SourceIP][conn.SNI]++
	}
	
	return summary
}

// sniffInterface captures TLS packets on a specific interface
func (s *Sniffer) sniffInterface(iface interfaces.NetworkInterface) {
	// Open device
	handle, err := pcap.OpenLive(iface.Name, 1600, true, pcap.BlockForever)
	if err != nil {
		logrus.Errorf("Failed to open interface %s for TLS sniffing: %v", iface.Name, err)
		return
	}
	defer handle.Close()

	// Set filter for TLS traffic (port 443)
	if err := handle.SetBPFFilter("tcp and port 443"); err != nil {
		logrus.Errorf("Failed to set BPF filter on interface %s: %v", iface.Name, err)
		return
	}

	logrus.Infof("TLS SNI sniffer started on interface %s", iface.Name)

	// Use the gopacket library to decode packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		select {
		case <-s.stopChan:
			return
		case packet := <-packetSource.Packets():
			s.processPacket(packet)
		}
	}
}

// processPacket analyzes a packet for TLS Client Hello and SNI information
func (s *Sniffer) processPacket(packet gopacket.Packet) {
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

	// Get IP layer
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}
	ip := ipLayer.(*layers.IPv4)

	// Get TCP layer
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}
	tcp := tcpLayer.(*layers.TCP)

	// Check if this is a TCP packet with payload
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer == nil {
		return
	}

	payload := applicationLayer.Payload()
	if len(payload) < 43 { // Too small to be a TLS Client Hello
		return
	}

	// Check if this is a TLS Client Hello packet
	if payload[0] != 0x16 { // Handshake record type
		return
	}

	// Check TLS version (1.0, 1.1, 1.2, or 1.3)
	if payload[1] != 0x03 || (payload[2] != 0x01 && payload[2] != 0x02 && payload[2] != 0x03 && payload[2] != 0x04) {
		return
	}

	// Check if the handshake type is Client Hello (1)
	if len(payload) < 43 || payload[5] != 0x01 {
		return
	}

	// Extract SNI from Client Hello
	sni := extractSNI(payload)
	if sni == "" {
		return
	}

	// Create TLS connection record
	conn := TLSConnection{
		Timestamp: time.Now(),
		SourceIP:  ip.SrcIP.String(),
		SourceMAC: ethernet.SrcMAC.String(),
		DestIP:    ip.DstIP.String(),
		DestPort:  uint16(tcp.DstPort),
		SNI:       sni,
	}

	// Add to connections list
	s.addConnection(conn)

	// Log the connection
	logrus.Infof("[TLS] %s → %s:%d → SNI: %s",
		conn.SourceIP, conn.DestIP, conn.DestPort, conn.SNI)
	fmt.Printf("[%s] Device %s → TLS SNI → %s\n",
		conn.Timestamp.Format("15:04:05"), conn.SourceIP, conn.SNI)
}

// extractSNI extracts the Server Name Indication from a TLS Client Hello
func extractSNI(data []byte) string {
	/*
	   TLS Client Hello format:
	   - Record header (5 bytes)
	   - Handshake header (4 bytes)
	   - Client Hello:
	     - TLS version (2 bytes)
	     - Random (32 bytes)
	     - Session ID Length (1 byte)
	     - Session ID (variable)
	     - Cipher Suites Length (2 bytes)
	     - Cipher Suites (variable)
	     - Compression Methods Length (1 byte)
	     - Compression Methods (variable)
	     - Extensions Length (2 bytes)
	     - Extensions (variable)
	*/

	// Skip record header (5 bytes) and handshake header (4 bytes)
	offset := 9

	// Skip client version (2 bytes) and random (32 bytes)
	offset += 34

	// Skip session ID
	if offset+1 >= len(data) {
		return ""
	}
	sessionIDLength := int(data[offset])
	offset += 1 + sessionIDLength

	// Skip cipher suites
	if offset+2 >= len(data) {
		return ""
	}
	cipherSuitesLength := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2 + cipherSuitesLength

	// Skip compression methods
	if offset+1 >= len(data) {
		return ""
	}
	compressionMethodsLength := int(data[offset])
	offset += 1 + compressionMethodsLength

	// Check for extensions
	if offset+2 >= len(data) {
		return ""
	}
	extensionsLength := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2

	// Parse extensions
	extensionsEnd := offset + extensionsLength
	if extensionsEnd > len(data) {
		return ""
	}

	for offset < extensionsEnd {
		// Check if we have enough bytes for extension type and length
		if offset+4 > len(data) {
			return ""
		}

		// Get extension type and length
		extensionType := binary.BigEndian.Uint16(data[offset : offset+2])
		extensionLength := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		offset += 4

		// Check if this is the server name extension (type 0)
		if extensionType == 0 {
			// Skip server name list length (2 bytes)
			if offset+2 > len(data) {
				return ""
			}
			offset += 2

			// Check name type (should be 0 for hostname)
			if offset+1 > len(data) || data[offset] != 0 {
				return ""
			}
			offset++

			// Get hostname length and value
			if offset+2 > len(data) {
				return ""
			}
			hostnameLength := int(binary.BigEndian.Uint16(data[offset : offset+2]))
			offset += 2

			if offset+hostnameLength > len(data) {
				return ""
			}
			return string(data[offset : offset+hostnameLength])
		}

		// Skip to next extension
		offset += extensionLength
	}

	return ""
}

// addConnection adds a TLS connection to the history
func (s *Sniffer) addConnection(conn TLSConnection) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Add the new connection
	s.connections = append(s.connections, conn)

	// Remove oldest connections if we exceed the maximum
	if len(s.connections) > s.maxConnections {
		s.connections = s.connections[len(s.connections)-s.maxConnections:]
	}
}
