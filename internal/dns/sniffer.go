package dns

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/sirupsen/logrus"
	"github.com/user/gonetsniff/internal/interfaces"
)

// DNSQuery represents a captured DNS query
type DNSQuery struct {
	Timestamp    time.Time
	SourceIP     string
	SourceMAC    string
	DestIP       string
	Domain       string
	QueryType    string
	ResponseCode string
	IsResponse   bool
}

// Sniffer handles DNS packet capture
type Sniffer struct {
	interfaces []interfaces.NetworkInterface
	queries    []DNSQuery
	mutex      sync.RWMutex
	stopChan   chan struct{}
	maxQueries int
}

// NewSniffer creates a new DNS sniffer
func NewSniffer(ifaces []interfaces.NetworkInterface) *Sniffer {
	return &Sniffer{
		interfaces: ifaces,
		queries:    make([]DNSQuery, 0, 1000),
		stopChan:   make(chan struct{}),
		maxQueries: 1000, // Keep last 1000 queries
	}
}

// Start begins DNS sniffing on all interfaces
func (s *Sniffer) Start() {
	logrus.Info("Starting DNS sniffer")

	for _, iface := range s.interfaces {
		go s.sniffInterface(iface)
	}
}

// Stop stops the DNS sniffer
func (s *Sniffer) Stop() {
	close(s.stopChan)
}

// GetQueries returns a copy of the current DNS queries
func (s *Sniffer) GetQueries() []DNSQuery {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	queries := make([]DNSQuery, len(s.queries))
	copy(queries, s.queries)
	return queries
}

// GetSummary returns a summary of the DNS queries
func (s *Sniffer) GetSummary() map[string]int {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	summary := make(map[string]int)
	for _, query := range s.queries {
		summary[query.Domain]++
	}
	return summary
}

// sniffInterface captures DNS packets on a specific interface
func (s *Sniffer) sniffInterface(iface interfaces.NetworkInterface) {
	// Open device
	handle, err := pcap.OpenLive(iface.Name, 1600, true, pcap.BlockForever)
	if err != nil {
		logrus.Errorf("Failed to open interface %s for DNS sniffing: %v", iface.Name, err)
		return
	}
	defer handle.Close()

	// Set filter for DNS traffic (port 53)
	if err := handle.SetBPFFilter("udp and port 53"); err != nil {
		logrus.Errorf("Failed to set BPF filter on interface %s: %v", iface.Name, err)
		return
	}

	logrus.Infof("DNS sniffer started on interface %s", iface.Name)

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

// processPacket analyzes a packet for DNS information
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

	// Get UDP layer
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return
	}
	
	// Get DNS layer
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return
	}
	dns := dnsLayer.(*layers.DNS)

	// Process DNS queries and responses
	for _, question := range dns.Questions {
		domain := string(question.Name)
		
		queryType := "Unknown"
		switch question.Type {
		case layers.DNSTypeA:
			queryType = "A"
		case layers.DNSTypeAAAA:
			queryType = "AAAA"
		case layers.DNSTypeCNAME:
			queryType = "CNAME"
		case layers.DNSTypeMX:
			queryType = "MX"
		case layers.DNSTypeNS:
			queryType = "NS"
		case layers.DNSTypeTXT:
			queryType = "TXT"
		case layers.DNSTypePTR:
			queryType = "PTR"
		}

		responseCode := ""
		if dns.QR {
			responseCode = dns.ResponseCode.String()
		}

		query := DNSQuery{
			Timestamp:    time.Now(),
			SourceIP:     ip.SrcIP.String(),
			SourceMAC:    ethernet.SrcMAC.String(),
			DestIP:       ip.DstIP.String(),
			Domain:       domain,
			QueryType:    queryType,
			ResponseCode: responseCode,
			IsResponse:   dns.QR,
		}

		s.addQuery(query)

		// Log the query
		if !dns.QR { // Only log requests, not responses
			logrus.Infof("[DNS] %s → %s → Domain: %s (Type: %s)",
				query.SourceIP, query.DestIP, query.Domain, query.QueryType)
			fmt.Printf("[%s] Device %s → DNS Query → %s (%s)\n",
				query.Timestamp.Format("15:04:05"), query.SourceIP, query.Domain, query.DestIP)
		}
	}
}

// addQuery adds a DNS query to the history
func (s *Sniffer) addQuery(query DNSQuery) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Add the new query
	s.queries = append(s.queries, query)

	// Remove oldest queries if we exceed the maximum
	if len(s.queries) > s.maxQueries {
		s.queries = s.queries[len(s.queries)-s.maxQueries:]
	}
}
