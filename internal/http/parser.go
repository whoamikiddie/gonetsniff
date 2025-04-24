package http

import (
	"bytes"
	"fmt"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/sirupsen/logrus"
	"github.com/user/gonetsniff/internal/interfaces"
)

// HTTPRequest represents a captured HTTP request
type HTTPRequest struct {
	Timestamp   time.Time
	SourceIP    string
	SourceMAC   string
	DestIP      string
	DestPort    uint16
	Method      string
	Host        string
	URI         string
	UserAgent   string
	ContentType string
}

// Parser handles HTTP packet capture and parsing
type Parser struct {
	interfaces  []interfaces.NetworkInterface
	requests    []HTTPRequest
	mutex       sync.RWMutex
	stopChan    chan struct{}
	maxRequests int
}

// NewParser creates a new HTTP parser
func NewParser(ifaces []interfaces.NetworkInterface) *Parser {
	return &Parser{
		interfaces:  ifaces,
		requests:    make([]HTTPRequest, 0, 1000),
		stopChan:    make(chan struct{}),
		maxRequests: 1000, // Keep last 1000 requests
	}
}

// Start begins HTTP sniffing on all interfaces
func (p *Parser) Start() {
	logrus.Info("Starting HTTP parser")

	for _, iface := range p.interfaces {
		go p.sniffInterface(iface)
	}
}

// Stop stops the HTTP parser
func (p *Parser) Stop() {
	close(p.stopChan)
}

// GetRequests returns a copy of the current HTTP requests
func (p *Parser) GetRequests() []HTTPRequest {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	requests := make([]HTTPRequest, len(p.requests))
	copy(requests, p.requests)
	return requests
}

// GetSummary returns a summary of the HTTP requests
func (p *Parser) GetSummary() map[string]map[string]int {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	// Map of source IP -> host -> count
	summary := make(map[string]map[string]int)
	
	for _, req := range p.requests {
		if _, exists := summary[req.SourceIP]; !exists {
			summary[req.SourceIP] = make(map[string]int)
		}
		summary[req.SourceIP][req.Host]++
	}
	
	return summary
}

// sniffInterface captures HTTP packets on a specific interface
func (p *Parser) sniffInterface(iface interfaces.NetworkInterface) {
	// Open device
	handle, err := pcap.OpenLive(iface.Name, 1600, true, pcap.BlockForever)
	if err != nil {
		logrus.Errorf("Failed to open interface %s for HTTP sniffing: %v", iface.Name, err)
		return
	}
	defer handle.Close()

	// Set filter for HTTP traffic (port 80)
	if err := handle.SetBPFFilter("tcp and port 80"); err != nil {
		logrus.Errorf("Failed to set BPF filter on interface %s: %v", iface.Name, err)
		return
	}

	logrus.Infof("HTTP parser started on interface %s", iface.Name)

	// Use the gopacket library to decode packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		select {
		case <-p.stopChan:
			return
		case packet := <-packetSource.Packets():
			p.processPacket(packet)
		}
	}
}

// processPacket analyzes a packet for HTTP information
func (p *Parser) processPacket(packet gopacket.Packet) {
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
	if len(payload) < 10 { // Too small to be an HTTP request
		return
	}

	// Check if this looks like an HTTP request
	if !isHTTPRequest(payload) {
		return
	}

	// Parse HTTP request
	request := parseHTTPRequest(payload)
	if request.Method == "" || request.Host == "" {
		return
	}

	// Fill in network details
	request.Timestamp = time.Now()
	request.SourceIP = ip.SrcIP.String()
	request.SourceMAC = ethernet.SrcMAC.String()
	request.DestIP = ip.DstIP.String()
	request.DestPort = uint16(tcp.DstPort)

	// Add to requests list
	p.addRequest(request)

	// Log the request
	logrus.Infof("[HTTP] %s → %s:%d → %s %s://%s%s",
		request.SourceIP, request.DestIP, request.DestPort,
		request.Method, "http", request.Host, request.URI)
	fmt.Printf("[%s] Device %s → HTTP %s → %s%s\n",
		request.Timestamp.Format("15:04:05"), request.SourceIP,
		request.Method, request.Host, request.URI)
}

// isHTTPRequest checks if the payload looks like an HTTP request
func isHTTPRequest(payload []byte) bool {
	// Check for common HTTP methods
	methods := [][]byte{
		[]byte("GET "),
		[]byte("POST "),
		[]byte("PUT "),
		[]byte("DELETE "),
		[]byte("HEAD "),
		[]byte("OPTIONS "),
		[]byte("CONNECT "),
		[]byte("TRACE "),
		[]byte("PATCH "),
	}

	for _, method := range methods {
		if bytes.HasPrefix(payload, method) {
			return true
		}
	}
	return false
}

// parseHTTPRequest extracts information from an HTTP request payload
func parseHTTPRequest(payload []byte) HTTPRequest {
	var request HTTPRequest

	// Split the payload into lines
	lines := bytes.Split(payload, []byte("\r\n"))
	if len(lines) < 2 {
		return request
	}

	// Parse the request line
	requestLine := bytes.Split(lines[0], []byte(" "))
	if len(requestLine) < 3 {
		return request
	}

	request.Method = string(requestLine[0])
	request.URI = string(requestLine[1])

	// Parse headers
	for i := 1; i < len(lines); i++ {
		if len(lines[i]) == 0 {
			break
		}

		header := bytes.SplitN(lines[i], []byte(": "), 2)
		if len(header) != 2 {
			continue
		}

		headerName := string(bytes.ToLower(header[0]))
		headerValue := string(header[1])

		switch headerName {
		case "host":
			request.Host = headerValue
		case "user-agent":
			request.UserAgent = headerValue
		case "content-type":
			request.ContentType = headerValue
		}
	}

	return request
}

// addRequest adds an HTTP request to the history
func (p *Parser) addRequest(request HTTPRequest) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	// Add the new request
	p.requests = append(p.requests, request)

	// Remove oldest requests if we exceed the maximum
	if len(p.requests) > p.maxRequests {
		p.requests = p.requests[len(p.requests)-p.maxRequests:]
	}
}
