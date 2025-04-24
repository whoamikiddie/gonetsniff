package gateway

import (
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/user/gonetsniff/internal/interfaces"
)

// GatewayInfo stores information about a network gateway
type GatewayInfo struct {
	IP        string
	Interface string
	MAC       string
	IsDefault bool
	LastSeen  time.Time
}

// Detector handles gateway detection
type Detector struct {
	interfaces []interfaces.NetworkInterface
	gateways   map[string]GatewayInfo // IP -> GatewayInfo
	mutex      sync.RWMutex
	stopChan   chan struct{}
}

// NewDetector creates a new gateway detector
func NewDetector(ifaces []interfaces.NetworkInterface) *Detector {
	return &Detector{
		interfaces: ifaces,
		gateways:   make(map[string]GatewayInfo),
		stopChan:   make(chan struct{}),
	}
}

// Start begins gateway detection
func (d *Detector) Start() {
	logrus.Info("Starting gateway detector")

	// Immediately detect gateways
	d.detectGateways()

	// Periodically detect gateways
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			d.detectGateways()
		case <-d.stopChan:
			return
		}
	}
}

// Stop stops the gateway detector
func (d *Detector) Stop() {
	close(d.stopChan)
}

// GetGateways returns a copy of the current gateways
func (d *Detector) GetGateways() []GatewayInfo {
	d.mutex.RLock()
	defer d.mutex.RUnlock()

	gateways := make([]GatewayInfo, 0, len(d.gateways))
	for _, gateway := range d.gateways {
		gateways = append(gateways, gateway)
	}
	return gateways
}

// detectGateways finds all gateways on the network
func (d *Detector) detectGateways() {
	// Method 1: Use 'ip route' command to find default gateway
	cmd := exec.Command("ip", "route")
	output, err := cmd.CombinedOutput()
	if err == nil {
		lines := strings.Split(string(output), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "default") {
				parts := strings.Fields(line)
				if len(parts) >= 3 && parts[0] == "default" && parts[1] == "via" {
					gatewayIP := parts[2]
					iface := ""
					
					// Find the interface
					for i, part := range parts {
						if part == "dev" && i+1 < len(parts) {
							iface = parts[i+1]
							break
						}
					}
					
					// Get MAC address of gateway
					mac := d.getGatewayMAC(gatewayIP)
					
					d.addGateway(gatewayIP, iface, mac, true)
					logrus.Infof("Default gateway detected: %s on interface %s (MAC: %s)", 
						gatewayIP, iface, mac)
				}
			}
		}
	}

	// Method 2: Check each interface's network
	for _, iface := range d.interfaces {
		// Skip interfaces without IP
		if iface.IPv4Addr == "" {
			continue
		}

		// Parse IP and subnet
		ip := net.ParseIP(iface.IPv4Addr).To4()
		if ip == nil {
			continue
		}

		// Get subnet mask
		ones, bits := iface.IPv4Mask.Size()
		if ones == 0 || bits == 0 {
			continue
		}

		// Common gateway patterns to check
		patterns := []int{1, 254}
		
		// For typical home networks (192.168.x.x or 10.x.x.x)
		if (ip[0] == 192 && ip[1] == 168) || ip[0] == 10 {
			subnet := ip.Mask(iface.IPv4Mask)
			
			for _, pattern := range patterns {
				gatewayIP := make(net.IP, len(subnet))
				copy(gatewayIP, subnet)
				gatewayIP[3] = byte(pattern)
				
				// Skip our own IP
				if gatewayIP.Equal(ip) {
					continue
				}
				
				// Check if this IP responds to ping
				if d.pingHost(gatewayIP.String()) {
					mac := d.getGatewayMAC(gatewayIP.String())
					d.addGateway(gatewayIP.String(), iface.Name, mac, false)
					logrus.Infof("Potential gateway detected: %s on interface %s (MAC: %s)", 
						gatewayIP.String(), iface.Name, mac)
				}
			}
		}
	}
}

// pingHost checks if a host responds to ping
func (d *Detector) pingHost(host string) bool {
	cmd := exec.Command("ping", "-c", "1", "-W", "1", host)
	err := cmd.Run()
	return err == nil
}

// getGatewayMAC gets the MAC address of a gateway using ARP
func (d *Detector) getGatewayMAC(ip string) string {
	cmd := exec.Command("arp", "-n", ip)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return ""
	}
	
	lines := strings.Split(string(output), "\n")
	if len(lines) < 2 {
		return ""
	}
	
	// Parse the output (skip header line)
	fields := strings.Fields(lines[1])
	if len(fields) >= 3 {
		return fields[2]
	}
	
	return ""
}

// addGateway adds or updates a gateway
func (d *Detector) addGateway(ip, iface, mac string, isDefault bool) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	
	d.gateways[ip] = GatewayInfo{
		IP:        ip,
		Interface: iface,
		MAC:       mac,
		IsDefault: isDefault,
		LastSeen:  time.Now(),
	}
}
