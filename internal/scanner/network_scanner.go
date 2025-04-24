package scanner

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/whoamikiddie/gonetsniff/internal/interfaces"
)

// DeviceInfo represents a discovered network device with enhanced information
type DeviceInfo struct {
	IP          string
	MAC         string
	Vendor      string
	Hostname    string
	OpenPorts   []int
	LastSeen    time.Time
	Interface   string
	IsGateway   bool
	DeviceType  string // Router, Mobile, PC, IoT, etc.
	FirstSeen   time.Time
}

// NetworkScanner provides enhanced device discovery
type NetworkScanner struct {
	interfaces []interfaces.NetworkInterface
	devices    map[string]DeviceInfo // IP -> DeviceInfo
	mutex      sync.RWMutex
	stopChan   chan struct{}
}

// NewNetworkScanner creates a new network scanner
func NewNetworkScanner(ifaces []interfaces.NetworkInterface) *NetworkScanner {
	return &NetworkScanner{
		interfaces: ifaces,
		devices:    make(map[string]DeviceInfo),
		stopChan:   make(chan struct{}),
	}
}

// Start begins network scanning
func (s *NetworkScanner) Start() {
	logrus.Info("Starting enhanced network scanner")

	// Start initial scan
	go s.fullNetworkScan()

	// Periodically scan the network
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			go s.fullNetworkScan()
		case <-s.stopChan:
			return
		}
	}
}

// Stop stops the network scanner
func (s *NetworkScanner) Stop() {
	close(s.stopChan)
}

// GetDevices returns a copy of the current devices
func (s *NetworkScanner) GetDevices() []DeviceInfo {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	devices := make([]DeviceInfo, 0, len(s.devices))
	for _, device := range s.devices {
		devices = append(devices, device)
	}
	return devices
}

// fullNetworkScan performs a comprehensive scan of all networks
func (s *NetworkScanner) fullNetworkScan() {
	for _, iface := range s.interfaces {
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

		// Calculate the number of hosts in the subnet
		numHosts := 1 << uint(bits-ones)
		if numHosts > 1024 {
			numHosts = 1024 // Limit to 1024 hosts for large subnets
		}

		// Generate all IP addresses in the subnet
		subnet := ip.Mask(iface.IPv4Mask)
		
		// Use multiple goroutines to scan in parallel
		var wg sync.WaitGroup
		semaphore := make(chan struct{}, 20) // Limit to 20 concurrent scans
		
		for i := 1; i < numHosts-1; i++ {
			targetIP := make(net.IP, len(subnet))
			copy(targetIP, subnet)
			
			// Calculate the host part of the IP
			for j := 0; j < 4; j++ {
				shift := 8 * (3 - j)
				targetIP[j] |= byte((i >> shift) & 0xff)
			}

			// Skip the network address and our own IP
			if targetIP.Equal(subnet) || targetIP.Equal(ip) {
				continue
			}

			wg.Add(1)
			semaphore <- struct{}{} // Acquire semaphore
			
			go func(ip string) {
				defer wg.Done()
				defer func() { <-semaphore }() // Release semaphore
				
				// Check if host is up
				if s.pingHost(ip) {
					// Get MAC address
					mac := s.getMACAddress(ip)
					
					// Get hostname
					hostname := s.getHostname(ip)
					
					// Determine if it's a gateway
					isGateway := s.checkIfGateway(ip)
					
					// Guess device type
					deviceType := s.guessDeviceType(ip, mac)
					
					// Check for common open ports
					openPorts := s.scanCommonPorts(ip)
					
					// Add or update device
					s.addOrUpdateDevice(ip, mac, hostname, openPorts, isGateway, deviceType, iface.Name)
				}
			}(targetIP.String())
		}
		
		wg.Wait()
	}
}

// pingHost checks if a host is up using ping
func (s *NetworkScanner) pingHost(host string) bool {
	cmd := exec.Command("ping", "-c", "1", "-W", "1", host)
	err := cmd.Run()
	return err == nil
}

// getMACAddress gets the MAC address of a host using ARP
func (s *NetworkScanner) getMACAddress(ip string) string {
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

// getHostname attempts to resolve the hostname of an IP
func (s *NetworkScanner) getHostname(ip string) string {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return names[0]
}

// checkIfGateway determines if an IP is likely a gateway
func (s *NetworkScanner) checkIfGateway(ip string) bool {
	// Check if it's the default gateway
	cmd := exec.Command("ip", "route")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	
	return strings.Contains(string(output), fmt.Sprintf("default via %s", ip))
}

// scanCommonPorts checks for common open ports
func (s *NetworkScanner) scanCommonPorts(ip string) []int {
	commonPorts := []int{22, 80, 443, 8080, 8443, 21, 23, 25, 53, 3389, 5900}
	openPorts := []int{}
	
	for _, port := range commonPorts {
		address := fmt.Sprintf("%s:%d", ip, port)
		conn, err := net.DialTimeout("tcp", address, 500*time.Millisecond)
		if err == nil {
			openPorts = append(openPorts, port)
			conn.Close()
		}
	}
	
	return openPorts
}

// guessDeviceType attempts to determine the type of device
func (s *NetworkScanner) guessDeviceType(ip string, mac string) string {
	if mac == "" {
		return "Unknown"
	}
	
	// Check for common vendor prefixes
	macPrefix := strings.ToUpper(mac[:8])
	
	// Apple devices
	if strings.HasPrefix(macPrefix, "00:03:93") || 
	   strings.HasPrefix(macPrefix, "00:05:02") || 
	   strings.HasPrefix(macPrefix, "00:0A:27") || 
	   strings.HasPrefix(macPrefix, "00:0A:95") || 
	   strings.HasPrefix(macPrefix, "00:1E:52") || 
	   strings.HasPrefix(macPrefix, "00:1E:C2") || 
	   strings.HasPrefix(macPrefix, "00:25:00") || 
	   strings.HasPrefix(macPrefix, "00:26:BB") {
		return "Apple Device"
	}
	
	// Cisco routers
	if strings.HasPrefix(macPrefix, "00:00:0C") || 
	   strings.HasPrefix(macPrefix, "00:01:42") || 
	   strings.HasPrefix(macPrefix, "00:03:6B") {
		return "Router/Switch"
	}
	
	// Check open ports for additional clues
	openPorts := s.scanCommonPorts(ip)
	
	// Web servers often have port 80 or 443 open
	if contains(openPorts, 80) || contains(openPorts, 443) || contains(openPorts, 8080) || contains(openPorts, 8443) {
		return "Web Server"
	}
	
	// SSH servers often have port 22 open
	if contains(openPorts, 22) {
		return "Server"
	}
	
	// RDP suggests a Windows machine
	if contains(openPorts, 3389) {
		return "Windows PC"
	}
	
	// VNC suggests a desktop
	if contains(openPorts, 5900) {
		return "Desktop"
	}
	
	return "Unknown"
}

// addOrUpdateDevice adds or updates a device in the device map
func (s *NetworkScanner) addOrUpdateDevice(ip, mac, hostname string, openPorts []int, isGateway bool, deviceType, iface string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	
	device, exists := s.devices[ip]
	if !exists {
		device = DeviceInfo{
			IP:         ip,
			FirstSeen:  time.Now(),
			OpenPorts:  []int{},
		}
		logrus.Infof("New device discovered: IP: %s | MAC: %s | Hostname: %s | Type: %s", 
			ip, mac, hostname, deviceType)
	}
	
	device.LastSeen = time.Now()
	
	if mac != "" {
		device.MAC = mac
	}
	
	if hostname != "" {
		device.Hostname = hostname
	}
	
	if len(openPorts) > 0 {
		device.OpenPorts = openPorts
	}
	
	device.IsGateway = isGateway
	device.DeviceType = deviceType
	device.Interface = iface
	
	s.devices[ip] = device
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
