package arp

import (
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/mdlayher/arp"
	"github.com/sirupsen/logrus"
	"github.com/whoamikiddie/gonetsniff/internal/interfaces"
	"github.com/whoamikiddie/gonetsniff/internal/utils"
)

// Device represents a discovered network device
type Device struct {
	IP        string
	MAC       string
	Vendor    string
	LastSeen  time.Time
	Interface string
}

// Scanner handles ARP scanning for a network interface
type Scanner struct {
	iface       interfaces.NetworkInterface
	devices     map[string]Device
	deviceMutex sync.RWMutex
	stopChan    chan struct{}
}

// NewScanner creates a new ARP scanner for the given interface
func NewScanner(iface interfaces.NetworkInterface) *Scanner {
	return &Scanner{
		iface:    iface,
		devices:  make(map[string]Device),
		stopChan: make(chan struct{}),
	}
}

// Start begins the ARP scanning process
func (s *Scanner) Start() {
	logrus.Infof("Starting ARP scanner on interface %s (%s)", s.iface.Name, s.iface.IPv4Addr)

	// Start passive ARP monitoring
	go s.monitorARPTraffic()

	// Start active scanning
	go s.activeScan()

	// Periodically clean up old devices
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.cleanupOldDevices()
		case <-s.stopChan:
			return
		}
	}
}

// Stop stops the ARP scanner
func (s *Scanner) Stop() {
	close(s.stopChan)
}

// GetDevices returns a copy of the current device list
func (s *Scanner) GetDevices() []Device {
	s.deviceMutex.RLock()
	defer s.deviceMutex.RUnlock()

	devices := make([]Device, 0, len(s.devices))
	for _, device := range s.devices {
		devices = append(devices, device)
	}
	return devices
}

// GetDevicesMap returns the devices map for the summary display
func (s *Scanner) GetDevicesMap() map[string]Device {
	s.deviceMutex.RLock()
	defer s.deviceMutex.RUnlock()

	devicesMap := make(map[string]Device, len(s.devices))
	for ip, device := range s.devices {
		devicesMap[ip] = device
	}
	return devicesMap
}

// monitorARPTraffic passively monitors ARP traffic on the interface
func (s *Scanner) monitorARPTraffic() {
	handle, err := pcap.OpenLive(s.iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		logrus.Errorf("Failed to open interface %s for ARP monitoring: %v", s.iface.Name, err)
		return
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("arp"); err != nil {
		logrus.Errorf("Failed to set BPF filter on interface %s: %v", s.iface.Name, err)
		return
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		select {
		case <-s.stopChan:
			return
		case packet := <-packetSource.Packets():
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}

			arp := arpLayer.(*layers.ARP)
			if arp.Operation != layers.ARPReply {
				continue
			}

			ipAddr := net.IP(arp.SourceProtAddress).String()
			macAddr := net.HardwareAddr(arp.SourceHwAddress).String()
			
			s.addOrUpdateDevice(ipAddr, macAddr)
		}
	}
}

// activeScan performs active ARP scanning of the subnet
func (s *Scanner) activeScan() {
	for {
		select {
		case <-s.stopChan:
			return
		default:
			// Parse the interface IP and subnet
			ip := net.ParseIP(s.iface.IPv4Addr).To4()
			if ip == nil {
				logrus.Errorf("Invalid IPv4 address for interface %s: %s", s.iface.Name, s.iface.IPv4Addr)
				return
			}

			// Create ARP client
			client, err := arp.Dial(&net.Interface{
				Index:        s.iface.Index,
				Name:         s.iface.Name,
				HardwareAddr: net.HardwareAddr([]byte(s.iface.HardwareAddr)),
			})
			if err != nil {
				logrus.Errorf("Failed to create ARP client for interface %s: %v", s.iface.Name, err)
				return
			}
			defer client.Close()

			// Get the subnet mask
			ones, bits := s.iface.IPv4Mask.Size()
			if ones == 0 || bits == 0 {
				logrus.Errorf("Invalid subnet mask for interface %s", s.iface.Name)
				return
			}

			// Calculate the number of hosts in the subnet
			numHosts := 1 << uint(bits-ones)
			if numHosts > 1024 {
				numHosts = 1024 // Limit to 1024 hosts for large subnets
			}

			// Generate all IP addresses in the subnet
			subnet := ip.Mask(s.iface.IPv4Mask)
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

				// Convert net.IP to netip.Addr for the Resolve method
				var targetAddr netip.Addr
				if len(targetIP) == 4 {
					targetAddr = netip.AddrFrom4([4]byte{targetIP[0], targetIP[1], targetIP[2], targetIP[3]})
				} else {
					continue // Skip if not IPv4
				}

				// Send ARP request
				mac, err := client.Resolve(targetAddr)
				if err != nil {
					continue // Skip errors, likely just no response
				}

				s.addOrUpdateDevice(targetIP.String(), mac.String())
			}

			// Sleep before next scan cycle
			time.Sleep(5 * time.Minute)
		}
	}
}

// addOrUpdateDevice adds or updates a device in the device map
func (s *Scanner) addOrUpdateDevice(ip, mac string) {
	s.deviceMutex.Lock()
	defer s.deviceMutex.Unlock()

	vendor := utils.LookupVendor(mac)
	
	device, exists := s.devices[ip]
	if !exists {
		device = Device{
			IP:        ip,
			MAC:       mac,
			Vendor:    vendor,
			Interface: s.iface.Name,
		}
		logrus.Infof("New device discovered: IP: %s | MAC: %s | Vendor: %s | Interface: %s",
			ip, mac, vendor, s.iface.Name)
	}
	
	device.LastSeen = time.Now()
	s.devices[ip] = device
}

// cleanupOldDevices removes devices that haven't been seen for a while
func (s *Scanner) cleanupOldDevices() {
	s.deviceMutex.Lock()
	defer s.deviceMutex.Unlock()

	threshold := time.Now().Add(-30 * time.Minute)
	for ip, device := range s.devices {
		if device.LastSeen.Before(threshold) {
			logrus.Infof("Device timed out: %s (%s)", ip, device.MAC)
			delete(s.devices, ip)
		}
	}
}
