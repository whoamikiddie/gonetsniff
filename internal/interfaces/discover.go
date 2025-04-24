package interfaces

import (
	"fmt"
	"net"

	"github.com/sirupsen/logrus"
)

// NetworkInterface represents a network interface with its properties
type NetworkInterface struct {
	Name       string
	Index      int
	HardwareAddr string
	IPv4Addr   string
	IPv4Mask   net.IPMask
	IsUp       bool
}

// DiscoverInterfaces finds all available network interfaces
func DiscoverInterfaces() ([]NetworkInterface, error) {
	var networkInterfaces []NetworkInterface

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("error getting network interfaces: %v", err)
	}

	for _, iface := range ifaces {
		// Skip loopback, non-ethernet interfaces, and interfaces that are down
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			logrus.Warnf("Failed to get addresses for interface %s: %v", iface.Name, err)
			continue
		}

		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok || ipnet.IP.To4() == nil {
				continue // Skip non-IPv4 addresses
			}

			netIface := NetworkInterface{
				Name:         iface.Name,
				Index:        iface.Index,
				HardwareAddr: iface.HardwareAddr.String(),
				IPv4Addr:     ipnet.IP.String(),
				IPv4Mask:     ipnet.Mask,
				IsUp:         iface.Flags&net.FlagUp != 0,
			}

			networkInterfaces = append(networkInterfaces, netIface)
			logrus.Infof("Found interface: %s, IP: %s, MAC: %s", 
				netIface.Name, netIface.IPv4Addr, netIface.HardwareAddr)
		}
	}

	if len(networkInterfaces) == 0 {
		return nil, fmt.Errorf("no suitable network interfaces found")
	}

	return networkInterfaces, nil
}

// GetSubnet returns the subnet for this interface in CIDR notation
func (ni *NetworkInterface) GetSubnet() string {
	ones, _ := ni.IPv4Mask.Size()
	return fmt.Sprintf("%s/%d", ni.IPv4Addr, ones)
}

// GetBroadcastIP returns the broadcast IP for this interface
func (ni *NetworkInterface) GetBroadcastIP() string {
	ip := net.ParseIP(ni.IPv4Addr).To4()
	if ip == nil {
		return ""
	}

	mask := ni.IPv4Mask
	broadcast := net.IP(make([]byte, 4))
	for i := range ip {
		broadcast[i] = ip[i] | ^mask[i]
	}
	
	return broadcast.String()
}
