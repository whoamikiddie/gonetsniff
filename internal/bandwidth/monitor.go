package bandwidth

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

// DeviceStats tracks bandwidth usage for a device
type DeviceStats struct {
	IP            string
	BytesReceived uint64
	BytesSent     uint64
	PacketsReceived uint64
	PacketsSent   uint64
	LastUpdated   time.Time
	RateReceived  float64 // bytes per second
	RateSent      float64 // bytes per second
	mutex         sync.RWMutex
}

// Monitor tracks bandwidth usage across the network
type Monitor struct {
	interfaces     []interfaces.NetworkInterface
	deviceStats    map[string]*DeviceStats // IP -> Stats
	localIPs       map[string]bool
	mutex          sync.RWMutex
	stopChan       chan struct{}
	updateInterval time.Duration
	wg             sync.WaitGroup
}

// NewMonitor creates a new bandwidth monitor
func NewMonitor(ifaces []interfaces.NetworkInterface) *Monitor {
	// Build map of local IPs for quick lookup
	localIPs := make(map[string]bool)
	for _, iface := range ifaces {
		if iface.IPv4Addr != "" {
			localIPs[iface.IPv4Addr] = true
		}
	}

	return &Monitor{
		interfaces:     ifaces,
		deviceStats:    make(map[string]*DeviceStats),
		localIPs:       localIPs,
		stopChan:       make(chan struct{}),
		updateInterval: 1 * time.Second,
	}
}

// Start begins bandwidth monitoring
func (m *Monitor) Start() {
	logrus.Info("Starting bandwidth monitor")

	// Start monitoring on each interface
	for _, iface := range m.interfaces {
		m.wg.Add(1)
		go func(iface interfaces.NetworkInterface) {
			defer m.wg.Done()
			if err := m.monitorInterface(iface); err != nil {
				logrus.Errorf("Error monitoring bandwidth on interface %s: %v", iface.Name, err)
			}
		}(iface)
	}

	// Start rate calculation in a separate goroutine
	go m.calculateRates()
}

// Stop stops bandwidth monitoring
func (m *Monitor) Stop() {
	close(m.stopChan)
	m.wg.Wait()
}

// GetAllStats returns a copy of all device statistics
func (m *Monitor) GetAllStats() map[string]DeviceStats {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	stats := make(map[string]DeviceStats)
	for ip, deviceStat := range m.deviceStats {
		deviceStat.mutex.RLock()
		stats[ip] = DeviceStats{
			IP:             ip,
			BytesReceived:  deviceStat.BytesReceived,
			BytesSent:      deviceStat.BytesSent,
			PacketsReceived: deviceStat.PacketsReceived,
			PacketsSent:    deviceStat.PacketsSent,
			LastUpdated:    deviceStat.LastUpdated,
			RateReceived:   deviceStat.RateReceived,
			RateSent:       deviceStat.RateSent,
		}
		deviceStat.mutex.RUnlock()
	}

	return stats
}

// GetDeviceStats returns statistics for a specific device
func (m *Monitor) GetDeviceStats(ip string) (DeviceStats, bool) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	deviceStat, exists := m.deviceStats[ip]
	if !exists {
		return DeviceStats{}, false
	}

	deviceStat.mutex.RLock()
	defer deviceStat.mutex.RUnlock()

	return DeviceStats{
		IP:             ip,
		BytesReceived:  deviceStat.BytesReceived,
		BytesSent:      deviceStat.BytesSent,
		PacketsReceived: deviceStat.PacketsReceived,
		PacketsSent:    deviceStat.PacketsSent,
		LastUpdated:    deviceStat.LastUpdated,
		RateReceived:   deviceStat.RateReceived,
		RateSent:       deviceStat.RateSent,
	}, true
}

// monitorInterface captures and processes packets on a specific interface
func (m *Monitor) monitorInterface(iface interfaces.NetworkInterface) error {
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
		case <-m.stopChan:
			return nil
		case packet, ok := <-packetChan:
			if !ok {
				return nil
			}
			m.processPacket(packet, iface.IPv4Addr)
		}
	}
}

// processPacket analyzes a packet for bandwidth statistics
func (m *Monitor) processPacket(packet gopacket.Packet, localIP string) {
	// Get IP layer
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}
	
	ip := ipLayer.(*layers.IPv4)
	packetLength := uint64(len(packet.Data()))

	// Determine if packet is inbound or outbound
	srcIP := ip.SrcIP.String()
	dstIP := ip.DstIP.String()

	// Update stats for source device if it's not our local interface
	if !m.isLocalIP(srcIP) {
		m.updateDeviceStats(srcIP, 0, packetLength, 0, 1)
	}

	// Update stats for destination device if it's not our local interface
	if !m.isLocalIP(dstIP) {
		m.updateDeviceStats(dstIP, packetLength, 0, 1, 0)
	}
}

// updateDeviceStats updates bandwidth statistics for a device
func (m *Monitor) updateDeviceStats(ip string, bytesReceived, bytesSent, packetsReceived, packetsSent uint64) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	deviceStat, exists := m.deviceStats[ip]
	if !exists {
		deviceStat = &DeviceStats{
			IP:          ip,
			LastUpdated: time.Now(),
		}
		m.deviceStats[ip] = deviceStat
	}

	deviceStat.mutex.Lock()
	defer deviceStat.mutex.Unlock()

	deviceStat.BytesReceived += bytesReceived
	deviceStat.BytesSent += bytesSent
	deviceStat.PacketsReceived += packetsReceived
	deviceStat.PacketsSent += packetsSent
	deviceStat.LastUpdated = time.Now()
}

// calculateRates periodically calculates bandwidth rates
func (m *Monitor) calculateRates() {
	ticker := time.NewTicker(m.updateInterval)
	defer ticker.Stop()

	// Store previous values for rate calculation
	prevStats := make(map[string]struct {
		bytesReceived uint64
		bytesSent     uint64
		timestamp     time.Time
	})

	for {
		select {
		case <-m.stopChan:
			return
		case <-ticker.C:
			m.mutex.Lock()
			
			now := time.Now()
			
			for ip, deviceStat := range m.deviceStats {
				deviceStat.mutex.Lock()
				
				// Get previous stats
				prev, exists := prevStats[ip]
				if exists {
					// Calculate time difference in seconds
					duration := now.Sub(prev.timestamp).Seconds()
					if duration > 0 {
						// Calculate rates
						deviceStat.RateReceived = float64(deviceStat.BytesReceived-prev.bytesReceived) / duration
						deviceStat.RateSent = float64(deviceStat.BytesSent-prev.bytesSent) / duration
					}
				}
				
				// Update previous stats
				prevStats[ip] = struct {
					bytesReceived uint64
					bytesSent     uint64
					timestamp     time.Time
				}{
					bytesReceived: deviceStat.BytesReceived,
					bytesSent:     deviceStat.BytesSent,
					timestamp:     now,
				}
				
				deviceStat.mutex.Unlock()
			}
			
			m.mutex.Unlock()
		}
	}
}

// isLocalIP checks if an IP is one of our local interfaces
func (m *Monitor) isLocalIP(ip string) bool {
	return m.localIPs[ip]
}

// FormatBytes formats bytes into a human-readable string
func FormatBytes(bytes uint64) string {
	const (
		_          = iota
		KB float64 = 1 << (10 * iota)
		MB
		GB
		TB
	)

	var (
		unit    string
		value   float64
		bytesF  = float64(bytes)
	)

	switch {
	case bytesF >= TB:
		unit = "TB"
		value = bytesF / TB
	case bytesF >= GB:
		unit = "GB"
		value = bytesF / GB
	case bytesF >= MB:
		unit = "MB"
		value = bytesF / MB
	case bytesF >= KB:
		unit = "KB"
		value = bytesF / KB
	default:
		unit = "B"
		value = bytesF
	}

	return fmt.Sprintf("%.2f %s", value, unit)
}

// FormatBytesPerSecond formats a bandwidth rate into a human-readable string
func FormatBytesPerSecond(bytesPerSecond float64) string {
	return fmt.Sprintf("%s/s", FormatBytes(uint64(bytesPerSecond)))
}
