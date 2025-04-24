package capture

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/sirupsen/logrus"
	"github.com/user/gonetsniff/internal/interfaces"
)

// CaptureOptions defines options for packet capture
type CaptureOptions struct {
	OutputDir      string
	RotationSize   int64 // in MB
	RotationPeriod time.Duration
	BPFFilter      string
	MaxFiles       int
	Interfaces     []string // Empty means all interfaces
}

// DefaultCaptureOptions returns default capture options
func DefaultCaptureOptions() CaptureOptions {
	return CaptureOptions{
		OutputDir:      "./captures",
		RotationSize:   100, // 100 MB
		RotationPeriod: 1 * time.Hour,
		BPFFilter:      "",
		MaxFiles:       10,
		Interfaces:     []string{},
	}
}

// PcapCapture handles packet capture to PCAP files
type PcapCapture struct {
	options     CaptureOptions
	interfaces  []interfaces.NetworkInterface
	writers     map[string]*pcapgo.Writer
	files       map[string]*os.File
	fileSizes   map[string]int64
	fileStarted map[string]time.Time
	mutex       sync.Mutex
	stopChan    chan struct{}
	wg          sync.WaitGroup
}

// NewPcapCapture creates a new PCAP capture handler
func NewPcapCapture(ifaces []interfaces.NetworkInterface, options CaptureOptions) (*PcapCapture, error) {
	// Create output directory if it doesn't exist
	if err := os.MkdirAll(options.OutputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %v", err)
	}

	// Filter interfaces if specified
	var filteredIfaces []interfaces.NetworkInterface
	if len(options.Interfaces) == 0 {
		filteredIfaces = ifaces
	} else {
		for _, iface := range ifaces {
			for _, name := range options.Interfaces {
				if iface.Name == name {
					filteredIfaces = append(filteredIfaces, iface)
					break
				}
			}
		}
	}

	if len(filteredIfaces) == 0 {
		return nil, fmt.Errorf("no matching interfaces found")
	}

	return &PcapCapture{
		options:     options,
		interfaces:  filteredIfaces,
		writers:     make(map[string]*pcapgo.Writer),
		files:       make(map[string]*os.File),
		fileSizes:   make(map[string]int64),
		fileStarted: make(map[string]time.Time),
		stopChan:    make(chan struct{}),
	}, nil
}

// Start begins packet capture
func (p *PcapCapture) Start() error {
	logrus.Info("Starting packet capture to PCAP files")

	// Start capture on each interface
	for _, iface := range p.interfaces {
		p.wg.Add(1)
		go func(iface interfaces.NetworkInterface) {
			defer p.wg.Done()
			if err := p.captureInterface(iface); err != nil {
				logrus.Errorf("Error capturing on interface %s: %v", iface.Name, err)
			}
		}(iface)
	}

	return nil
}

// Stop stops packet capture
func (p *PcapCapture) Stop() {
	close(p.stopChan)
	p.wg.Wait()

	// Close all open files
	p.mutex.Lock()
	defer p.mutex.Unlock()

	for name, file := range p.files {
		logrus.Infof("Closing capture file for interface %s", name)
		file.Close()
	}
}

// captureInterface captures packets on a specific interface
func (p *PcapCapture) captureInterface(iface interfaces.NetworkInterface) error {
	// Open the device for capturing
	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("failed to open interface %s: %v", iface.Name, err)
	}
	defer handle.Close()

	// Set BPF filter if specified
	if p.options.BPFFilter != "" {
		if err := handle.SetBPFFilter(p.options.BPFFilter); err != nil {
			return fmt.Errorf("failed to set BPF filter on interface %s: %v", iface.Name, err)
		}
	}

	// Create initial capture file
	if err := p.createNewCaptureFile(iface.Name); err != nil {
		return fmt.Errorf("failed to create capture file: %v", err)
	}

	// Start packet processing
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetChan := packetSource.Packets()

	rotationTicker := time.NewTicker(10 * time.Second) // Check for rotation every 10 seconds
	defer rotationTicker.Stop()

	for {
		select {
		case <-p.stopChan:
			return nil
		case <-rotationTicker.C:
			if err := p.checkRotation(iface.Name); err != nil {
				logrus.Errorf("Error during file rotation for interface %s: %v", iface.Name, err)
			}
		case packet, ok := <-packetChan:
			if !ok {
				return nil
			}
			if err := p.processPacket(iface.Name, packet); err != nil {
				logrus.Errorf("Error processing packet on interface %s: %v", iface.Name, err)
			}
		}
	}
}

// createNewCaptureFile creates a new capture file for an interface
func (p *PcapCapture) createNewCaptureFile(ifaceName string) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	// Close existing file if open
	if file, exists := p.files[ifaceName]; exists {
		file.Close()
		delete(p.files, ifaceName)
		delete(p.writers, ifaceName)
	}

	// Create filename with timestamp
	timestamp := time.Now().Format("20060102-150405")
	filename := filepath.Join(p.options.OutputDir, fmt.Sprintf("%s-%s.pcap", ifaceName, timestamp))

	// Open new file
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create capture file %s: %v", filename, err)
	}

	// Create pcap writer
	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		file.Close()
		return fmt.Errorf("failed to write pcap header: %v", err)
	}

	// Store file and writer
	p.files[ifaceName] = file
	p.writers[ifaceName] = writer
	p.fileSizes[ifaceName] = 0
	p.fileStarted[ifaceName] = time.Now()

	logrus.Infof("Created new capture file for interface %s: %s", ifaceName, filename)

	// Clean up old files if needed
	p.cleanupOldFiles(ifaceName)

	return nil
}

// processPacket processes and writes a packet to the capture file
func (p *PcapCapture) processPacket(ifaceName string, packet gopacket.Packet) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	writer, exists := p.writers[ifaceName]
	if !exists {
		return fmt.Errorf("no writer found for interface %s", ifaceName)
	}

	// Write packet
	if err := writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
		return fmt.Errorf("failed to write packet: %v", err)
	}

	// Update file size
	p.fileSizes[ifaceName] += int64(len(packet.Data()))

	return nil
}

// checkRotation checks if file rotation is needed
func (p *PcapCapture) checkRotation(ifaceName string) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	size, exists := p.fileSizes[ifaceName]
	if !exists {
		return nil
	}

	startTime, exists := p.fileStarted[ifaceName]
	if !exists {
		return nil
	}

	// Check if rotation is needed based on size or time
	sizeLimit := p.options.RotationSize * 1024 * 1024 // Convert MB to bytes
	timeLimit := p.options.RotationPeriod

	if size >= sizeLimit || time.Since(startTime) >= timeLimit {
		p.mutex.Unlock() // Unlock before calling createNewCaptureFile which will lock again
		if err := p.createNewCaptureFile(ifaceName); err != nil {
			p.mutex.Lock() // Lock again before returning
			return err
		}
		p.mutex.Lock() // Lock again after createNewCaptureFile
	}

	return nil
}

// cleanupOldFiles removes old capture files if there are too many
func (p *PcapCapture) cleanupOldFiles(ifaceName string) {
	// Get all capture files for this interface
	pattern := filepath.Join(p.options.OutputDir, fmt.Sprintf("%s-*.pcap", ifaceName))
	files, err := filepath.Glob(pattern)
	if err != nil {
		logrus.Errorf("Failed to list capture files: %v", err)
		return
	}

	// If we have more files than the limit, delete the oldest ones
	if len(files) > p.options.MaxFiles {
		// Sort files by modification time (oldest first)
		type fileInfo struct {
			path    string
			modTime time.Time
		}

		fileInfos := make([]fileInfo, 0, len(files))
		for _, file := range files {
			info, err := os.Stat(file)
			if err != nil {
				logrus.Errorf("Failed to stat file %s: %v", file, err)
				continue
			}
			fileInfos = append(fileInfos, fileInfo{path: file, modTime: info.ModTime()})
		}

		// Sort by modification time (oldest first)
		for i := 0; i < len(fileInfos); i++ {
			for j := i + 1; j < len(fileInfos); j++ {
				if fileInfos[i].modTime.After(fileInfos[j].modTime) {
					fileInfos[i], fileInfos[j] = fileInfos[j], fileInfos[i]
				}
			}
		}

		// Delete oldest files
		filesToDelete := len(fileInfos) - p.options.MaxFiles
		for i := 0; i < filesToDelete; i++ {
			if err := os.Remove(fileInfos[i].path); err != nil {
				logrus.Errorf("Failed to delete old capture file %s: %v", fileInfos[i].path, err)
			} else {
				logrus.Infof("Deleted old capture file: %s", fileInfos[i].path)
			}
		}
	}
}
