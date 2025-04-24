package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"path/filepath"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/whoamikiddie/gonetsniff/internal/analyzer"
	"github.com/whoamikiddie/gonetsniff/internal/arp"
	"github.com/whoamikiddie/gonetsniff/internal/bandwidth"
	"github.com/whoamikiddie/gonetsniff/internal/capture"
	"github.com/whoamikiddie/gonetsniff/internal/display"
	"github.com/whoamikiddie/gonetsniff/internal/dns"
	"github.com/whoamikiddie/gonetsniff/internal/fingerprint"
	"github.com/whoamikiddie/gonetsniff/internal/gateway"
	"github.com/whoamikiddie/gonetsniff/internal/geoip"
	"github.com/whoamikiddie/gonetsniff/internal/http"
	"github.com/whoamikiddie/gonetsniff/internal/interfaces"
	"github.com/whoamikiddie/gonetsniff/internal/mitm"
	"github.com/whoamikiddie/gonetsniff/internal/scanner"
	"github.com/whoamikiddie/gonetsniff/internal/spoof"
	"github.com/whoamikiddie/gonetsniff/internal/uniqueid"
	"github.com/whoamikiddie/gonetsniff/internal/tls"
	"github.com/whoamikiddie/gonetsniff/internal/utils"
)

var (
	enableGeoIP      bool
	geoIPAPIKey      string
	enableCapture    bool
	captureFilePath  string
	captureInterface string
	enableARPSpoof   bool
	arpSpooferIface  string
	arpTargets       []string
	arpGateway       string
	enableDNSSpoof   bool
	dnsSpooferIface  string
	enableMITM       bool
	mitmPort         int
	enableDeviceID   bool
)

var rootCmd = &cobra.Command{
	Use:   "gonetsniff",
	Short: "GoNetSniff++ - A Golang-based Real-Time Network Scanner & Packet Sniffer",
	Long: `🕷️ GoNetSniff++ 🕷️
A full-featured, real-time network scanning and traffic monitoring tool, 
written in Golang, designed for cybersecurity researchers, penetration testers, and ethical hackers.

It scans all local networks, detects all connected devices, and captures live traffic,
including DNS queries, HTTP requests, and other protocol activities.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Check for root/admin privileges
		if os.Geteuid() != 0 {
			logrus.Fatal("This program requires root/admin privileges to capture packets. Please run with sudo.")
		}

		// Initialize logger
		utils.InitLogger()

		// Get all network interfaces
		netInterfaces, err := interfaces.DiscoverInterfaces()
		if err != nil {
			logrus.Fatalf("Failed to discover network interfaces: %v", err)
		}

		// Start ARP scanner for each interface
		var arpScanner *arp.Scanner
		for _, iface := range netInterfaces {
			scanner := arp.NewScanner(iface)
			go scanner.Start()
			
			// Use the first interface's scanner for the summary display
			if arpScanner == nil {
				arpScanner = scanner
			}
		}

		// Start DNS sniffer
		dnsSniff := dns.NewSniffer(netInterfaces)
		go dnsSniff.Start()

		// Start HTTP tracker
		httpTracker := http.NewParser(netInterfaces)
		go httpTracker.Start()

		// Start TLS SNI extractor
		tlsSniffer := tls.NewSniffer(netInterfaces)
		go tlsSniffer.Start()
		
		// Start gateway detector
		gatewayDetector := gateway.NewDetector(netInterfaces)
		go gatewayDetector.Start()
		
		// Start enhanced network scanner
		networkScanner := scanner.NewNetworkScanner(netInterfaces)
		go networkScanner.Start()
		
		// Start bandwidth monitor
		bandwidthMonitor := bandwidth.NewMonitor(netInterfaces)
		go bandwidthMonitor.Start()
		
		// Start protocol analyzer
		protocolAnalyzer := analyzer.NewProtocolAnalyzer(netInterfaces)
		go protocolAnalyzer.Start()
		
		// Start device fingerprinter
		deviceFingerprinter := fingerprint.NewDeviceFingerprinter()
		go deviceFingerprinter.Start()
		
		// Initialize unique device classifier if enabled
		var deviceClassifier *uniqueid.DeviceClassifier
		if enableDeviceID {
			deviceClassifier = uniqueid.NewDeviceClassifier(netInterfaces)
			deviceClassifier.Start()
			logrus.Info("Unique device classifier started")
		}
		
		// Initialize ARP spoofer if enabled
		var arpSpoofer *spoof.ARPSpoofer
		if enableARPSpoof {
			arpConfig := spoof.DefaultARPSpooferConfig()
			arpConfig.Enabled = true
			arpConfig.Interface = arpSpooferIface
			arpConfig.TargetIPs = arpTargets
			arpConfig.GatewayIP = arpGateway
			
			arpSpoofer, err = spoof.NewARPSpoofer(arpConfig, netInterfaces)
			if err != nil {
				logrus.Warnf("Failed to initialize ARP spoofer: %v", err)
			} else {
				if err := arpSpoofer.Start(); err != nil {
					logrus.Warnf("Failed to start ARP spoofer: %v", err)
				} else {
					logrus.Info("ARP spoofer started")
				}
			}
		}
		
		// Initialize DNS spoofer if enabled
		var dnsSpoofer *spoof.DNSSpoofer
		if enableDNSSpoof {
			dnsConfig := spoof.DefaultDNSSpooferConfig()
			dnsConfig.Enabled = true
			dnsConfig.Interface = dnsSpooferIface
			
			dnsSpoofer, err = spoof.NewDNSSpoofer(dnsConfig, netInterfaces)
			if err != nil {
				logrus.Warnf("Failed to initialize DNS spoofer: %v", err)
			} else {
				if err := dnsSpoofer.Start(); err != nil {
					logrus.Warnf("Failed to start DNS spoofer: %v", err)
				} else {
					logrus.Info("DNS spoofer started")
				}
			}
		}
		
		// Initialize MITM proxy if enabled
		var mitmProxy *mitm.Proxy
		if enableMITM {
			mitmConfig := mitm.DefaultProxyConfig()
			mitmConfig.Enabled = true
			mitmConfig.Port = mitmPort
			
			mitmProxy, err = mitm.NewProxy(mitmConfig)
			if err != nil {
				logrus.Warnf("Failed to initialize MITM proxy: %v", err)
			} else {
				if err := mitmProxy.Start(); err != nil {
					logrus.Warnf("Failed to start MITM proxy: %v", err)
				} else {
					logrus.Infof("MITM proxy started on port %d", mitmPort)
				}
			}
		}
		
		// Initialize GeoIP locator if enabled
		var ipLocator *geoip.Locator
		if enableGeoIP {
			ipLocator = geoip.NewLocator(geoIPAPIKey)
			logrus.Info("GeoIP location service initialized")
		}
		
		// Start packet capture if enabled
		var packetCapture *capture.PcapCapture
		if enableCapture {
			// Determine which interface to capture on
			captureIface := captureInterface
			if captureIface == "" && len(netInterfaces) > 0 {
				captureIface = netInterfaces[0].Name
			}
			
			if captureIface != "" {
				options := capture.DefaultCaptureOptions()
				options.OutputDir = filepath.Dir(captureFilePath)
				options.Interfaces = []string{captureIface}
				
				packetCapture, err = capture.NewPcapCapture(netInterfaces, options)
				if err != nil {
					logrus.Warnf("Failed to initialize packet capture: %v", err)
				} else {
					if err := packetCapture.Start(); err != nil {
						logrus.Warnf("Failed to start packet capture: %v", err)
					} else {
						logrus.Infof("Packet capture started on interface %s", captureIface)
					}
				}
			} else {
				logrus.Warn("Packet capture enabled but no suitable interface found")
			}
		}
		
		// Start summary display with all components
		summaryDisplay := display.NewSummaryDisplay(
			arpScanner, 
			dnsSniff, 
			httpTracker, 
			tlsSniffer, 
			gatewayDetector, 
			networkScanner,
			bandwidthMonitor,
			protocolAnalyzer,
			ipLocator,
			deviceFingerprinter,
			deviceClassifier,
		)
		summaryDisplay.Start()

		// Wait for interrupt signal
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		fmt.Println("\nShutting down GoNetSniff++...")
		
		// Stop all components
		summaryDisplay.Stop()
		networkScanner.Stop()
		gatewayDetector.Stop()
		bandwidthMonitor.Stop()
		protocolAnalyzer.Stop()
		
		if deviceClassifier != nil {
			deviceClassifier.Stop()
		}
		
		if arpSpoofer != nil {
			arpSpoofer.Stop()
			logrus.Info("ARP spoofer stopped")
		}
		
		if dnsSpoofer != nil {
			dnsSpoofer.Stop()
			logrus.Info("DNS spoofer stopped")
		}
		
		if mitmProxy != nil {
			mitmProxy.Stop()
			logrus.Info("MITM proxy stopped")
		}
		
		if packetCapture != nil {
			packetCapture.Stop()
			logrus.Info("Packet capture stopped")
		}
	},
}

func init() {
	// Add command line flags
	rootCmd.Flags().BoolVar(&enableGeoIP, "geo", false, "Enable GeoIP location service")
	rootCmd.Flags().StringVar(&geoIPAPIKey, "geo-key", "", "API key for GeoIP service (optional)")
	rootCmd.Flags().BoolVar(&enableCapture, "capture", false, "Enable packet capture to PCAP file")
	rootCmd.Flags().StringVar(&captureFilePath, "capture-file", "./capture.pcap", "Path to save PCAP capture file")
	rootCmd.Flags().StringVar(&captureInterface, "capture-iface", "", "Interface to capture packets on (default: first available)")
	
	// Add new flags for ARP spoofing
	rootCmd.Flags().BoolVar(&enableARPSpoof, "arp-spoof", false, "Enable ARP spoofing (MITM)")
	rootCmd.Flags().StringVar(&arpSpooferIface, "arp-iface", "", "Interface to use for ARP spoofing")
	rootCmd.Flags().StringSliceVar(&arpTargets, "arp-targets", []string{}, "Target IPs for ARP spoofing (comma-separated)")
	rootCmd.Flags().StringVar(&arpGateway, "arp-gateway", "", "Gateway IP for ARP spoofing")
	
	// Add new flags for DNS spoofing
	rootCmd.Flags().BoolVar(&enableDNSSpoof, "dns-spoof", false, "Enable DNS spoofing")
	rootCmd.Flags().StringVar(&dnsSpooferIface, "dns-iface", "", "Interface to use for DNS spoofing")
	
	// Add new flags for MITM proxy
	rootCmd.Flags().BoolVar(&enableMITM, "mitm", false, "Enable MITM HTTP/HTTPS proxy")
	rootCmd.Flags().IntVar(&mitmPort, "mitm-port", 8080, "Port to use for MITM proxy")
	
	// Add new flag for device identification
	rootCmd.Flags().BoolVar(&enableDeviceID, "device-id", false, "Enable unique device identification")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
