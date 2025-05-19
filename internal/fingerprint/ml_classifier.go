package fingerprint

import (
	"math"
	"sort"
	"strings"
)

// MLFeatures represents the features used for device classification
type MLFeatures struct {
	TTL                int
	WindowSize         int
	OpenPortsCount     int
	CommonPortsCount   int
	ProtocolsCount     int
	BandwidthUsage     float64
	PacketSize         float64
	InterPacketGap     float64
	TCPFlagsFrequency  map[string]float64
	DHCPOptionsPresent bool
	mDNSPresent        bool
	UPnPPresent        bool
	SSLCipherSuites    []uint16
}

// DeviceClassifier uses machine learning techniques to classify devices
type DeviceClassifier struct {
	features     map[string]*MLFeatures    // IP -> Features
	signatures   map[string]DeviceSignature // Device signatures
	portWeights  map[int]float64           // Port importance weights
	protoWeights map[string]float64        // Protocol importance weights
}

// NewDeviceClassifier creates a new ML-based device classifier
func NewDeviceClassifier() *DeviceClassifier {
	return &DeviceClassifier{
		features:   make(map[string]*MLFeatures),
		signatures: deviceSignatures,
		portWeights: map[int]float64{
			80:    0.8,  // HTTP
			443:   0.8,  // HTTPS
			22:    0.9,  // SSH
			53:    0.7,  // DNS
			5353:  0.6,  // mDNS
			1883:  0.9,  // MQTT
			8883:  0.9,  // MQTT over TLS
			554:   0.8,  // RTSP
			1900:  0.7,  // SSDP
			5228:  0.8,  // Android Push
			62078: 0.8,  // iOS Sync
		},
		protoWeights: map[string]float64{
			"HTTP":    0.7,
			"HTTPS":   0.7,
			"MQTT":    0.9,
			"RTSP":    0.8,
			"mDNS":    0.6,
			"SSDP":    0.7,
			"DHCP":    0.8,
			"DNS":     0.6,
			"SSH":     0.9,
			"Telnet":  0.8,
			"ONVIF":   0.9,
			"ZigBee":  0.9,
			"Z-Wave":  0.9,
			"Thread":  0.9,
		},
	}
}

// UpdateFeatures updates the ML features for a device
func (c *DeviceClassifier) UpdateFeatures(ip string, features *MLFeatures) {
	c.features[ip] = features
}

// ClassifyDevice uses ML techniques to classify a device
func (c *DeviceClassifier) ClassifyDevice(ip string) (string, string, float64) {
	features := c.features[ip]
	if features == nil {
		return "Unknown", "Unknown", 0.0
	}

	scores := make(map[string]float64)

	// Calculate similarity scores for each device signature
	for sigType, sig := range c.signatures {
		score := c.calculateSimilarityScore(features, sig)
		scores[sigType] = score
	}

	// Get the best match
	bestType := ""
	bestCategory := ""
	bestScore := 0.0

	for sigType, score := range scores {
		if score > bestScore {
			bestScore = score
			bestType = sigType
			bestCategory = c.signatures[sigType].Category
		}
	}

	return bestCategory, bestType, bestScore
}

// calculateSimilarityScore calculates how well the features match a signature
func (c *DeviceClassifier) calculateSimilarityScore(features *MLFeatures, sig DeviceSignature) float64 {
	score := 0.0
	weights := 0.0

	// Port matching
	portScore := 0.0
	portWeight := 0.0
	for port := range sig.Ports {
		weight := c.portWeights[port]
		if weight == 0 {
			weight = 0.5
		}
		portWeight += weight
		if features.OpenPortsCount > 0 {
			portScore += weight
		}
	}
	if portWeight > 0 {
		score += (portScore / portWeight) * 0.3
		weights += 0.3
	}

	// Protocol matching
	protoScore := 0.0
	protoWeight := 0.0
	for _, proto := range sig.Protocols {
		weight := c.protoWeights[proto]
		if weight == 0 {
			weight = 0.5
		}
		protoWeight += weight
		if features.ProtocolsCount > 0 {
			protoScore += weight
		}
	}
	if protoWeight > 0 {
		score += (protoScore / protoWeight) * 0.3
		weights += 0.3
	}

	// TCP behavior analysis
	if len(features.TCPFlagsFrequency) > 0 {
		tcpScore := analyzeTCPBehavior(features.TCPFlagsFrequency)
		score += tcpScore * 0.2
		weights += 0.2
	}

	// SSL/TLS analysis
	if len(features.SSLCipherSuites) > 0 {
		tlsScore := analyzeSSLCipherSuites(features.SSLCipherSuites)
		score += tlsScore * 0.1
		weights += 0.1
	}

	// IoT-specific features
	if sig.Category == "IoT" {
		iotScore := analyzeIoTFeatures(features)
		score += iotScore * 0.1
		weights += 0.1
	}

	if weights > 0 {
		return score / weights
	}
	return 0.0
}

// analyzeTCPBehavior analyzes TCP flags patterns
func analyzeTCPBehavior(flags map[string]float64) float64 {
	score := 0.0
	total := 0.0

	for _, freq := range flags {
		total += freq
	}

	if total > 0 {
		// Analyze SYN-ACK ratio
		synFreq := flags["SYN"] / total
		ackFreq := flags["ACK"] / total
		if synFreq > 0 && ackFreq > 0 {
			ratio := synFreq / ackFreq
			score += math.Min(ratio, 1.0) * 0.5
		}

		// Analyze PSH frequency
		pshFreq := flags["PSH"] / total
		score += math.Min(pshFreq*2, 0.5)
	}

	return score
}

// analyzeSSLCipherSuites analyzes SSL/TLS cipher suite preferences
func analyzeSSLCipherSuites(suites []uint16) float64 {
	modernCount := 0
	legacyCount := 0

	for _, suite := range suites {
		if suite >= 0xC02B { // Modern suites typically start from this range
			modernCount++
		} else {
			legacyCount++
		}
	}

	total := float64(modernCount + legacyCount)
	if total > 0 {
		return float64(modernCount) / total
	}
	return 0.0
}

// analyzeIoTFeatures analyzes IoT-specific characteristics
func analyzeIoTFeatures(features *MLFeatures) float64 {
	score := 0.0

	// Check for IoT-specific protocols
	if features.mDNSPresent {
		score += 0.3
	}
	if features.UPnPPresent {
		score += 0.3
	}
	if features.DHCPOptionsPresent {
		score += 0.2
	}

	// Analyze bandwidth patterns
	if features.BandwidthUsage > 0 && features.BandwidthUsage < 1000000 { // Less than 1 Mbps
		score += 0.2
	}

	return math.Min(score, 1.0)
}
