package geoip

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// GeoLocation represents geographic information for an IP address
type GeoLocation struct {
	IP          string  `json:"ip"`
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	City        string  `json:"city"`
	Region      string  `json:"region"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	ISP         string  `json:"isp"`
	Org         string  `json:"org"`
	ASN         string  `json:"as"`
	Timezone    string  `json:"timezone"`
	LastUpdated time.Time
}

// Locator provides IP geolocation services
type Locator struct {
	cache       map[string]GeoLocation
	mutex       sync.RWMutex
	cacheExpiry time.Duration
	apiKey      string
	apiURL      string
	rateLimit   time.Duration
	lastRequest time.Time
	rateMutex   sync.Mutex
}

// NewLocator creates a new IP geolocation service
func NewLocator(apiKey string) *Locator {
	return &Locator{
		cache:       make(map[string]GeoLocation),
		cacheExpiry: 24 * time.Hour,
		apiKey:      apiKey,
		apiURL:      "https://ipapi.co/%s/json/",
		rateLimit:   1 * time.Second, // Respect rate limits
	}
}

// Locate returns the geographic location of an IP address
func (l *Locator) Locate(ip string) (GeoLocation, error) {
	// Check if IP is private
	if isPrivateIP(ip) {
		return GeoLocation{
			IP:          ip,
			Country:     "Private Network",
			CountryCode: "LAN",
			City:        "Local",
			Region:      "Local Network",
			ISP:         "Private",
			LastUpdated: time.Now(),
		}, nil
	}

	// Check cache first
	l.mutex.RLock()
	location, exists := l.cache[ip]
	l.mutex.RUnlock()

	if exists && time.Since(location.LastUpdated) < l.cacheExpiry {
		return location, nil
	}

	// Fetch from API
	location, err := l.fetchLocation(ip)
	if err != nil {
		return GeoLocation{}, err
	}

	// Update cache
	l.mutex.Lock()
	l.cache[ip] = location
	l.mutex.Unlock()

	return location, nil
}

// fetchLocation retrieves location data from the API
func (l *Locator) fetchLocation(ip string) (GeoLocation, error) {
	// Respect rate limiting
	l.rateMutex.Lock()
	timeSinceLastRequest := time.Since(l.lastRequest)
	if timeSinceLastRequest < l.rateLimit {
		time.Sleep(l.rateLimit - timeSinceLastRequest)
	}
	l.lastRequest = time.Now()
	l.rateMutex.Unlock()

	// Create request
	url := fmt.Sprintf(l.apiURL, ip)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return GeoLocation{}, fmt.Errorf("failed to create request: %v", err)
	}

	// Set headers
	req.Header.Set("whoamikiddie-Agent", "GoNetSniff/1.0")
	if l.apiKey != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", l.apiKey))
	}

	// Make request
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return GeoLocation{}, fmt.Errorf("API request failed: %v", err)
	}
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		return GeoLocation{}, fmt.Errorf("API returned status code %d", resp.StatusCode)
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return GeoLocation{}, fmt.Errorf("failed to read response body: %v", err)
	}

	// Parse JSON
	var location GeoLocation
	if err := json.Unmarshal(body, &location); err != nil {
		return GeoLocation{}, fmt.Errorf("failed to parse JSON: %v", err)
	}

	// Set IP and update time
	location.IP = ip
	location.LastUpdated = time.Now()

	logrus.Infof("GeoIP: Located %s in %s, %s (%s)", ip, location.City, location.Country, location.CountryCode)
	return location, nil
}

// GetAllLocations returns all cached locations
func (l *Locator) GetAllLocations() map[string]GeoLocation {
	l.mutex.RLock()
	defer l.mutex.RUnlock()

	locations := make(map[string]GeoLocation)
	for ip, location := range l.cache {
		locations[ip] = location
	}

	return locations
}

// ClearCache clears the location cache
func (l *Locator) ClearCache() {
	l.mutex.Lock()
	defer l.mutex.Unlock()

	l.cache = make(map[string]GeoLocation)
}

// isPrivateIP checks if an IP address is in a private range
func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// Check if this is a private IP
	privateRanges := []struct {
		start net.IP
		end   net.IP
	}{
		{net.ParseIP("10.0.0.0"), net.ParseIP("10.255.255.255")},
		{net.ParseIP("172.16.0.0"), net.ParseIP("172.31.255.255")},
		{net.ParseIP("192.168.0.0"), net.ParseIP("192.168.255.255")},
		{net.ParseIP("127.0.0.0"), net.ParseIP("127.255.255.255")},
	}

	for _, r := range privateRanges {
		if (ipLessThanOrEqual(r.start, ip) && ipLessThanOrEqual(ip, r.end)) {
			return true
		}
	}

	return false
}

// ipLessThanOrEqual compares two IP addresses
func ipLessThanOrEqual(ip1, ip2 net.IP) bool {
	for i := 0; i < len(ip1); i++ {
		if ip1[i] < ip2[i] {
			return true
		}
		if ip1[i] > ip2[i] {
			return false
		}
	}
	return true
}
