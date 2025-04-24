package hostname

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/hashicorp/mdns"
)

// Resolver handles hostname resolution using multiple methods
type Resolver struct {
	cache     map[string]string
	mutex     sync.RWMutex
	stopChan  chan struct{}
	mdnsCache map[string]string
	mdnsMutex sync.RWMutex
}

// NewResolver creates a new hostname resolver
func NewResolver() *Resolver {
	return &Resolver{
		cache:     make(map[string]string),
		mdnsCache: make(map[string]string),
		stopChan:  make(chan struct{}),
	}
}

// Start begins the hostname resolution service
func (r *Resolver) Start() {
	logrus.Info("Starting hostname resolver")
	go r.startMDNSListener()
}

// Stop stops the hostname resolver
func (r *Resolver) Stop() {
	close(r.stopChan)
}

// ResolveHostname attempts to resolve a hostname using multiple methods
func (r *Resolver) ResolveHostname(ip string) string {
	// Check cache first
	r.mutex.RLock()
	if hostname, exists := r.cache[ip]; exists {
		r.mutex.RUnlock()
		return hostname
	}
	r.mutex.RUnlock()

	// Check mDNS cache
	r.mdnsMutex.RLock()
	if hostname, exists := r.mdnsCache[ip]; exists {
		r.mdnsMutex.RUnlock()
		// Add to main cache
		r.mutex.Lock()
		r.cache[ip] = hostname
		r.mutex.Unlock()
		return hostname
	}
	r.mdnsMutex.RUnlock()

	// Try reverse DNS
	hostname := r.reverseResolve(ip)
	if hostname != "" {
		r.mutex.Lock()
		r.cache[ip] = hostname
		r.mutex.Unlock()
		return hostname
	}

	// Try NetBIOS/SMB
	hostname = r.netbiosResolve(ip)
	if hostname != "" {
		r.mutex.Lock()
		r.cache[ip] = hostname
		r.mutex.Unlock()
		return hostname
	}

	return ""
}

// reverseResolve attempts to resolve a hostname using reverse DNS
func (r *Resolver) reverseResolve(ip string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}

	// Remove trailing dot from PTR record
	hostname := names[0]
	if strings.HasSuffix(hostname, ".") {
		hostname = hostname[:len(hostname)-1]
	}

	logrus.Debugf("Resolved %s to %s via reverse DNS", ip, hostname)
	return hostname
}

// netbiosResolve attempts to resolve a hostname using NetBIOS/SMB
func (r *Resolver) netbiosResolve(ip string) string {
	// This is a simplified implementation
	// For a full implementation, you would need to use a library like github.com/stacktitan/smb
	// or implement the NetBIOS protocol directly

	// For now, we'll just try to connect to the SMB port and check if it's open
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:445", ip), 1*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()

	// If we can connect, we know it's likely a Windows machine
	// In a real implementation, we would send NetBIOS name query packets
	// and parse the response to get the actual hostname
	
	logrus.Debugf("Detected SMB service on %s, likely a Windows device", ip)
	return ""
}

// startMDNSListener starts listening for mDNS announcements
func (r *Resolver) startMDNSListener() {
	// Create a channel for mDNS entries
	entriesCh := make(chan *mdns.ServiceEntry, 10)
	
	// Start listening for mDNS broadcasts
	go func() {
		for {
			select {
			case <-r.stopChan:
				return
			case entry := <-entriesCh:
				if entry.AddrV4 == nil {
					continue
				}
				
				ip := entry.AddrV4.String()
				hostname := entry.Host
				
				// Remove trailing dot
				if strings.HasSuffix(hostname, ".") {
					hostname = hostname[:len(hostname)-1]
				}
				
				// Store in mDNS cache
				r.mdnsMutex.Lock()
				r.mdnsCache[ip] = hostname
				r.mdnsMutex.Unlock()
				
				logrus.Debugf("Discovered device via mDNS: %s (%s)", hostname, ip)
			}
		}
	}()
	
	// Start the mDNS listener
	params := mdns.DefaultParams("_services._dns-sd._udp")
	params.Entries = entriesCh
	params.DisableIPv6 = true
	
	for {
		select {
		case <-r.stopChan:
			return
		default:
			// Perform mDNS query periodically
			if err := mdns.Query(params); err != nil {
				logrus.Errorf("Error querying mDNS: %v", err)
			}
			
			// Sleep before next query
			time.Sleep(30 * time.Second)
		}
	}
}

// GetAllHostnames returns all resolved hostnames
func (r *Resolver) GetAllHostnames() map[string]string {
	r.mutex.RLock()
	defer r.mutex.RUnlock()
	
	// Create a copy of the cache
	result := make(map[string]string, len(r.cache))
	for ip, hostname := range r.cache {
		result[ip] = hostname
	}
	
	return result
}
