package mitm

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// HTTPSProxyConfig contains configuration for the HTTPS proxy
type HTTPSProxyConfig struct {
	ListenAddr    string
	CertFile      string
	KeyFile       string
	Enabled       bool
	InterceptHTTPS bool
	FilterDomains []string
}

// DefaultHTTPSProxyConfig returns default HTTPS proxy configuration
func DefaultHTTPSProxyConfig() HTTPSProxyConfig {
	return HTTPSProxyConfig{
		ListenAddr:    ":8080",
		CertFile:      "cert.pem",
		KeyFile:       "key.pem",
		Enabled:       false,
		InterceptHTTPS: false,
		FilterDomains: []string{},
	}
}

// HTTPSProxy is a man-in-the-middle HTTP/HTTPS proxy
type HTTPSProxy struct {
	config       HTTPSProxyConfig
	server       *http.Server
	stopChan     chan struct{}
	wg           sync.WaitGroup
	interceptors []HTTPInterceptor
	mutex        sync.RWMutex
}

// HTTPInterceptor defines an interface for HTTP traffic interceptors
type HTTPInterceptor interface {
	ProcessRequest(*http.Request) (*http.Request, error)
	ProcessResponse(*http.Response) (*http.Response, error)
}

// NewHTTPSProxy creates a new HTTPS proxy
func NewHTTPSProxy(config HTTPSProxyConfig) *HTTPSProxy {
	return &HTTPSProxy{
		config:       config,
		stopChan:     make(chan struct{}),
		interceptors: []HTTPInterceptor{},
	}
}

// AddInterceptor adds an HTTP interceptor
func (p *HTTPSProxy) AddInterceptor(interceptor HTTPInterceptor) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.interceptors = append(p.interceptors, interceptor)
}

// Start starts the HTTPS proxy
func (p *HTTPSProxy) Start() error {
	if !p.config.Enabled {
		logrus.Info("HTTPS proxy is disabled")
		return nil
	}

	logrus.Infof("Starting HTTPS proxy on %s", p.config.ListenAddr)

	// Create a custom transport
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	// Create a proxy handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.handleRequest(w, r, transport)
	})

	// Create a server
	p.server = &http.Server{
		Addr:    p.config.ListenAddr,
		Handler: handler,
	}

	// Start the server in a goroutine
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		var err error
		if p.config.InterceptHTTPS {
			// Start with TLS for HTTPS interception
			err = p.server.ListenAndServeTLS(p.config.CertFile, p.config.KeyFile)
		} else {
			// Start without TLS for HTTP-only proxy
			err = p.server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			logrus.Errorf("HTTPS proxy error: %v", err)
		}
	}()

	return nil
}

// Stop stops the HTTPS proxy
func (p *HTTPSProxy) Stop() {
	if !p.config.Enabled || p.server == nil {
		return
	}

	logrus.Info("Stopping HTTPS proxy")
	close(p.stopChan)

	// Shutdown the server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := p.server.Shutdown(ctx); err != nil {
		logrus.Errorf("HTTPS proxy shutdown error: %v", err)
	}

	p.wg.Wait()
}

// handleRequest handles an HTTP request
func (p *HTTPSProxy) handleRequest(w http.ResponseWriter, r *http.Request, transport *http.Transport) {
	// Log the request
	logrus.Infof("[PROXY] %s %s %s", r.RemoteAddr, r.Method, r.URL)

	// Check if we should filter this domain
	if len(p.config.FilterDomains) > 0 {
		shouldFilter := false
		for _, domain := range p.config.FilterDomains {
			if strings.Contains(r.Host, domain) {
				shouldFilter = true
				break
			}
		}
		if !shouldFilter {
			p.handleNonProxiedRequest(w, r)
			return
		}
	}

	// Handle CONNECT method (HTTPS)
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}

	// Process the request through interceptors
	modifiedReq, err := p.processRequestInterceptors(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Create a new request to forward
	req, err := http.NewRequest(modifiedReq.Method, modifiedReq.URL.String(), modifiedReq.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Copy headers
	for key, values := range modifiedReq.Header {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	// Send the request
	resp, err := transport.RoundTrip(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Process the response through interceptors
	modifiedResp, err := p.processResponseInterceptors(resp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Copy response headers
	for key, values := range modifiedResp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Set status code
	w.WriteHeader(modifiedResp.StatusCode)

	// Copy response body
	io.Copy(w, modifiedResp.Body)
}

// handleConnect handles HTTPS CONNECT requests
func (p *HTTPSProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	if !p.config.InterceptHTTPS {
		p.tunnelConnect(w, r)
		return
	}

	// Hijack the connection
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hj.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Respond to the CONNECT request
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// TODO: Implement HTTPS interception with custom certificates
	// This requires generating certificates on the fly and is complex
	// For now, we'll just tunnel the connection

	p.tunnelConnect(w, r)
}

// tunnelConnect creates a tunnel for HTTPS connections
func (p *HTTPSProxy) tunnelConnect(w http.ResponseWriter, r *http.Request) {
	// Connect to the target server
	targetConn, err := net.Dial("tcp", r.Host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer targetConn.Close()

	// Hijack the connection
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hj.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	// Respond to the CONNECT request
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Start bidirectional copy
	p.wg.Add(2)
	go func() {
		defer p.wg.Done()
		io.Copy(targetConn, clientConn)
		targetConn.Close()
	}()
	go func() {
		defer p.wg.Done()
		io.Copy(clientConn, targetConn)
		clientConn.Close()
	}()
}

// handleNonProxiedRequest handles requests that don't match our filter domains
func (p *HTTPSProxy) handleNonProxiedRequest(w http.ResponseWriter, r *http.Request) {
	// Just respond with a simple message
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("GoNetSniff++ Proxy - Domain not in filter list"))
}

// processRequestInterceptors runs the request through all interceptors
func (p *HTTPSProxy) processRequestInterceptors(r *http.Request) (*http.Request, error) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	req := r
	var err error

	for _, interceptor := range p.interceptors {
		req, err = interceptor.ProcessRequest(req)
		if err != nil {
			return nil, err
		}
	}

	return req, nil
}

// processResponseInterceptors runs the response through all interceptors
func (p *HTTPSProxy) processResponseInterceptors(r *http.Response) (*http.Response, error) {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	resp := r
	var err error

	for _, interceptor := range p.interceptors {
		resp, err = interceptor.ProcessResponse(resp)
		if err != nil {
			return nil, err
		}
	}

	return resp, nil
}

// LoggingInterceptor logs HTTP requests and responses
type LoggingInterceptor struct {
	LogRequests  bool
	LogResponses bool
}

// ProcessRequest logs the request
func (i *LoggingInterceptor) ProcessRequest(r *http.Request) (*http.Request, error) {
	if i.LogRequests {
		dump, err := httputil.DumpRequest(r, true)
		if err != nil {
			return r, err
		}
		logrus.Infof("[PROXY REQUEST] %s", string(dump))
	}
	return r, nil
}

// ProcessResponse logs the response
func (i *LoggingInterceptor) ProcessResponse(r *http.Response) (*http.Response, error) {
	if i.LogResponses {
		dump, err := httputil.DumpResponse(r, true)
		if err != nil {
			return r, err
		}
		logrus.Infof("[PROXY RESPONSE] %s", string(dump))
	}
	return r, nil
}

// ContentModifierInterceptor modifies HTTP content
type ContentModifierInterceptor struct {
	RequestReplacements  map[string]string
	ResponseReplacements map[string]string
}

// ProcessRequest modifies the request content
func (i *ContentModifierInterceptor) ProcessRequest(r *http.Request) (*http.Request, error) {
	if len(i.RequestReplacements) == 0 || r.Body == nil {
		return r, nil
	}

	// Read the body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return r, err
	}
	r.Body.Close()

	// Apply replacements
	modified := string(body)
	for from, to := range i.RequestReplacements {
		modified = strings.ReplaceAll(modified, from, to)
	}

	// Create a new body
	r.Body = io.NopCloser(bytes.NewBufferString(modified))
	r.ContentLength = int64(len(modified))

	return r, nil
}

// ProcessResponse modifies the response content
func (i *ContentModifierInterceptor) ProcessResponse(r *http.Response) (*http.Response, error) {
	if len(i.ResponseReplacements) == 0 || r.Body == nil {
		return r, nil
	}

	// Read the body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return r, err
	}
	r.Body.Close()

	// Apply replacements
	modified := string(body)
	for from, to := range i.ResponseReplacements {
		modified = strings.ReplaceAll(modified, from, to)
	}

	// Create a new body
	r.Body = io.NopCloser(bytes.NewBufferString(modified))
	r.ContentLength = int64(len(modified))

	return r, nil
}

// ScriptInjectorInterceptor injects JavaScript into HTML responses
type ScriptInjectorInterceptor struct {
	Script string
}

// ProcessRequest does nothing for requests
func (i *ScriptInjectorInterceptor) ProcessRequest(r *http.Request) (*http.Request, error) {
	return r, nil
}

// ProcessResponse injects JavaScript into HTML responses
func (i *ScriptInjectorInterceptor) ProcessResponse(r *http.Response) (*http.Response, error) {
	if r.Header.Get("Content-Type") != "text/html" || r.Body == nil {
		return r, nil
	}

	// Read the body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return r, err
	}
	r.Body.Close()

	// Inject the script before the closing </body> tag
	html := string(body)
	scriptTag := fmt.Sprintf("<script>%s</script>", i.Script)
	modified := strings.Replace(html, "</body>", scriptTag+"</body>", 1)

	// Create a new body
	r.Body = io.NopCloser(bytes.NewBufferString(modified))
	r.ContentLength = int64(len(modified))

	return r, nil
}

// HeaderModifierInterceptor modifies HTTP headers
type HeaderModifierInterceptor struct {
	RequestHeaders  map[string]string
	ResponseHeaders map[string]string
}

// ProcessRequest modifies request headers
func (i *HeaderModifierInterceptor) ProcessRequest(r *http.Request) (*http.Request, error) {
	for name, value := range i.RequestHeaders {
		r.Header.Set(name, value)
	}
	return r, nil
}

// ProcessResponse modifies response headers
func (i *HeaderModifierInterceptor) ProcessResponse(r *http.Response) (*http.Response, error) {
	for name, value := range i.ResponseHeaders {
		r.Header.Set(name, value)
	}
	return r, nil
}
