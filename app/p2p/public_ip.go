package p2p

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	// publicIPRequestTimeout bounds a single public IP lookup
	publicIPRequestTimeout = 10 * time.Second

	// publicIPSuccessTTL is how long a resolved public IP is reused before refreshing
	publicIPSuccessTTL = 30 * time.Minute

	// publicIPFailureBackoff is how long to wait before retrying after a failed lookup
	publicIPFailureBackoff = time.Minute

	// publicIPMaxBodyBytes caps how much of the lookup response is read
	publicIPMaxBodyBytes = 64
)

// ErrInvalidPublicIP is returned when the lookup service does not return a valid IPv4 address
var ErrInvalidPublicIP = errors.New("public ip lookup returned an invalid ipv4 address")

// ErrPublicIPLookupStatus is returned when the lookup service responds with a non-2xx status
var ErrPublicIPLookupStatus = errors.New("public ip lookup failed")

// publicIPURL is the lookup endpoint (a var so tests can point it at a local server)
var publicIPURL = "https://ifconfig.me/ip" //nolint:gochecknoglobals // overridden in tests

// publicIPClient is shared across lookups so connections are reused instead of leaked
var publicIPClient = &http.Client{ //nolint:gochecknoglobals // shared client, created once
	Timeout: publicIPRequestTimeout,
	Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			// Force the use of IPv4 by specifying 'tcp4' as the network
			return (&net.Dialer{Timeout: publicIPRequestTimeout}).DialContext(ctx, "tcp4", addr)
		},
		TLSHandshakeTimeout: publicIPRequestTimeout,
		MaxIdleConns:        1,
		IdleConnTimeout:     90 * time.Second,
	},
}

// GetPublicIP fetches the public IPv4 address from ifconfig.me
func GetPublicIP(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, publicIPURL, nil)
	if err != nil {
		return "", err
	}

	resp, err := publicIPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		// Drain so the connection can be reused
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, publicIPMaxBodyBytes))
		return "", fmt.Errorf("%w: status %d", ErrPublicIPLookupStatus, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, publicIPMaxBodyBytes))
	if err != nil {
		return "", err
	}

	ip := strings.TrimSpace(string(body))
	if parsed := net.ParseIP(ip); parsed == nil || parsed.To4() == nil {
		return "", ErrInvalidPublicIP
	}
	return ip, nil
}

// publicIPCache resolves the public IP in the background and caches the result,
// so callers on hot paths (like the libp2p address factory) never do network I/O
type publicIPCache struct {
	mu         sync.Mutex
	ip         string
	expires    time.Time
	refreshing bool

	fetch func(ctx context.Context) (string, error)
	now   func() time.Time
}

// newPublicIPCache creates a cache backed by GetPublicIP
func newPublicIPCache() *publicIPCache {
	return &publicIPCache{
		fetch: GetPublicIP,
		now:   time.Now,
	}
}

// get returns the last known public IP (empty if unknown) and starts a
// single background refresh when the cached value has expired
func (c *publicIPCache) get() string {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.refreshing && !c.now().Before(c.expires) {
		c.refreshing = true
		go c.refresh()
	}
	return c.ip
}

// refresh performs one lookup and records the result
func (c *publicIPCache) refresh() {
	ctx, cancel := context.WithTimeout(context.Background(), publicIPRequestTimeout)
	defer cancel()

	ip, err := c.fetch(ctx)

	c.mu.Lock()
	defer c.mu.Unlock()
	c.refreshing = false
	if err != nil {
		// Keep the last known IP, but back off before trying again
		c.expires = c.now().Add(publicIPFailureBackoff)
		return
	}
	c.ip = ip
	c.expires = c.now().Add(publicIPSuccessTTL)
}
