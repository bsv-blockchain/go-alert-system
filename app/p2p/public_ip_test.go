package p2p

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	maddr "github.com/multiformats/go-multiaddr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errLookupFailed = errors.New("lookup failed")

// fakeClock is a manually advanced clock for the public IP cache
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// newTestCache returns a cache with a fake clock and a counting fetch func
func newTestCache(fetch func(ctx context.Context) (string, error)) (*publicIPCache, *fakeClock, *atomic.Int32) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	calls := new(atomic.Int32)
	return &publicIPCache{
		fetch: func(ctx context.Context) (string, error) {
			calls.Add(1)
			return fetch(ctx)
		},
		now: clock.Now,
	}, clock, calls
}

// waitForRefresh blocks until the background refresh has finished
func waitForRefresh(t *testing.T, c *publicIPCache) {
	t.Helper()
	require.Eventually(t, func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return !c.refreshing
	}, time.Second, time.Millisecond)
}

func TestPublicIPCache_CachesWithinTTL(t *testing.T) {
	c, clock, calls := newTestCache(func(context.Context) (string, error) {
		return "203.0.113.7", nil
	})

	// The first call never blocks on the network; it kicks off a refresh
	assert.Empty(t, c.get())
	waitForRefresh(t, c)

	for i := 0; i < 1000; i++ {
		assert.Equal(t, "203.0.113.7", c.get())
	}
	assert.Equal(t, int32(1), calls.Load())

	// After the TTL expires the stale value is served while one refresh runs
	clock.Advance(publicIPSuccessTTL)
	assert.Equal(t, "203.0.113.7", c.get())
	waitForRefresh(t, c)
	assert.Equal(t, int32(2), calls.Load())
}

func TestPublicIPCache_SingleInFlightRefresh(t *testing.T) {
	release := make(chan struct{})
	c, _, calls := newTestCache(func(context.Context) (string, error) {
		<-release
		return "203.0.113.7", nil
	})

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.get()
		}()
	}
	wg.Wait()
	close(release)
	waitForRefresh(t, c)

	assert.Equal(t, int32(1), calls.Load())
	assert.Equal(t, "203.0.113.7", c.get())
}

func TestPublicIPCache_FailureBackoff(t *testing.T) {
	c, clock, calls := newTestCache(func(context.Context) (string, error) {
		return "", errLookupFailed
	})

	assert.Empty(t, c.get())
	waitForRefresh(t, c)

	// No retries until the backoff has elapsed
	for i := 0; i < 100; i++ {
		assert.Empty(t, c.get())
	}
	assert.Equal(t, int32(1), calls.Load())

	clock.Advance(publicIPFailureBackoff)
	c.get()
	waitForRefresh(t, c)
	assert.Equal(t, int32(2), calls.Load())
}

func TestPublicIPCache_KeepsLastKnownIPOnFailure(t *testing.T) {
	fail := new(atomic.Bool)
	c, clock, _ := newTestCache(func(context.Context) (string, error) {
		if fail.Load() {
			return "", errLookupFailed
		}
		return "203.0.113.7", nil
	})

	c.get()
	waitForRefresh(t, c)

	fail.Store(true)
	clock.Advance(publicIPSuccessTTL)
	c.get()
	waitForRefresh(t, c)
	assert.Equal(t, "203.0.113.7", c.get())
}

func TestGetPublicIP(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		body    string
		want    string
		wantErr bool
	}{
		{name: "valid ip", status: http.StatusOK, body: "203.0.113.7", want: "203.0.113.7"},
		{name: "trims whitespace", status: http.StatusOK, body: " 203.0.113.7\n", want: "203.0.113.7"},
		{name: "non-200", status: http.StatusTooManyRequests, body: "slow down", wantErr: true},
		{name: "html body", status: http.StatusOK, body: "<html>blocked</html>", wantErr: true},
		{name: "ipv4-mapped ipv6 is canonicalized", status: http.StatusOK, body: "::ffff:203.0.113.7", want: "203.0.113.7"},
		{name: "ipv6", status: http.StatusOK, body: "2001:db8::1", wantErr: true},
		{name: "oversized body", status: http.StatusOK, body: strings.Repeat("1", 200), wantErr: true},
		{name: "empty", status: http.StatusOK, body: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer srv.Close()

			orig := publicIPURL
			publicIPURL = srv.URL
			defer func() { publicIPURL = orig }()

			got, err := GetPublicIP(context.Background())
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestGetPublicIP_ReusesConnection verifies repeated lookups share one connection
// instead of opening (and leaking) a new one per call, including when the response
// is an error or larger than what is parsed
func TestGetPublicIP_ReusesConnection(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		body    string
		wantErr bool
	}{
		{name: "valid ip", status: http.StatusOK, body: "203.0.113.7"},
		{name: "oversized error page", status: http.StatusTooManyRequests, body: strings.Repeat("x", 4096), wantErr: true},
		{name: "oversized success body", status: http.StatusOK, body: strings.Repeat("x", 4096), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Start each case with no pooled connections
			publicIPClient.CloseIdleConnections()
			assertSingleConnection(t, tt.status, tt.body, tt.wantErr)
		})
	}
}

// assertSingleConnection performs 20 lookups against a server returning status/body
// and checks they all went over one TCP connection
func assertSingleConnection(t *testing.T, status int, body string, wantErr bool) {
	t.Helper()
	var newConns atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			newConns.Add(1)
		}
	}
	srv.Start()
	defer srv.Close()

	orig := publicIPURL
	publicIPURL = srv.URL
	defer func() { publicIPURL = orig }()

	for i := 0; i < 20; i++ {
		_, err := GetPublicIP(context.Background())
		if wantErr {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
		}
	}
	assert.Equal(t, int32(1), newConns.Load())
}

func TestAddressFactory_PublicIPFallback(t *testing.T) {
	privateAddr := maddr.StringCast("/ip4/172.17.0.2/tcp/9906")
	publicAddr := maddr.StringCast("/ip4/198.51.100.4/tcp/9906")

	newCache := func() (*publicIPCache, *atomic.Int32) {
		c, _, calls := newTestCache(func(context.Context) (string, error) {
			return "203.0.113.7", nil
		})
		c.get()
		waitForRefresh(t, c)
		calls.Store(0)
		return c, calls
	}

	t.Run("no public addrs and reachability unknown uses cached ip", func(t *testing.T) {
		c, calls := newCache()
		factory := newAddressFactory("9906", false, nil, c, new(atomic.Int32))
		for i := 0; i < 100; i++ {
			got := factory([]maddr.Multiaddr{privateAddr})
			require.Len(t, got, 1)
			assert.Equal(t, "/ip4/203.0.113.7/tcp/9906", got[0].String())
		}
		assert.Equal(t, int32(0), calls.Load(), "factory must not hit the network within the TTL")
	})

	t.Run("reachability private skips the guess and the lookup", func(t *testing.T) {
		c, calls := newCache()
		reach := new(atomic.Int32)
		reach.Store(int32(network.ReachabilityPrivate))
		factory := newAddressFactory("9906", false, nil, c, reach)
		assert.Empty(t, factory([]maddr.Multiaddr{privateAddr}))
		assert.Equal(t, int32(0), calls.Load())
	})

	t.Run("observed public addr is preferred over the guess", func(t *testing.T) {
		c, _ := newCache()
		factory := newAddressFactory("9906", false, nil, c, new(atomic.Int32))
		got := factory([]maddr.Multiaddr{privateAddr, publicAddr})
		require.Len(t, got, 1)
		assert.True(t, got[0].Equal(publicAddr))
	})

	t.Run("broadcast ip is preferred over the guess", func(t *testing.T) {
		c, _ := newCache()
		ext := maddr.StringCast("/ip4/192.0.2.9/tcp/9906")
		factory := newAddressFactory("9906", false, ext, c, new(atomic.Int32))
		got := factory([]maddr.Multiaddr{privateAddr})
		require.Len(t, got, 1)
		assert.True(t, got[0].Equal(ext))
	})
}
