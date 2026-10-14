package config

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewNodeConfig creates a new NodeConfig struct
func TestNewNodeConfig(t *testing.T) {
	t.Run("test new node config", func(t *testing.T) {
		// Create a new node config
		node := NewNodeConfig("user", "pass", "host")

		val := node.GetRPCUser()
		assert.Equal(t, "user", val)

		val = node.GetRPCPassword()
		assert.Equal(t, "pass", val)

		val = node.GetRPCHost()
		assert.Equal(t, "host", val)
	})
}

// TestNewNodeMock creates a new NodeConfig struct for testing
func TestNewNodeMock(t *testing.T) {
	t.Run("test new node mock", func(t *testing.T) {
		// Create a new node config
		node := NewNodeMock("user", "pass", "host")

		val := node.GetRPCUser()
		assert.Equal(t, "user", val)

		val = node.GetRPCPassword()
		assert.Equal(t, "pass", val)

		val = node.GetRPCHost()
		assert.Equal(t, "host", val)
	})
}

// TestNode_Chain covers reading the chain name from getblockchaininfo
func TestNode_Chain(t *testing.T) {
	serve := func(t *testing.T, status int, body string) NodeInterface {
		t.Helper()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, pass, ok := r.BasicAuth()
			assert.True(t, ok)
			assert.Equal(t, "user", user)
			assert.Equal(t, "pass", pass)
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		}))
		t.Cleanup(srv.Close)
		return NewNodeConfig("user", "pass", srv.URL)
	}

	t.Run("a real node response", func(t *testing.T) {
		// Shaped like SV Node's reply: verificationprogress is a fraction
		node := serve(t, http.StatusOK, `{"result":{"chain":"main","blocks":870000,"headers":870000,`+
			`"bestblockhash":"00000000000000000a1b","difficulty":81215962566.79,"mediantime":1760000000,`+
			`"verificationprogress":0.9999996727845,"chainwork":"0000ab","pruned":false},"error":null,"id":"go-alert-system"}`)
		chain, err := node.Chain(context.Background())
		require.NoError(t, err)
		assert.Equal(t, "main", chain)
	})

	t.Run("an rpc error", func(t *testing.T) {
		node := serve(t, http.StatusInternalServerError, `{"result":null,"error":{"code":-28,"message":"Loading block index..."},"id":"go-alert-system"}`)
		_, err := node.Chain(context.Background())
		require.ErrorIs(t, err, ErrUnexpectedRPCResponse)
		assert.Contains(t, err.Error(), "Loading block index")
	})

	t.Run("wrong credentials", func(t *testing.T) {
		node := serve(t, http.StatusUnauthorized, ``)
		_, err := node.Chain(context.Background())
		require.ErrorIs(t, err, ErrUnexpectedRPCResponse)
		assert.Contains(t, err.Error(), "HTTP 401")
	})

	t.Run("no chain in the response", func(t *testing.T) {
		node := serve(t, http.StatusOK, `{"result":{},"error":null,"id":"go-alert-system"}`)
		_, err := node.Chain(context.Background())
		require.ErrorIs(t, err, ErrUnexpectedRPCResponse)
	})
}
