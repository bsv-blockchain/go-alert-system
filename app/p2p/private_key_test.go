package p2p

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// peerIDOf returns the peer ID derived from a private key
func peerIDOf(t *testing.T, pk *crypto.PrivKey) peer.ID {
	t.Helper()
	id, err := peer.IDFromPrivateKey(*pk)
	require.NoError(t, err)
	return id
}

// newEd25519Key generates a fresh Ed25519 key for tests
func newEd25519Key(t *testing.T) crypto.PrivKey {
	t.Helper()
	pk, _, err := crypto.GenerateEd25519Key(rand.Reader)
	require.NoError(t, err)
	return pk
}

func TestLoadOrCreatePrivateKeyFile(t *testing.T) {
	t.Run("missing file generates a key and reuses it on the next load", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "alert_system_private_key")

		first, err := loadOrCreatePrivateKeyFile(path)
		require.NoError(t, err)

		info, err := os.Stat(path)
		require.NoError(t, err)
		if runtime.GOOS != "windows" {
			assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
		}

		second, err := loadOrCreatePrivateKeyFile(path)
		require.NoError(t, err)
		assert.Equal(t, peerIDOf(t, first), peerIDOf(t, second))
	})

	t.Run("empty placeholder file generates a key", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "alert_system_private_key")
		require.NoError(t, os.WriteFile(path, nil, 0o600))

		first, err := loadOrCreatePrivateKeyFile(path)
		require.NoError(t, err)
		second, err := loadOrCreatePrivateKeyFile(path)
		require.NoError(t, err)
		assert.Equal(t, peerIDOf(t, first), peerIDOf(t, second))
	})

	t.Run("protobuf file written by earlier versions is loaded as-is", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "alert_system_private_key")
		key := newEd25519Key(t)
		data, err := crypto.MarshalPrivateKey(key)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(path, data, 0o600))

		loaded, err := loadOrCreatePrivateKeyFile(path)
		require.NoError(t, err)
		assert.True(t, key.Equals(*loaded))

		after, err := os.ReadFile(path) //nolint:gosec // test temp file
		require.NoError(t, err)
		assert.Equal(t, data, after, "existing key file must not be rewritten")
	})

	t.Run("hex raw ed25519 key (private_key format) is loaded", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "alert_system_private_key")
		key := newEd25519Key(t)
		raw, err := key.Raw()
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(path, []byte(hex.EncodeToString(raw)+"\n"), 0o600))

		loaded, err := loadOrCreatePrivateKeyFile(path)
		require.NoError(t, err)
		assert.True(t, key.Equals(*loaded))
	})

	t.Run("hex protobuf key is loaded", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "alert_system_private_key")
		key := newEd25519Key(t)
		data, err := crypto.MarshalPrivateKey(key)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(path, []byte(hex.EncodeToString(data)), 0o600))

		loaded, err := loadOrCreatePrivateKeyFile(path)
		require.NoError(t, err)
		assert.True(t, key.Equals(*loaded))
	})

	t.Run("invalid contents return an error and leave the file untouched", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "alert_system_private_key")
		garbage := []byte("not a private key")
		require.NoError(t, os.WriteFile(path, garbage, 0o600))

		_, err := loadOrCreatePrivateKeyFile(path)
		require.ErrorIs(t, err, ErrInvalidPrivateKeyFile)

		after, err := os.ReadFile(path) //nolint:gosec // test temp file
		require.NoError(t, err)
		assert.Equal(t, garbage, after)
	})

	t.Run("read errors other than not-exist are returned", func(t *testing.T) {
		// A directory at the key path can't be read as a file
		_, err := loadOrCreatePrivateKeyFile(t.TempDir())
		require.Error(t, err)
	})
}

// TestNewServer_PrivateKeyPathStableAcrossRestarts reproduces #185: with only
// private_key_path configured, the peer ID must survive a restart
func TestNewServer_PrivateKeyPathStableAcrossRestarts(t *testing.T) {
	deps := loadTestDependencies(t)
	deps.P2P.PrivateKey = ""
	deps.P2P.PrivateKeyPath = filepath.Join(t.TempDir(), "alert_system_private_key")
	deps.P2P.IP = "127.0.0.1"
	deps.P2P.Port = "0"

	start := func() peer.ID {
		s, err := NewServer(ServerOptions{
			Config: deps,
			// Never hit ifconfig.me from tests
			publicIPFetch: func(context.Context) (string, error) { return "", errLookupFailed },
		})
		require.NoError(t, err)
		id := s.host.ID()
		require.NoError(t, s.closeHostResources())
		return id
	}

	first := start()
	second := start()
	assert.Equal(t, first, second)
}
