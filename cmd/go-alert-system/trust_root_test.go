package main

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-alert-system/app/config"
	"github.com/bsv-blockchain/go-alert-system/app/config/mocks"
)

var errNodeDown = errors.New("connection refused")

// newCheck returns a trust root check against a mock node on the given chain, counting chain lookups
func newCheck(chain string, err error) (*trustRootCheck, *int) {
	calls := 0
	return &trustRootCheck{node: &mocks.Node{ChainFunc: func(context.Context) (string, error) {
		calls++
		return chain, err
	}}}, &calls
}

// TestTrustRootCheck covers the startup trust root check
func TestTrustRootCheck(t *testing.T) {
	ctx := context.Background()
	local, err := config.NetworkDefaults(config.EnvironmentLocal)
	require.NoError(t, err)
	mainnet, err := config.NetworkDefaults(config.EnvironmentMainnet)
	require.NoError(t, err)

	t.Run("development keys on main are refused", func(t *testing.T) {
		check, _ := newCheck("main", nil)
		require.ErrorIs(t, check.verify(ctx, local.GenesisKeys, true), config.ErrDevelopmentKeysOnPublicChain)
	})

	t.Run("development keys on main are refused with rpc verification disabled", func(t *testing.T) {
		check, calls := newCheck("main", nil)
		require.ErrorIs(t, check.verify(ctx, local.GenesisKeys, false), config.ErrDevelopmentKeysOnPublicChain)
		require.Equal(t, 1, *calls)
	})

	t.Run("development keys with an unreachable node are refused", func(t *testing.T) {
		check, _ := newCheck("", errNodeDown)
		require.ErrorIs(t, check.verify(ctx, local.GenesisKeys, false), errNodeDown)
	})

	t.Run("development keys on regtest are allowed", func(t *testing.T) {
		check, _ := newCheck(config.ChainRegtest, nil)
		require.NoError(t, check.verify(ctx, local.GenesisKeys, false))
	})

	t.Run("public network keys skip the node when rpc verification is disabled", func(t *testing.T) {
		check, calls := newCheck("", errNodeDown)
		require.NoError(t, check.verify(ctx, mainnet.GenesisKeys, false))
		require.Equal(t, 0, *calls)
	})

	t.Run("public network keys still verify the rpc connection", func(t *testing.T) {
		check, _ := newCheck("", errNodeDown)
		require.ErrorIs(t, check.verify(ctx, mainnet.GenesisKeys, true), errNodeDown)
	})

	t.Run("active keys from a persisted datastore are checked after the config keys", func(t *testing.T) {
		check, calls := newCheck("main", nil)
		require.NoError(t, check.verify(ctx, mainnet.GenesisKeys, true))
		require.ErrorIs(t, check.verify(ctx, local.GenesisKeys[:3], false), config.ErrDevelopmentKeysOnPublicChain)
		require.Equal(t, 1, *calls, "the chain is looked up once")
	})
}
