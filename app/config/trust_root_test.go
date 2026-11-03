package config

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestValidateTrustRoot covers refusing development genesis keys outside regtest
func TestValidateTrustRoot(t *testing.T) {
	local, err := NetworkDefaults(EnvironmentLocal)
	require.NoError(t, err)
	mainnet, err := NetworkDefaults(EnvironmentMainnet)
	require.NoError(t, err)

	t.Run("development keys on regtest are allowed", func(t *testing.T) {
		require.NoError(t, ValidateTrustRoot(local.GenesisKeys, ChainRegtest))
	})

	for _, chain := range []string{"main", "test", "stn", ""} {
		t.Run("development keys on chain "+chain+" are refused", func(t *testing.T) {
			require.ErrorIs(t, ValidateTrustRoot(local.GenesisKeys, chain), ErrDevelopmentKeysOnPublicChain)
		})
	}

	t.Run("a single development key mixed into other keys is refused", func(t *testing.T) {
		keys := append(append([]string{}, mainnet.GenesisKeys[:4]...), local.GenesisKeys[2])
		require.ErrorIs(t, ValidateTrustRoot(keys, "main"), ErrDevelopmentKeysOnPublicChain)
	})

	t.Run("a development key in upper case is refused", func(t *testing.T) {
		keys := []string{strings.ToUpper(local.GenesisKeys[0])}
		require.ErrorIs(t, ValidateTrustRoot(keys, "test"), ErrDevelopmentKeysOnPublicChain)
	})

	for _, env := range []string{EnvironmentMainnet, EnvironmentProduction, EnvironmentTestnet, EnvironmentStn} {
		t.Run("the "+env+" genesis keys are allowed on any chain", func(t *testing.T) {
			network, err := NetworkDefaults(env)
			require.NoError(t, err)
			for _, chain := range []string{"main", "test", "stn", ChainRegtest} {
				require.NoError(t, ValidateTrustRoot(network.GenesisKeys, chain))
			}
		})
	}
}

// TestHasDevelopmentKeys covers detecting development genesis keys
func TestHasDevelopmentKeys(t *testing.T) {
	local, err := NetworkDefaults(EnvironmentLocal)
	require.NoError(t, err)
	mainnet, err := NetworkDefaults(EnvironmentMainnet)
	require.NoError(t, err)

	has, err := HasDevelopmentKeys(local.GenesisKeys)
	require.NoError(t, err)
	require.True(t, has)

	has, err = HasDevelopmentKeys(append(append([]string{}, mainnet.GenesisKeys...), strings.ToUpper(local.GenesisKeys[4])))
	require.NoError(t, err)
	require.True(t, has)

	has, err = HasDevelopmentKeys(mainnet.GenesisKeys)
	require.NoError(t, err)
	require.False(t, has)

	has, err = HasDevelopmentKeys(nil)
	require.NoError(t, err)
	require.False(t, has)
}
