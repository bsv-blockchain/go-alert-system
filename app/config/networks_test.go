package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNetworkDefaults tests the method NetworkDefaults()
func TestNetworkDefaults(t *testing.T) {
	mainnetKeys := []string{
		"02a1589f2c8e1a4e7cbf28d4d6b676aa2f30811277883211027950e82a83eb2768",
		"03aec1d40f02ac7f6df701ef8f629515812f1bcd949b6aa6c7a8dd778b748b2433",
		"03ddb2806f3cc48aa36bd4aea6b9f1c7ed3ffc8b9302b198ca963f15beff123678",
		"036846e3e8f4f944af644b6a6c6243889dd90d7b6c3593abb9ccf2acb8c9e606e2",
		"03e45c9dd2b34829c1d27c8b5d16917dd0dc2c88fa0d7bad7bffb9b542229a9304",
	}
	testnetKeys := []string{
		"0203aa8ca16b6b247b109b65e9d7a0f3a23ccae8f093f792e63bf5ce2567f572bc",
		"0289d3a1c6dacd0ee3de7e5a960d8d226ffbdb82b3af41b4c6a01b0230cc6e0dce",
		"0396d8808641463b41fe31b11717294e2e14941454ba6b27967ed571b9848ae768",
		"02aaf9583bd5aa8e5993666e11785ff3b1b0a97694003b22cbd8a2b7150ff27736",
		"02dfb76a88100c2b6cd7ad9c051bc9ef9daf74c9fa13a99cb870865a046a9772f1",
	}

	tests := []struct {
		environment string
		want        Network
	}{
		{
			environment: EnvironmentMainnet,
			want: Network{
				GenesisKeys: mainnetKeys,
				ProtocolID:  "/bitcoin/alert-system/1.0.0",
				TopicName:   "bitcoin_alert_system",
			},
		},
		{
			environment: EnvironmentTestnet,
			want: Network{
				GenesisKeys: testnetKeys,
				ProtocolID:  "/bitcoin-testnet/alert-system/0.0.1",
				TopicName:   "bitcoin_alert_system_testnet",
			},
		},
		{
			environment: EnvironmentStn,
			want: Network{
				GenesisKeys: testnetKeys,
				ProtocolID:  "/bitcoin-stn/alert-system/0.0.1",
				TopicName:   "bitcoin_alert_system_stn",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.environment, func(t *testing.T) {
			got, err := NetworkDefaults(tt.environment)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}

	t.Run("environment is case insensitive", func(t *testing.T) {
		got, err := NetworkDefaults("TestNet")
		require.NoError(t, err)
		assert.Equal(t, "/bitcoin-testnet/alert-system/0.0.1", got.ProtocolID)
	})

	t.Run("production matches mainnet", func(t *testing.T) {
		production, err := NetworkDefaults(EnvironmentProduction)
		require.NoError(t, err)

		mainnet, err := NetworkDefaults(EnvironmentMainnet)
		require.NoError(t, err)

		assert.Equal(t, mainnet, production)
	})

	t.Run("invalid environment", func(t *testing.T) {
		_, err := NetworkDefaults("regtest")
		require.ErrorIs(t, err, ErrInvalidEnvironment)
	})

	t.Run("does not depend on process environment", func(t *testing.T) {
		t.Setenv(EnvironmentKey, EnvironmentTestnet)
		t.Setenv("ALERT_SYSTEM_P2P__ALERT_SYSTEM_PROTOCOL_ID", "/overridden")

		got, err := NetworkDefaults(EnvironmentMainnet)
		require.NoError(t, err)
		assert.Equal(t, "/bitcoin/alert-system/1.0.0", got.ProtocolID)
	})

	t.Run("matches LoadConfigFile", func(t *testing.T) {
		for _, environment := range []string{EnvironmentMainnet, EnvironmentTestnet, EnvironmentStn} {
			t.Setenv(EnvironmentKey, environment)

			c, err := LoadConfigFile()
			require.NoError(t, err)

			got, err := NetworkDefaults(environment)
			require.NoError(t, err)

			assert.Equal(t, c.GenesisKeys, got.GenesisKeys, environment)
			assert.Equal(t, c.P2P.AlertSystemProtocolID, got.ProtocolID, environment)
			assert.Equal(t, c.P2P.TopicName, got.TopicName, environment)
		}
	})
}
