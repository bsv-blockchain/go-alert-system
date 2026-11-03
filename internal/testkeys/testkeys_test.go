package testkeys

import (
	"encoding/hex"
	"testing"

	"github.com/bitcoinschema/go-bitcoin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-alert-system/app/config"
)

// TestKeysMatchDevelopmentGenesisKeys checks the private keys are the ones behind the
// local and test genesis keys, which is what makes those environments development only
func TestKeysMatchDevelopmentGenesisKeys(t *testing.T) {
	for _, env := range []string{config.EnvironmentLocal, config.EnvironmentTest} {
		network, err := config.NetworkDefaults(env)
		require.NoError(t, err)
		require.Len(t, network.GenesisKeys, 5)
		for i, priv := range []string{Key1, Key2, Key3, Key4, Key5} {
			pub, err := bitcoin.PubKeyFromPrivateKeyString(priv, true)
			require.NoError(t, err)
			assert.Equal(t, network.GenesisKeys[i], pub, "%s genesis key %d", env, i)
		}
	}
}

// TestSignWithGenesis_Success tests the function SignWithGenesis
func TestSignWithGenesis_Success(t *testing.T) {
	signatures, err := SignWithGenesis([]byte("test data"))
	require.NoError(t, err)
	require.Len(t, signatures, 3)
	assert.Equal(t, "1f4132a89ccf82d3df3a0ee06105eeee173c374930f84fe0c9f6587790b2cbc6ef65a33bbe4e4b9fe57c65ba816db2d62cff4c9b4e66531cfc549d2be746f495bb", hex.EncodeToString(signatures[0]))
	assert.Equal(t, "1f71934b00f38fc068ce606b9ea6c9a3a73b7f68ed2ec7cfea3ab93cf3b1e117c0605b74b026a9e575e1b63d55b54bd50f493d52cdd37fbaa7e0aba26b96dc0376", hex.EncodeToString(signatures[1]))
	assert.Equal(t, "1f17850af80b856545e77b060057e4c31a45bdc5fa89a6f91a6bb7c8df683b5875269d18ec3dc61c7198ff07d53df241fa61210f3825a871bd485e32329e6fcff2", hex.EncodeToString(signatures[2]))
}
