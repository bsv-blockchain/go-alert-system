package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestValidateGenesisKeys covers validation of the configured genesis keys
func TestValidateGenesisKeys(t *testing.T) {
	valid := []string{
		"027276d234a138415c7d8d61e33ea9c625f0d043fd06f1c863464a58ed7939afe1",
		"0254b81f2e1bed83e414970ae7f7e3373014706251efb6990b5292a020e3a1585c",
		"03801e7b4077edad7ebb3fa87ced7b126ae8eb2fbcb75821001f84a0374eea4a21",
	}

	t.Run("valid distinct compressed keys pass", func(t *testing.T) {
		require.NoError(t, validateGenesisKeys(valid))
	})

	t.Run("a key that is not valid hex is rejected", func(t *testing.T) {
		keys := append([]string{}, valid...)
		keys[1] = "not-a-key"
		require.ErrorIs(t, validateGenesisKeys(keys), ErrInvalidGenesisKey)
	})

	t.Run("a key that is not on the curve is rejected", func(t *testing.T) {
		keys := append([]string{}, valid...)
		keys[1] = "020000000000000000000000000000000000000000000000000000000000000000"
		require.ErrorIs(t, validateGenesisKeys(keys), ErrInvalidGenesisKey)
	})

	t.Run("a repeated key is rejected", func(t *testing.T) {
		keys := append([]string{}, valid...)
		keys[2] = keys[0]
		require.ErrorIs(t, validateGenesisKeys(keys), ErrDuplicateGenesisKey)
	})

	t.Run("the same key in different case is a repeat", func(t *testing.T) {
		keys := append([]string{}, valid...)
		keys[2] = "027276D234A138415C7D8D61E33EA9C625F0D043FD06F1C863464A58ED7939AFE1"
		require.ErrorIs(t, validateGenesisKeys(keys), ErrDuplicateGenesisKey)
	})
}
