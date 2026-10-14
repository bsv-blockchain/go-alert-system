package config

import (
	"fmt"
	"strings"
)

// ChainRegtest is the chain name bitcoind reports (getblockchaininfo) for a regression test network
const ChainRegtest = "regtest"

// devEnvironments are the environments whose genesis keys are development keys:
// their private keys are public, so anyone can sign alerts for them
var devEnvironments = []string{EnvironmentLocal, EnvironmentTest}

// ValidateTrustRoot refuses a trust root of development genesis keys on any chain other
// than regtest. chain is the chain name reported by the node (getblockchaininfo).
// Every configured key is checked, so a custom config file that copies the development
// keys is caught as well as the local and test environments.
func ValidateTrustRoot(genesisKeys []string, chain string) error {
	if chain == ChainRegtest {
		return nil
	}

	for _, env := range devEnvironments {
		network, err := NetworkDefaults(env)
		if err != nil {
			return err
		}
		for _, devKey := range network.GenesisKeys {
			for _, key := range genesisKeys {
				if strings.EqualFold(key, devKey) {
					return fmt.Errorf("%w: genesis key %s is a development key from the %q environment, but the node is on chain %q",
						ErrDevelopmentKeysOnPublicChain, key, env, chain)
				}
			}
		}
	}
	return nil
}
