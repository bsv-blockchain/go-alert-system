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

// developmentKey returns the environment a key is a development genesis key of, or "" if it is not one
func developmentKey(key string) (string, error) {
	for _, env := range devEnvironments {
		network, err := NetworkDefaults(env)
		if err != nil {
			return "", err
		}
		for _, devKey := range network.GenesisKeys {
			if strings.EqualFold(key, devKey) {
				return env, nil
			}
		}
	}
	return "", nil
}

// HasDevelopmentKeys reports whether any of the keys is a development genesis key
func HasDevelopmentKeys(keys []string) (bool, error) {
	for _, key := range keys {
		env, err := developmentKey(key)
		if err != nil {
			return false, err
		}
		if len(env) > 0 {
			return true, nil
		}
	}
	return false, nil
}

// ValidateTrustRoot refuses development genesis keys on any chain other than regtest.
// chain is the chain name reported by the node (getblockchaininfo). Every key is checked,
// so a custom config file or a persisted datastore that holds the development keys is
// caught as well as the local and test environments.
func ValidateTrustRoot(keys []string, chain string) error {
	if chain == ChainRegtest {
		return nil
	}
	for _, key := range keys {
		env, err := developmentKey(key)
		if err != nil {
			return err
		}
		if len(env) > 0 {
			return fmt.Errorf("%w: key %s is a development key from the %q environment, but the node is on chain %q",
				ErrDevelopmentKeysOnPublicChain, key, env, chain)
		}
	}
	return nil
}
