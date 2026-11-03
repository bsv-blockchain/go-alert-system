package main

import (
	"context"
	"fmt"

	"github.com/bsv-blockchain/go-alert-system/app/config"
)

// trustRootCheck refuses development genesis keys (their private keys are public) unless the
// node is on regtest. The node's chain is fetched once, on first use.
type trustRootCheck struct {
	node  config.NodeInterface
	chain string
}

// verify checks the keys against the node's chain. The chain is fetched whenever the keys include
// a development key, and also when verifyRPC is set (which checks the RPC connection on its own).
func (c *trustRootCheck) verify(ctx context.Context, keys []string, verifyRPC bool) error {
	hasDevKeys, err := config.HasDevelopmentKeys(keys)
	if err != nil {
		return err
	}
	if !hasDevKeys && !verifyRPC {
		return nil
	}
	if len(c.chain) == 0 {
		if c.chain, err = c.node.Chain(ctx); err != nil {
			return fmt.Errorf("error talking to Bitcoin node with supplied RPC credentials: %w", err)
		}
	}
	return config.ValidateTrustRoot(keys, c.chain)
}
