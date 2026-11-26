package models

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/bitcoinschema/go-bitcoin"
	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-alert-system/app/config"
	"github.com/bsv-blockchain/go-alert-system/app/models/model"
)

// tablePrefixes are the datastore table prefixes a node can run with: the shipped
// environment configs (alert_system, alert_system_mainnet, alert_system_testnet,
// alert_system_stn) and Teranode's default SQLite alert store (alert)
var tablePrefixes = []string{
	"alert_system",
	"alert_system_mainnet",
	"alert_system_testnet",
	"alert_system_stn",
	"alert",
}

// loadWithTablePrefix loads test dependencies backed by a fresh datastore using the given
// table prefix, with the genesis keys active
func loadWithTablePrefix(t *testing.T, prefix string) *config.Config {
	t.Helper()
	t.Setenv(config.EnvironmentKey, config.EnvironmentTest)
	t.Setenv("ALERT_SYSTEM_DATASTORE__TABLE_PREFIX", prefix)

	ctx := context.Background()
	deps, err := config.LoadDependencies(ctx, BaseModels, true)
	require.NoError(t, err)
	t.Cleanup(func() { deps.CloseAll(ctx) })
	require.Equal(t, prefix+"_"+model.TablePublicKeys, deps.Services.Datastore.GetTableName(model.TablePublicKeys))

	require.NoError(t, CreateGenesisAlert(ctx, model.WithAllDependencies(deps)))
	return deps
}

// activeKeys returns the currently active public keys as a set
func activeKeys(t *testing.T, deps *config.Config) map[string]bool {
	t.Helper()
	keys, err := GetActivePublicKey(context.Background(), nil, model.WithAllDependencies(deps))
	require.NoError(t, err)
	set := make(map[string]bool, len(keys))
	for _, k := range keys {
		set[k.Key] = true
	}
	return set
}

// newPubKeys returns n freshly generated compressed public keys (hex)
func newPubKeys(t *testing.T, n int) []string {
	t.Helper()
	pubs := make([]string, 0, n)
	for i := 0; i < n; i++ {
		priv, err := bitcoin.CreatePrivateKeyString()
		require.NoError(t, err)
		pub, err := bitcoin.PubKeyFromPrivateKeyString(priv, true)
		require.NoError(t, err)
		pubs = append(pubs, pub)
	}
	return pubs
}

// rotate runs a set keys alert carrying the given public keys
func rotate(t *testing.T, deps *config.Config, pubs []string) error {
	t.Helper()
	payload := make([]byte, 0, setKeysPayloadLength)
	for _, pub := range pubs {
		b, err := hex.DecodeString(pub)
		require.NoError(t, err)
		payload = append(payload, b...)
	}
	a := &AlertMessageSetKeys{AlertMessage: *NewAlertMessage(model.WithAllDependencies(deps))}
	require.NoError(t, a.Read(payload))
	a.Hash = "00000000000000000000000000000000000000000000000000000000000000aa"
	return a.Do(context.Background())
}

// requireExactly asserts that the active key set is exactly the given keys, one active row per key
func requireExactly(t *testing.T, deps *config.Config, want []string) {
	t.Helper()
	rows, err := getAllActivePublicKeys(context.Background(), model.WithAllDependencies(deps))
	require.NoError(t, err)
	require.Len(t, rows, len(want), "active rows")
	got := activeKeys(t, deps)
	require.Len(t, got, len(want))
	for _, k := range want {
		require.True(t, got[k], "key %s should be active", k)
	}
}

// TestAlertMessageSetKeys_Do_TablePrefixes runs a real key rotation under every table prefix
// a node can use: the old key set must be revoked and the new set activated
func TestAlertMessageSetKeys_Do_TablePrefixes(t *testing.T) {
	for _, prefix := range tablePrefixes {
		t.Run(prefix, func(t *testing.T) {
			deps := loadWithTablePrefix(t, prefix)
			require.Len(t, activeKeys(t, deps), 5)

			newKeys := newPubKeys(t, 5)
			require.NoError(t, rotate(t, deps, newKeys))
			requireExactly(t, deps, newKeys)
		})
	}
}

// TestAlertMessageSetKeys_Do_OverlappingKeys covers a new key set that keeps some of the old keys
func TestAlertMessageSetKeys_Do_OverlappingKeys(t *testing.T) {
	deps := loadWithTablePrefix(t, "alert_system_mainnet")

	newKeys := append(append([]string{}, deps.GenesisKeys[1], deps.GenesisKeys[3]), newPubKeys(t, 3)...)
	require.NoError(t, rotate(t, deps, newKeys))
	requireExactly(t, deps, newKeys)

	// A second rotation from the rotated set (re-runs on existing rows)
	again := append(append([]string{}, newKeys[0], newKeys[4]), newPubKeys(t, 3)...)
	require.NoError(t, rotate(t, deps, again))
	requireExactly(t, deps, again)
}

// TestAlertMessageSetKeys_Do_Idempotent covers the retry cron re-running a rotation that already applied
func TestAlertMessageSetKeys_Do_Idempotent(t *testing.T) {
	deps := loadWithTablePrefix(t, "alert_system_testnet")

	newKeys := newPubKeys(t, 5)
	require.NoError(t, rotate(t, deps, newKeys))
	require.NoError(t, rotate(t, deps, newKeys))
	requireExactly(t, deps, newKeys)
}

// TestAlertMessageSetKeys_Do_RollsBack checks a failure part way through a rotation leaves
// the current key set active: the deactivation of the old keys is rolled back with it
func TestAlertMessageSetKeys_Do_RollsBack(t *testing.T) {
	deps := loadWithTablePrefix(t, "alert_system_mainnet")
	ds := deps.Services.Datastore
	newKeys := newPubKeys(t, 5)

	// Make inserting the last new key fail, after the old keys were deactivated in the transaction
	table := ds.GetTableName(model.TablePublicKeys)
	require.NoError(t, ds.Execute("").Exec(
		"CREATE TRIGGER fail_insert BEFORE INSERT ON "+table+
			" WHEN NEW.key = '"+newKeys[4]+"' BEGIN SELECT RAISE(ABORT, 'injected failure'); END",
	).Error)

	err := rotate(t, deps, newKeys)
	require.ErrorContains(t, err, "injected failure")
	requireExactly(t, deps, deps.GenesisKeys)

	// Once the failure clears, the retry applies the rotation
	require.NoError(t, ds.Execute("").Exec("DROP TRIGGER fail_insert").Error)
	require.NoError(t, rotate(t, deps, newKeys))
	requireExactly(t, deps, newKeys)
}

// TestClearActivePublicKeys_TablePrefixes checks the deactivation targets the prefixed table
func TestClearActivePublicKeys_TablePrefixes(t *testing.T) {
	for _, prefix := range tablePrefixes {
		t.Run(prefix, func(t *testing.T) {
			deps := loadWithTablePrefix(t, prefix)
			require.NoError(t, ClearActivePublicKeys(context.Background(), deps.Services.Datastore))
			require.Empty(t, activeKeys(t, deps))
		})
	}
}
