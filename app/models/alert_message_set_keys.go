package models

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/bitcoinschema/go-bitcoin"
	"github.com/bitcoinsv/bsvd/bsvec"
	"github.com/mrz1836/go-datastore"

	"github.com/bsv-blockchain/go-alert-system/app/models/model"
)

const (
	// setKeysCount is the number of public keys carried by a set keys alert
	setKeysCount = 5

	// setKeysPayloadLength is the byte length of a set keys payload
	setKeysPayloadLength = setKeysCount * bsvec.PubKeyBytesLenCompressed
)

// AlertMessageSetKeys is the message for setting keys
type AlertMessageSetKeys struct {
	AlertMessage

	Keys [][33]byte
	Hash string
}

// Read reads the message
func (a *AlertMessageSetKeys) Read(alert []byte) error {
	// Check the length
	if len(alert) != setKeysPayloadLength {
		return fmt.Errorf("%w, got %d bytes, not valid", ErrSetKeysAlertInvalidLength, len(alert))
	}

	// Read the five compressed public keys
	seen := make(map[string]struct{}, setKeysCount)
	for key := 0; key < setKeysCount; key++ {
		start := key * bsvec.PubKeyBytesLenCompressed
		pubKey := alert[start : start+bsvec.PubKeyBytesLenCompressed]

		// Every key must be a valid public key, otherwise signature validation
		// would fail for every future alert once the key set is activated
		pubKeyHex := hex.EncodeToString(pubKey)
		if _, err := bitcoin.PubKeyFromString(pubKeyHex); err != nil {
			return fmt.Errorf("%w: key %d: %s", ErrInvalidPubKeyFormat, key, err.Error())
		}

		// Every key must be distinct, otherwise the effective signing threshold drops
		if _, exists := seen[pubKeyHex]; exists {
			return fmt.Errorf("%w: key %d", ErrDuplicatePubKey, key)
		}
		seen[pubKeyHex] = struct{}{}

		a.Keys = append(a.Keys, [bsvec.PubKeyBytesLenCompressed]byte(pubKey))
	}

	return nil
}

// Do execute the alert: deactivate the current key set and activate the new one
// in a single transaction, so a failure leaves the current key set untouched
func (a *AlertMessageSetKeys) Do(ctx context.Context) error {
	opts := model.WithAllDependencies(a.Config())

	// Read everything first: a datastore transaction only supports writes
	active, err := getAllActivePublicKeys(ctx, opts)
	if err != nil {
		return err
	}

	// One model per row: the current keys, deactivated unless they are in the new set
	rows := make(map[string]*PublicKey, len(active)+len(a.Keys))
	toSave := make([]*PublicKey, 0, len(active)+len(a.Keys))
	for _, pk := range active {
		pk.SetOptions(opts)
		pk.Active = false
		rows[pk.Key] = pk
		toSave = append(toSave, pk)
	}

	// The new keys, reusing an existing row for a key that was seen before
	for _, key := range a.Keys {
		keyHex := hex.EncodeToString(key[:])
		pk, ok := rows[keyHex]
		if !ok {
			pk = NewPublicKey(opts)
			err = model.Get(ctx, pk, map[string]interface{}{"key": keyHex}, 5*time.Second, false)
			if errors.Is(err, datastore.ErrNoResults) {
				pk = NewPublicKey(opts, model.New())
			} else if err != nil {
				return err
			}
			rows[keyHex] = pk
			toSave = append(toSave, pk)
		}
		pk.Key = keyHex
		pk.Active = true
		pk.LastUpdateHash = a.Hash
	}

	// Write every change in one transaction
	return a.Config().Services.Datastore.NewTx(ctx, func(tx *datastore.Transaction) error {
		saved := make([]model.BaseInterface, 0, len(toSave))
		for _, pk := range toSave {
			models, saveErr := pk.BeginSaveWithTx(ctx, tx)
			if saveErr != nil {
				_ = tx.Rollback()
				return saveErr
			}
			saved = append(saved, models...)
		}
		return model.CompleteSaveWithTx(ctx, tx, saved)
	})
}

// ToJSON is the alert in JSON format
func (a *AlertMessageSetKeys) ToJSON(_ context.Context) []byte {
	m := a.ProcessAlertMessage()
	if m == nil {
		return []byte{}
	}
	// TODO: Come back and add a message interface for each alert
	_ = m.Read(a.GetRawMessage())
	data, err := json.MarshalIndent(m, "", "    ")
	if err != nil {
		return []byte{}
	}
	return data
}

// MessageString executes the alert
func (a *AlertMessageSetKeys) MessageString() string {
	if len(a.Keys) < 5 {
		return "Setting keys: alert message contains an incomplete key set."
	}
	return fmt.Sprintf("Setting keys: %x, %x, %x, %x, %x", a.Keys[0], a.Keys[1], a.Keys[2], a.Keys[3], a.Keys[4])
}
