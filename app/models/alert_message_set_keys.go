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

// Do execute the alert
func (a *AlertMessageSetKeys) Do(ctx context.Context) error {
	err := ClearActivePublicKeys(ctx, a.Config().Services.Datastore)
	if err != nil {
		return err
	}
	for _, key := range a.Keys {
		pk := NewPublicKey(model.WithAllDependencies(a.Config()))
		conditions := map[string]interface{}{
			"key": hex.EncodeToString(key[:]),
		}
		err := model.Get(ctx, pk, conditions, 5*time.Second, false)
		if !errors.Is(err, datastore.ErrNoResults) && err != nil {
			return err
		}
		pk.Key = hex.EncodeToString(key[:])
		pk.Active = true
		pk.LastUpdateHash = a.Hash
		if err = pk.Save(ctx); err != nil {
			return err
		}
	}
	return nil
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
