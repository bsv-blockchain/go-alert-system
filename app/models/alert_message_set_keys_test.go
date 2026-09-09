package models

import (
	"encoding/hex"

	"github.com/bitcoinschema/go-bitcoin"

	"github.com/bsv-blockchain/go-alert-system/utils"
)

// setKeysPayload builds a 165 byte set keys payload from the given compressed public keys (hex)
func (ts *TestSuite) setKeysPayload(pubKeys ...string) []byte {
	payload := make([]byte, 0, 165)
	for _, pub := range pubKeys {
		b, err := hex.DecodeString(pub)
		ts.Require().NoError(err)
		payload = append(payload, b...)
	}
	return payload
}

// testPubKeys returns the compressed public keys for the test private keys
func (ts *TestSuite) testPubKeys() []string {
	pubs := make([]string, 0, 5)
	for _, priv := range []string{utils.Key1, utils.Key2, utils.Key3, utils.Key4, utils.Key5} {
		pub, err := bitcoin.PubKeyFromPrivateKeyString(priv, true)
		ts.Require().NoError(err)
		pubs = append(pubs, pub)
	}
	return pubs
}

// TestAlertMessageSetKeys_Read covers validation of the keys carried by a set keys alert
func (ts *TestSuite) TestAlertMessageSetKeys_Read() {
	ts.Run("five distinct valid keys parse", func() {
		pubs := ts.testPubKeys()
		alert := &AlertMessageSetKeys{}
		ts.Require().NoError(alert.Read(ts.setKeysPayload(pubs...)))
		ts.Require().Len(alert.Keys, 5)
		ts.Require().Equal(pubs[0], hex.EncodeToString(alert.Keys[0][:]))
	})

	ts.Run("wrong length is rejected", func() {
		alert := &AlertMessageSetKeys{}
		ts.Require().ErrorIs(alert.Read(make([]byte, 164)), ErrSetKeysAlertInvalidLength)
	})

	ts.Run("a key that is not a valid public key is rejected", func() {
		pubs := ts.testPubKeys()
		pubs[2] = "02" + hex.EncodeToString(make([]byte, 32)) // not a point on the curve
		alert := &AlertMessageSetKeys{}
		ts.Require().ErrorIs(alert.Read(ts.setKeysPayload(pubs...)), ErrInvalidPubKeyFormat)
	})

	ts.Run("a repeated key is rejected", func() {
		pubs := ts.testPubKeys()
		pubs[4] = pubs[0]
		alert := &AlertMessageSetKeys{}
		ts.Require().ErrorIs(alert.Read(ts.setKeysPayload(pubs...)), ErrDuplicatePubKey)
	})
}
