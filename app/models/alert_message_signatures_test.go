package models

import (
	"context"
	"encoding/binary"
	"strings"

	"github.com/bitcoinschema/go-bitcoin"
	"github.com/bitcoinsv/bsvd/bsvec"

	"github.com/bsv-blockchain/go-alert-system/app/models/model"
	"github.com/bsv-blockchain/go-alert-system/utils"
)

// activateTestKeys stores the public keys derived from the given private keys as active keys
func (ts *TestSuite) activateTestKeys(ctx context.Context, privateKeys ...string) {
	for _, priv := range privateKeys {
		pub, err := bitcoin.PubKeyFromPrivateKeyString(priv, true)
		ts.Require().NoError(err)

		key := NewPublicKey(model.WithAllDependencies(ts.Dependencies), model.New())
		key.Key = pub
		key.Active = true
		ts.Require().NoError(key.Save(ctx))
	}
}

// newSignedTestAlert builds an informational alert and signs it with the given private keys
func (ts *TestSuite) newSignedTestAlert(signingKeys []string) *AlertMessage {
	alert := NewAlertMessage(model.WithAllDependencies(ts.Dependencies), model.New())
	alert.SetAlertType(AlertTypeInformational)
	alert.SetVersion(1)
	alert.SetTimestamp(1)
	alert.SequenceNumber = 1
	alert.SetRawMessage([]byte{0x05, 'h', 'e', 'l', 'l', 'o'})
	alert.SerializeData()

	sigs, err := utils.SignWithKeys(alert.GetRawData(), signingKeys)
	ts.Require().NoError(err)
	alert.SetSignatures(sigs)
	return alert
}

// requireSignaturesValid activates the given keys, signs with signingKeys and checks the verdict
func (ts *TestSuite) requireSignaturesValid(activeKeys, signingKeys []string, want bool) {
	ctx := context.Background()
	ts.activateTestKeys(ctx, activeKeys...)
	alert := ts.newSignedTestAlert(signingKeys)

	valid, err := alert.AreSignaturesValid(ctx)
	ts.Require().NoError(err)
	ts.Require().Equal(want, valid)
}

// TestAlertMessage_AreSignaturesValid_ThreeDistinctKeys accepts three signatures from three active keys
func (ts *TestSuite) TestAlertMessage_AreSignaturesValid_ThreeDistinctKeys() {
	ts.requireSignaturesValid(
		[]string{utils.Key1, utils.Key2, utils.Key3, utils.Key4, utils.Key5},
		[]string{utils.Key1, utils.Key2, utils.Key3},
		true,
	)
}

// TestAlertMessage_AreSignaturesValid_ZeroSignatures rejects an empty signature set
func (ts *TestSuite) TestAlertMessage_AreSignaturesValid_ZeroSignatures() {
	ctx := context.Background()
	ts.activateTestKeys(ctx, utils.Key1, utils.Key2, utils.Key3)
	alert := ts.newSignedTestAlert([]string{utils.Key1, utils.Key2, utils.Key3})
	alert.SetSignatures(nil)

	valid, err := alert.AreSignaturesValid(ctx)
	ts.Require().NoError(err)
	ts.Require().False(valid)
}

// TestAlertMessage_AreSignaturesValid_TwoSignatures rejects fewer than three signatures
func (ts *TestSuite) TestAlertMessage_AreSignaturesValid_TwoSignatures() {
	ts.requireSignaturesValid(
		[]string{utils.Key1, utils.Key2, utils.Key3},
		[]string{utils.Key1, utils.Key2},
		false,
	)
}

// TestAlertMessage_AreSignaturesValid_SameKeyThreeTimes rejects three signatures from one keyholder
func (ts *TestSuite) TestAlertMessage_AreSignaturesValid_SameKeyThreeTimes() {
	ts.requireSignaturesValid(
		[]string{utils.Key1, utils.Key2, utils.Key3},
		[]string{utils.Key1, utils.Key1, utils.Key1},
		false,
	)
}

// TestAlertMessage_AreSignaturesValid_RepeatedKey rejects two distinct keys plus a repeat
func (ts *TestSuite) TestAlertMessage_AreSignaturesValid_RepeatedKey() {
	ts.requireSignaturesValid(
		[]string{utils.Key1, utils.Key2, utils.Key3},
		[]string{utils.Key1, utils.Key2, utils.Key1},
		false,
	)
}

// TestAlertMessage_AreSignaturesValid_InactiveKey rejects a signature from a key that is not active
func (ts *TestSuite) TestAlertMessage_AreSignaturesValid_InactiveKey() {
	ts.requireSignaturesValid(
		[]string{utils.Key1, utils.Key2, utils.Key3},
		[]string{utils.Key1, utils.Key2, utils.Key4},
		false,
	)
}

// TestAlertMessage_AreSignaturesValid_TamperedData rejects signatures over different data
func (ts *TestSuite) TestAlertMessage_AreSignaturesValid_TamperedData() {
	ctx := context.Background()
	ts.activateTestKeys(ctx, utils.Key1, utils.Key2, utils.Key3)
	alert := ts.newSignedTestAlert([]string{utils.Key1, utils.Key2, utils.Key3})
	alert.SetRawMessage([]byte{0x05, 'w', 'o', 'r', 'l', 'd'})
	alert.SerializeData()

	valid, err := alert.AreSignaturesValid(ctx)
	ts.Require().NoError(err)
	ts.Require().False(valid)
}

// TestAlertMessage_AreSignaturesValid_NoActiveKeys returns an error when no keys are active
func (ts *TestSuite) TestAlertMessage_AreSignaturesValid_NoActiveKeys() {
	alert := ts.newSignedTestAlert([]string{utils.Key1, utils.Key2, utils.Key3})

	valid, err := alert.AreSignaturesValid(context.Background())
	ts.Require().ErrorIs(err, ErrNoActivePublicKeys)
	ts.Require().False(valid)
}

// TestAlertMessage_AreSignaturesValid_SameKeyStoredTwice rejects two signatures from one
// keyholder whose public key is active under two spellings (here lower and upper case hex).
// Distinctness has to be decided by the key a signature recovers to, not by the stored string.
func (ts *TestSuite) TestAlertMessage_AreSignaturesValid_SameKeyStoredTwice() {
	ctx := context.Background()
	ts.activateTestKeys(ctx, utils.Key1, utils.Key2, utils.Key3)

	pub, err := bitcoin.PubKeyFromPrivateKeyString(utils.Key1, true)
	ts.Require().NoError(err)
	key := NewPublicKey(model.WithAllDependencies(ts.Dependencies), model.New())
	key.Key = strings.ToUpper(pub)
	key.Active = true
	ts.Require().NoError(key.Save(ctx))

	// Which spelling a signature is attributed to depends on map iteration order, so
	// repeat enough times that a string keyed implementation cannot pass by luck
	for i := 0; i < 32; i++ {
		alert := ts.newSignedTestAlert([]string{utils.Key1, utils.Key1, utils.Key2})
		valid, validErr := alert.AreSignaturesValid(ctx)
		ts.Require().NoError(validErr)
		ts.Require().False(valid)
	}
}

// TestAlertMessage_AreSignaturesValid_MalformedSignatures rejects signatures that are not well
// formed compact signatures, without panicking. bsvec.RecoverCompact does not range check R
// and S: an R equal to the curve order is a valid x coordinate on secp256k1, survives point
// decompression and then reaches a nil ModInverse, which is a nil pointer dereference.
func (ts *TestSuite) TestAlertMessage_AreSignaturesValid_MalformedSignatures() {
	ctx := context.Background()
	ts.activateTestKeys(ctx, utils.Key1, utils.Key2, utils.Key3)

	curveOrder := bsvec.S256().N.FillBytes(make([]byte, 32))
	one := make([]byte, 32)
	one[31] = 1

	// compact builds a 65 byte compact signature from a header byte and its R and S components
	compact := func(header byte, r, s []byte) []byte {
		sig := []byte{header}
		sig = append(sig, r...)
		return append(sig, s...)
	}

	tests := []struct {
		name string
		sig  func(valid []byte) []byte
	}{
		{
			name: "R equal to the curve order",
			sig:  func(_ []byte) []byte { return compact(27, curveOrder, one) },
		},
		{
			name: "R equal to the curve order with the odd parity header",
			sig:  func(_ []byte) []byte { return compact(28, curveOrder, one) },
		},
		{
			name: "R zero",
			sig:  func(_ []byte) []byte { return compact(27, make([]byte, 32), one) },
		},
		{
			name: "S zero",
			sig:  func(valid []byte) []byte { return compact(valid[0], valid[1:33], make([]byte, 32)) },
		},
		{
			name: "S equal to the curve order",
			sig:  func(valid []byte) []byte { return compact(valid[0], valid[1:33], curveOrder) },
		},
		{
			name: "header byte below the compact range",
			sig:  func(valid []byte) []byte { return compact(26, valid[1:33], valid[33:]) },
		},
		{
			name: "header byte above the compact range",
			sig:  func(valid []byte) []byte { return compact(35, valid[1:33], valid[33:]) },
		},
		{
			name: "signature shorter than 65 bytes",
			sig:  func(valid []byte) []byte { return valid[:SignatureLength-1] },
		},
		{
			name: "signature longer than 65 bytes",
			sig:  func(valid []byte) []byte { return append(append([]byte{}, valid...), 0) },
		},
	}

	for _, tt := range tests {
		ts.Run(tt.name, func() {
			alert := ts.newSignedTestAlert([]string{utils.Key1, utils.Key2, utils.Key3})
			sigs := alert.signatures
			sigs[0] = tt.sig(sigs[0])
			alert.SetSignatures(sigs)

			valid, err := alert.AreSignaturesValid(ctx)
			ts.Require().NoError(err)
			ts.Require().False(valid)
		})
	}
}

// TestAlertMessage_ReadRaw_SignatureLength ensures every alert type carries the full signature block
func (ts *TestSuite) TestAlertMessage_ReadRaw_SignatureLength() {
	buildAlert := func(alertType uint32, trailing int) []byte {
		raw := make([]byte, 0)
		raw = binary.LittleEndian.AppendUint32(raw, 1)
		raw = binary.LittleEndian.AppendUint32(raw, 1)
		raw = binary.LittleEndian.AppendUint64(raw, 1)
		raw = binary.LittleEndian.AppendUint32(raw, alertType)
		raw = append(raw, []byte("test")...)
		raw = append(raw, make([]byte, trailing)...)
		return raw
	}

	ts.Run("unknown alert type 99 does not get a reduced signature block", func() {
		alert := NewAlertMessage()
		alert.SetRawMessage(buildAlert(99, 128))
		ts.Require().ErrorIs(alert.ReadRaw(), ErrAlertMessageInvalidLength)
	})

	ts.Run("every alert type parses exactly three signatures", func() {
		for _, alertType := range []uint32{uint32(AlertTypeInformational), uint32(AlertTypeSetKeys), 99} {
			alert := NewAlertMessage()
			alert.SetRawMessage(buildAlert(alertType, RequiredSignatures*SignatureLength))
			ts.Require().NoError(alert.ReadRaw())
			ts.Require().Len(alert.signatures, RequiredSignatures)
			ts.Require().Equal([]byte("test"), alert.GetRawMessage())
		}
	})
}
