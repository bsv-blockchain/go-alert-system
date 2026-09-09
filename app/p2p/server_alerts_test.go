package p2p

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/bitcoinschema/go-bitcoin"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-alert-system/app/models"
	"github.com/bsv-blockchain/go-alert-system/app/models/model"
	"github.com/bsv-blockchain/go-alert-system/utils"
)

// duplicateKeySetKeysPayload builds a 165 byte set keys payload that repeats a key
func duplicateKeySetKeysPayload(t *testing.T) []byte {
	t.Helper()
	payload := make([]byte, 0, 165)
	for _, priv := range []string{utils.Key1, utils.Key2, utils.Key3, utils.Key4, utils.Key1} {
		pub, err := bitcoin.PubKeyFromPrivateKeyString(priv, true)
		require.NoError(t, err)
		b, err := hex.DecodeString(pub)
		require.NoError(t, err)
		payload = append(payload, b...)
	}
	return payload
}

// newTestServer returns a server wired to the test dependencies with the webhook disabled
func newTestServer(t *testing.T) *Server {
	t.Helper()
	deps := loadTestDependencies(t)
	deps.AlertWebhookURL = ""
	return &Server{config: deps}
}

// TestServer_handleAlert covers alerts arriving over pubsub
func TestServer_handleAlert(t *testing.T) {
	from := peer.ID("peer")

	t.Run("the next sequence is stored and processed", func(t *testing.T) {
		s := newTestServer(t)
		raw := signedAlertBytes(t, s.config, models.AlertTypeInformational, 1)

		require.NoError(t, s.handleAlert(context.Background(), "topic", raw, from))

		saved, err := models.GetAlertMessageBySequenceNumber(context.Background(), 1, model.WithAllDependencies(s.config))
		require.NoError(t, err)
		require.True(t, saved.Processed)
	})

	t.Run("a sequence that is already stored is rejected", func(t *testing.T) {
		s := newTestServer(t)
		raw := signedAlertBytes(t, s.config, models.AlertTypeInformational, 1)
		storeAlert(t, s.config, raw)
		stored := countAlerts(t, s.config)

		require.ErrorIs(t, s.handleAlert(context.Background(), "topic", raw, from), ErrDuplicateAlert)
		require.Equal(t, stored, countAlerts(t, s.config))
	})

	t.Run("a sequence whose predecessor is missing is rejected", func(t *testing.T) {
		s := newTestServer(t)
		raw := signedAlertBytes(t, s.config, models.AlertTypeInformational, 3)

		require.ErrorIs(t, s.handleAlert(context.Background(), "topic", raw, from), ErrPriorAlertMissing)
		require.Equal(t, 1, countAlerts(t, s.config), "only genesis should be stored")
	})

	t.Run("an alert with bad signatures is rejected", func(t *testing.T) {
		s := newTestServer(t)
		raw := signedAlertBytes(t, s.config, models.AlertTypeInformational, 1)
		raw[len(raw)-1] ^= 0xff

		require.ErrorIs(t, s.handleAlert(context.Background(), "topic", raw, from), ErrInvalidAlerts)
		require.Equal(t, 1, countAlerts(t, s.config), "only genesis should be stored")
	})

	t.Run("a validly signed alert of an unknown type is stored unprocessed", func(t *testing.T) {
		s := newTestServer(t)
		raw := signedAlertBytes(t, s.config, models.AlertType(99), 1)

		require.NoError(t, s.handleAlert(context.Background(), "topic", raw, from))

		saved, err := models.GetAlertMessageBySequenceNumber(context.Background(), 1, model.WithAllDependencies(s.config))
		require.NoError(t, err)
		require.False(t, saved.Processed)
	})

	t.Run("unparseable bytes are rejected", func(t *testing.T) {
		s := newTestServer(t)
		require.ErrorIs(t, s.handleAlert(context.Background(), "topic", []byte{0x01, 0x02}, from), models.ErrAlertTooShort)
	})
}

// TestServer_processAlerts covers the retry cron for unprocessed alerts
func TestServer_processAlerts(t *testing.T) {
	t.Run("an alert that cannot be read does not stop later alerts from being retried", func(t *testing.T) {
		s := newTestServer(t)

		bad := signedAlertBytesWithMessage(t, s.config, models.AlertTypeSetKeys, 1, duplicateKeySetKeysPayload(t))
		badAlert, err := models.NewAlertFromBytes(bad, model.WithAllDependencies(s.config), model.New())
		require.NoError(t, err)
		require.NoError(t, badAlert.Save(context.Background()))

		good := signedAlertBytes(t, s.config, models.AlertTypeInformational, 2)
		goodAlert, err := models.NewAlertFromBytes(good, model.WithAllDependencies(s.config), model.New())
		require.NoError(t, err)
		require.NoError(t, goodAlert.Save(context.Background()))

		require.NoError(t, s.processAlerts(context.Background()))

		saved, err := models.GetAlertMessageBySequenceNumber(context.Background(), 2, model.WithAllDependencies(s.config))
		require.NoError(t, err)
		require.True(t, saved.Processed, "the readable alert after the bad one must be processed")

		saved, err = models.GetAlertMessageBySequenceNumber(context.Background(), 1, model.WithAllDependencies(s.config))
		require.NoError(t, err)
		require.False(t, saved.Processed)
	})
}
