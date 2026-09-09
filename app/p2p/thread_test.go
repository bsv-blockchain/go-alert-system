package p2p

import (
	"bytes"
	"context"
	"testing"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-alert-system/app/config"
	"github.com/bsv-blockchain/go-alert-system/app/models"
	"github.com/bsv-blockchain/go-alert-system/app/models/model"
	"github.com/bsv-blockchain/go-alert-system/utils"
)

// fakeStream records what the thread writes to the peer and whether it closed the stream.
// Every other network.Stream method is left unimplemented and panics if called.
type fakeStream struct {
	network.Stream

	written bytes.Buffer
	closed  bool
}

// Write records the bytes the thread sends to the peer
func (f *fakeStream) Write(p []byte) (int, error) {
	return f.written.Write(p)
}

// Close records that the thread closed the stream
func (f *fakeStream) Close() error {
	f.closed = true
	return nil
}

// loadTestDependencies loads the test configuration and stores the genesis alert
// (sequence 0), which activates the test genesis keys: the public keys of
// utils.Key1 to utils.Key5
func loadTestDependencies(t *testing.T) *config.Config {
	t.Helper()
	ctx := context.Background()
	t.Setenv(config.EnvironmentKey, config.EnvironmentTest)

	deps, err := config.LoadDependencies(ctx, models.BaseModels, true)
	require.NoError(t, err)
	t.Cleanup(func() { deps.CloseAll(ctx) })

	require.NoError(t, models.CreateGenesisAlert(ctx, model.WithAllDependencies(deps)))
	return deps
}

// signedAlertBytes builds a fully signed raw informational style alert of the given type and sequence
func signedAlertBytes(t *testing.T, deps *config.Config, alertType models.AlertType, sequence uint32) []byte {
	t.Helper()
	return signedAlertBytesWithMessage(t, deps, alertType, sequence, []byte{0x05, 'h', 'e', 'l', 'l', 'o'})
}

// signedAlertBytesWithMessage builds a fully signed raw alert with the given payload
func signedAlertBytesWithMessage(
	t *testing.T, deps *config.Config, alertType models.AlertType, sequence uint32, message []byte,
) []byte {
	t.Helper()
	alert := models.NewAlertMessage(model.WithAllDependencies(deps), model.New())
	alert.SetAlertType(alertType)
	alert.SetVersion(1)
	alert.SetTimestamp(1)
	alert.SequenceNumber = sequence
	alert.SetRawMessage(message)
	alert.SerializeData()

	sigs, err := utils.SignWithKeys(alert.GetRawData(), []string{utils.Key1, utils.Key2, utils.Key3})
	require.NoError(t, err)
	alert.SetSignatures(sigs)
	return alert.Serialize()
}

// storeAlert saves a raw alert as if it had already been synced
func storeAlert(t *testing.T, deps *config.Config, raw []byte) {
	t.Helper()
	alert, err := models.NewAlertFromBytes(raw, model.WithAllDependencies(deps), model.New())
	require.NoError(t, err)
	alert.Processed = true
	require.NoError(t, alert.Save(context.Background()))
}

// countAlerts returns the number of alerts stored in the datastore
func countAlerts(t *testing.T, deps *config.Config) int {
	t.Helper()
	alerts, err := models.GetAllAlerts(context.Background(), nil, model.WithAllDependencies(deps))
	require.NoError(t, err)
	return len(alerts)
}

// TestStreamThread_ProcessGotSequenceNumber covers validation of alerts received during sync
func TestStreamThread_ProcessGotSequenceNumber(t *testing.T) {
	t.Run("alert with an unexpected sequence number is rejected", func(t *testing.T) {
		deps := loadTestDependencies(t)
		thread := &StreamThread{config: deps, ctx: context.Background(), myLatestSequence: 0, latestSequence: 10}

		msg := &SyncMessage{
			Type:           IGotSequenceNumber,
			SequenceNumber: 7,
			Data:           signedAlertBytes(t, deps, models.AlertTypeInformational, 7),
		}
		require.ErrorIs(t, thread.ProcessGotSequenceNumber(msg), ErrUnexpectedSequenceNumber)
		require.Equal(t, uint32(0), thread.myLatestSequence)
	})

	t.Run("validly signed alert of an unknown type is stored unprocessed and the chain advances", func(t *testing.T) {
		deps := loadTestDependencies(t)
		stream := &fakeStream{}
		thread := &StreamThread{config: deps, ctx: context.Background(), stream: stream, latestSequence: 1}

		msg := &SyncMessage{
			Type:           IGotSequenceNumber,
			SequenceNumber: 1,
			Data:           signedAlertBytes(t, deps, models.AlertType(99), 1),
		}
		require.NoError(t, thread.ProcessGotSequenceNumber(msg))
		require.Equal(t, uint32(1), thread.myLatestSequence)

		saved, err := models.GetAlertMessageBySequenceNumber(context.Background(), 1, model.WithAllDependencies(deps))
		require.NoError(t, err)
		require.False(t, saved.Processed, "an alert with no handler must be kept for a later retry")
	})

	t.Run("replay of an alert already in the datastore is rejected on an inbound stream", func(t *testing.T) {
		deps := loadTestDependencies(t)
		raw := signedAlertBytes(t, deps, models.AlertTypeInformational, 1)
		storeAlert(t, deps, raw)
		stored := countAlerts(t, deps)

		// The inbound stream handler never learns the local latest sequence, so a
		// thread it creates starts at zero. An unsolicited IGotSequenceNumber carrying
		// the historical sequence 1 must still be rejected against what is stored.
		stream := &fakeStream{}
		thread := &StreamThread{config: deps, ctx: context.Background(), stream: stream}

		msg := &SyncMessage{Type: IGotSequenceNumber, SequenceNumber: 1, Data: raw}
		require.ErrorIs(t, thread.ProcessGotSequenceNumber(msg), ErrUnexpectedSequenceNumber)
		require.Equal(t, stored, countAlerts(t, deps), "replayed alert must not be stored again")
		require.False(t, stream.closed)
		require.Zero(t, stream.written.Len(), "no follow up request should be sent to the peer")
	})

	t.Run("the next sequence is accepted, stored and the stream is closed when synced", func(t *testing.T) {
		deps := loadTestDependencies(t)
		stream := &fakeStream{}
		thread := &StreamThread{config: deps, ctx: context.Background(), stream: stream, latestSequence: 1}

		msg := &SyncMessage{
			Type:           IGotSequenceNumber,
			SequenceNumber: 1,
			Data:           signedAlertBytes(t, deps, models.AlertTypeInformational, 1),
		}
		require.NoError(t, thread.ProcessGotSequenceNumber(msg))
		require.Equal(t, uint32(1), thread.myLatestSequence)
		require.True(t, stream.closed)

		saved, err := models.GetAlertMessageBySequenceNumber(context.Background(), 1, model.WithAllDependencies(deps))
		require.NoError(t, err)
		require.True(t, saved.Processed)
	})
}
