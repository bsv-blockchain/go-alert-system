package models

import (
	"context"

	"github.com/bsv-blockchain/go-alert-system/utils"
)

// TestAlertMessage_Execute covers reading and running an alert in one step
func (ts *TestSuite) TestAlertMessage_Execute() {
	ctx := context.Background()

	ts.Run("informational alert executes", func() {
		alert := ts.newSignedTestAlert([]string{utils.Key1, utils.Key2, utils.Key3})
		ts.Require().NoError(alert.Execute(ctx))
	})

	ts.Run("unknown alert type returns ErrUnknownAlertType", func() {
		alert := ts.newSignedTestAlert([]string{utils.Key1, utils.Key2, utils.Key3})
		alert.SetAlertType(AlertType(99))
		ts.Require().ErrorIs(alert.Execute(ctx), ErrUnknownAlertType)
	})

	ts.Run("payload that fails to read surfaces the read error", func() {
		pubs := ts.testPubKeys()
		pubs[4] = pubs[0]
		alert := ts.newSignedTestAlert([]string{utils.Key1, utils.Key2, utils.Key3})
		alert.SetAlertType(AlertTypeSetKeys)
		alert.SetRawMessage(ts.setKeysPayload(pubs...))
		ts.Require().ErrorIs(alert.Execute(ctx), ErrDuplicatePubKey)
	})
}

// TestAlertMessage_ToJSON_UnknownType ensures ToJSON never panics on an alert with no handler
func (ts *TestSuite) TestAlertMessage_ToJSON_UnknownType() {
	ctx := context.Background()
	wrappers := []AlertMessageInterface{
		&AlertMessageInformational{},
		&AlertMessageFreezeUtxo{},
		&AlertMessageUnfreezeUtxo{},
		&AlertMessageConfiscateTransaction{},
		&AlertMessageBanPeer{},
		&AlertMessageUnbanPeer{},
		&AlertMessageInvalidateBlock{},
		&AlertMessageSetKeys{},
	}
	for _, w := range wrappers {
		ts.Require().NotPanics(func() { _ = w.ToJSON(ctx) })
		ts.Require().Empty(w.ToJSON(ctx))
	}
}
