package webhook

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bsv-blockchain/go-alert-system/app/models"
)

// TestPostAlert_UnknownAlertType ensures an alert with no handler returns an error instead of panicking
func TestPostAlert_UnknownAlertType(t *testing.T) {
	alert := models.NewAlertMessage()
	alert.SetAlertType(models.AlertType(99))

	err := PostAlert(context.Background(), nil, "https://example.invalid/hook", alert)
	require.ErrorIs(t, err, models.ErrUnknownAlertType)
}
