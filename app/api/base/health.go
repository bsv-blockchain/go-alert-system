package base

import (
	"encoding/json"
	"net/http"

	"github.com/julienschmidt/httprouter"
	apirouter "github.com/mrz1836/go-api-router"

	"github.com/bsv-blockchain/go-alert-system/app"
	"github.com/bsv-blockchain/go-alert-system/app/models"
	"github.com/bsv-blockchain/go-alert-system/app/models/model"
)

// HealthResponse is the response for the health endpoint
type HealthResponse struct {
	Alert             models.AlertMessage `json:"alert"`
	Sequence          uint32              `json:"sequence"`
	Synced            bool                `json:"synced"`
	ActivePeers       int                 `json:"active_peers"`
	UnprocessedAlerts int                 `json:"unprocessed_alerts"`
}

// health will return the health of the API and the current alert
func (a *Action) health(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
	// Get the latest alert
	alert, err := models.GetLatestAlert(req.Context(), nil, model.WithAllDependencies(a.Config))
	if err != nil {
		app.APIErrorResponse(w, req, http.StatusBadRequest, err)
		return
	} else if alert == nil {
		app.APIErrorResponse(w, req, http.StatusNotFound, ErrAlertNotFound)
		return
	}

	failed, _ := models.GetAllUnprocessedAlerts(req.Context(), nil, model.WithAllDependencies(a.Config))

	// Return the response
	_ = apirouter.ReturnJSONEncode(
		w,
		http.StatusOK,
		json.NewEncoder(w),
		HealthResponse{
			Alert:             *alert,
			Sequence:          alert.SequenceNumber,
			ActivePeers:       a.P2pServer.ActivePeers(),
			UnprocessedAlerts: len(failed),
			Synced:            true, // TODO actually fetch this state from the DB somehow, or from the server struct
		}, []string{"alert", "synced", "sequence", "active_peers", "unprocessed_alerts"})
}
