// Package models is the models for the alert system application
package models

import "github.com/bsv-blockchain/go-alert-system/app/models/model"

// BaseModels is the list of models for loading the engine and AutoMigration (defaults)
var BaseModels = []interface{}{
	// AlertMessage - used for alert messages
	&AlertMessage{
		Model: *model.NewBaseModel(model.NameAlertMessage),
	},

	// PublicKey - used for public keys
	&PublicKey{
		Model: *model.NewBaseModel(model.NamePublicKey),
	},
}
