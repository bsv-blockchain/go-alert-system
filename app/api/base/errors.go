package base

import "errors"

// Static errors for the base API package
var (
	ErrAlertNotFound     = errors.New("alert not found")
	ErrAlertFailed       = errors.New("alert failed")
	ErrAlertNotValidType = errors.New("alert not valid type")
)
