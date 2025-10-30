package main

import "errors"

// Errors for the hack package
var (
	ErrNotImplemented              = errors.New("not implemented")
	ErrThreePrivateKeysNotSupplied = errors.New("3 private keys not supplied")
)
