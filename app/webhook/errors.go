package webhook

import "errors"

// Errors for the webhook package
var (
	ErrWebhookURLNotConfigured  = errors.New("webhook URL is not configured")
	ErrWebhookURLInvalidPrefix  = errors.New("webhook URL does not have a valid prefix")
	ErrWebhookUnexpectedStatus  = errors.New("unexpected status code sending payload to webhook")
	ErrWebhookMockUnimplemented = errors.New("unimplemented")
)
