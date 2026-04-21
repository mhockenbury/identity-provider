// Package fga wraps the OpenFGA HTTP API + translates outbox event types
// into tuple writes. The IdP uses this only via the outbox worker;
// demo-api uses it directly for Check calls.
package fga
