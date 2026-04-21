// Package outbox writes to the fga_outbox table. Handlers that mutate
// identity state call EnqueueEvent(tx, event) inside their transaction;
// the worker in cmd/outbox-worker drains asynchronously.
package outbox
