// Package fga wraps openfga/go-sdk with the tiny bit of ergonomics we
// need: loading the DSL model, constructing a client from env config,
// and surfacing idiomatic errors.
//
// Kept deliberately thin: almost all real work happens in the SDK.
// This package holds the adapters between "our Go types + env vars"
// and "SDK method calls." The outbox worker (cmd/outbox-worker) and
// the admin CLI (`idp fga init`) both use this package.
package fga

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	openfga "github.com/openfga/go-sdk"
	"github.com/openfga/go-sdk/client"
	"github.com/openfga/go-sdk/credentials"
	"github.com/openfga/language/pkg/go/transformer"
)

// Config is the minimal set of fields needed to build a client. Fields
// come from env vars (OPENFGA_API_URL, OPENFGA_STORE_ID, OPENFGA_AUTHORIZATION_MODEL_ID).
// StoreID + AuthorizationModelID are optional at Client construction time
// — `idp fga init` builds a client without a StoreID (to create one),
// and other callers pass it through after that.
type Config struct {
	APIURL               string
	StoreID              string // empty at bootstrap
	AuthorizationModelID string // empty at bootstrap

	// APIToken is optional. Local OpenFGA runs without auth; hosted
	// Auth0 FGA or secured OpenFGA deployments use this as a bearer token.
	APIToken string
}

// NewClient builds an OpenFGA SDK client from Config. Used by the worker,
// the init CLI, and (later) demo-api.
func NewClient(cfg Config) (*client.OpenFgaClient, error) {
	clientCfg := client.ClientConfiguration{
		ApiUrl:               cfg.APIURL,
		StoreId:              cfg.StoreID,
		AuthorizationModelId: cfg.AuthorizationModelID,
	}
	if cfg.APIToken != "" {
		clientCfg.Credentials = &credentials.Credentials{
			Method: credentials.CredentialsMethodApiToken,
			Config: &credentials.Config{ApiToken: cfg.APIToken},
		}
	}

	c, err := client.NewSdkClient(&clientCfg)
	if err != nil {
		return nil, fmt.Errorf("openfga: build client: %w", err)
	}
	return c, nil
}

// CreateStore creates a new store with the given name. Used ONCE at
// first setup (via `idp fga init`); subsequent runs reuse the printed
// store ID via the OPENFGA_STORE_ID env var.
//
// Returns the store ID.
func CreateStore(ctx context.Context, c *client.OpenFgaClient, name string) (string, error) {
	resp, err := c.CreateStore(ctx).
		Body(client.ClientCreateStoreRequest{Name: name}).
		Execute()
	if err != nil {
		return "", fmt.Errorf("openfga: create store: %w", err)
	}
	return resp.Id, nil
}

// UploadModelFromDSL parses a DSL model (string contents of a .fga file)
// and uploads it as a new authorization model. Returns the model ID.
//
// `idp fga init` calls this after CreateStore. Subsequent model changes
// would be a separate `idp fga update-model` workflow (not implemented;
// updating a model creates a new version, old tuples still work against
// it because FGA preserves backward-compatible model edits).
func UploadModelFromDSL(ctx context.Context, c *client.OpenFgaClient, dsl string) (string, error) {
	jsonModel, err := transformer.TransformDSLToJSON(dsl)
	if err != nil {
		return "", fmt.Errorf("parse DSL: %w", err)
	}

	var body openfga.WriteAuthorizationModelRequest
	if err := json.Unmarshal([]byte(jsonModel), &body); err != nil {
		return "", fmt.Errorf("unmarshal DSL json: %w", err)
	}

	resp, err := c.WriteAuthorizationModel(ctx).Body(body).Execute()
	if err != nil {
		return "", fmt.Errorf("openfga: write authorization model: %w", err)
	}
	return resp.AuthorizationModelId, nil
}

// WriteTuples writes a batch of tuples. `openfga/go-sdk` supports Writes
// and Deletes in a single atomic call via the Write API; the outbox
// worker splits a batch by kind and calls WriteAndDelete.
func WriteTuples(ctx context.Context, c *client.OpenFgaClient, tuples []client.ClientTupleKey) error {
	if len(tuples) == 0 {
		return nil
	}
	_, err := c.Write(ctx).Body(client.ClientWriteRequest{
		Writes: tuples,
	}).Execute()
	if err != nil {
		return fmt.Errorf("openfga: write tuples: %w", err)
	}
	return nil
}

// WriteAndDelete calls the Write API with both Writes and Deletes in a
// single atomic request. Either all operations succeed or all fail.
// The worker uses this to batch a mixed set of outbox events into one
// FGA round-trip.
//
// idempotent=true sets OnDuplicateWrites="ignore" + OnMissingDeletes="ignore",
// so a retried batch that already partly-applied (worker crashed mid-ack)
// won't fail. The outbox guarantees at-least-once delivery; ignoring
// duplicates turns that into effectively-once at the FGA layer.
func WriteAndDelete(ctx context.Context, c *client.OpenFgaClient,
	writes []client.ClientTupleKey,
	deletes []client.ClientTupleKeyWithoutCondition,
	idempotent bool,
) error {
	if len(writes) == 0 && len(deletes) == 0 {
		return nil
	}
	body := client.ClientWriteRequest{}
	if len(writes) > 0 {
		body.Writes = writes
	}
	if len(deletes) > 0 {
		body.Deletes = deletes
	}

	req := c.Write(ctx).Body(body)
	if idempotent {
		req = req.Options(client.ClientWriteOptions{
			Conflict: client.ClientWriteConflictOptions{
				OnDuplicateWrites: client.CLIENT_WRITE_REQUEST_ON_DUPLICATE_WRITES_IGNORE,
				OnMissingDeletes:  client.CLIENT_WRITE_REQUEST_ON_MISSING_DELETES_IGNORE,
			},
		})
	}
	_, err := req.Execute()
	return err
}

// Check is used by demo-api (layer 9) and by tests. Thin wrapper
// returning a simple bool.
func Check(ctx context.Context, c *client.OpenFgaClient, user, relation, object string) (bool, error) {
	resp, err := c.Check(ctx).Body(client.ClientCheckRequest{
		User:     user,
		Relation: relation,
		Object:   object,
	}).Execute()
	if err != nil {
		return false, fmt.Errorf("openfga: check: %w", err)
	}
	if resp.Allowed == nil {
		return false, nil
	}
	return *resp.Allowed, nil
}

// ErrStoreNotConfigured is returned when a caller that needs a
// StoreID builds a client without setting one.
var ErrStoreNotConfigured = errors.New("fga: OPENFGA_STORE_ID not set")

// TupleWithoutCondition strips the optional Condition field from a
// ClientTupleKey. Needed because the Delete API takes
// ClientTupleKeyWithoutCondition (tuples with conditions can't be
// deleted via the same exact-match path).
//
// For our use case (no conditions on tuples) this is a no-op transform,
// but the SDK's type signatures require it.
func TupleWithoutCondition(t client.ClientTupleKey) client.ClientTupleKeyWithoutCondition {
	return client.ClientTupleKeyWithoutCondition{
		User:     t.User,
		Relation: t.Relation,
		Object:   t.Object,
	}
}
