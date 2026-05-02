package main

// `docs-api grant` — operator-facing CLI for writing FGA tuples that
// authorize a user against a docs-api resource.
//
// Why on docs-api and not on the IdP: the vocabulary (owner/editor/viewer
// on folder/document) is docs-api's. The IdP shouldn't know what a
// "viewer-on-engineering" means. Service boundary is the seam; the
// operator pastes the user UUID across (from `idp users list`).
//
//   docs-api grant <user-uuid> <role> <resource>
//
// Examples:
//   docs-api grant 9bbc7a34-... viewer folder:11111111-1111-1111-1111-000000000003
//   docs-api grant 9bbc7a34-... editor folder:11111111-1111-1111-1111-000000000001
//   docs-api grant 9bbc7a34-... owner  document:22222222-2222-2222-2222-000000000005

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	openfgaclient "github.com/openfga/go-sdk/client"

	"github.com/mhockenbury/identity-provider/internal/fga"
)

func runGrant(args []string) error {
	if len(args) < 3 {
		return fmt.Errorf("grant: need <user-uuid> <role> <resource>")
	}
	userUUID := args[0]
	role := strings.ToLower(args[1])
	resource := args[2]

	// Validate role against the vocabulary docs-api enforces in handlers.
	switch role {
	case fga.RelOwner, fga.RelEditor, fga.RelViewer:
	default:
		return fmt.Errorf("grant: role must be one of owner|editor|viewer; got %q", role)
	}

	// Validate resource shape: type:<uuid> with type ∈ {folder, document}.
	parts := strings.SplitN(resource, ":", 2)
	if len(parts) != 2 || parts[1] == "" {
		return fmt.Errorf("grant: resource must be type:<uuid> (e.g. folder:11111111-...); got %q", resource)
	}
	switch parts[0] {
	case "folder", "document":
	default:
		return fmt.Errorf("grant: resource type must be folder or document; got %q", parts[0])
	}

	// Owners are only meaningful on documents in our model.
	if role == fga.RelOwner && parts[0] != "document" {
		return fmt.Errorf("grant: owner role applies to documents only")
	}

	// FGA env required (same as `serve`). We don't need the docs DB or
	// JWKS for a grant; just the FGA client.
	cfg := fga.Config{
		APIURL:               envOr("OPENFGA_API_URL", "http://localhost:8081"),
		StoreID:              os.Getenv("OPENFGA_STORE_ID"),
		AuthorizationModelID: os.Getenv("OPENFGA_AUTHORIZATION_MODEL_ID"),
		APIToken:             os.Getenv("OPENFGA_API_TOKEN"),
	}
	if cfg.StoreID == "" || cfg.AuthorizationModelID == "" {
		return fmt.Errorf("grant: OPENFGA_STORE_ID and OPENFGA_AUTHORIZATION_MODEL_ID are required (run: idp fga init)")
	}

	client, err := fga.NewClient(cfg)
	if err != nil {
		return fmt.Errorf("grant: build fga client: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tuple := openfgaclient.ClientTupleKey{
		User:     fga.TypeUser + userUUID,
		Relation: role,
		Object:   resource,
	}
	if err := fga.WriteAndDelete(ctx, client, []openfgaclient.ClientTupleKey{tuple}, nil, true); err != nil {
		return fmt.Errorf("grant: write tuple: %w", err)
	}
	fmt.Printf("granted: user:%s %s %s\n", userUUID, role, resource)
	return nil
}
