package main

// HTTP handlers for docs-api.
//
// All routes below sit INSIDE the authenticate middleware group, so
// every handler can assume claimsFromCtx(r.Context()) returns non-nil.
// Scope middleware (requireScope) layers on top per-method.
//
// The FGA check pattern is uniform:
//
//	user := userFromClaims(claims)            // "user:<sub-uuid>"
//	ok, err := deps.fga.Check(ctx, user, rel, obj)
//	if err  → 502
//	if !ok  → 403
//
// 502 rather than 500 on FGA errors because FGA is an upstream service
// from our perspective: the failure is external.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	openfgaclient "github.com/openfga/go-sdk/client"

	"github.com/mhockenbury/identity-provider/internal/fga"
	"github.com/mhockenbury/identity-provider/internal/tokens"
)

// handlerDeps is what every resource handler needs. A superset of
// routerDeps — adds Store and the raw FGA client (so POST /docs can
// write the owner tuple). Built in main.go.
type handlerDeps struct {
	store        *Store
	fga          fgaChecker
	fgaRawClient *openfgaclient.OpenFgaClient // for tuple writes from POST/DELETE
}

// docResponse is the enriched JSON shape returned to clients. Wraps
// Document with the caller's permission tier on that doc so the SPA
// can show/hide Edit + Delete buttons without a round trip.
//
// Permission is one of: "owner" | "editor" | "viewer". Computed via
// up-to-3 FGA Checks per doc, most-privileged-first for early-out.
type docResponse struct {
	Document
	Permission string `json:"permission"`
}

type folderResponse struct {
	Folder
	Permission string `json:"permission"`
}

// resolvePermission returns the highest tier the user has on an object,
// or "" if none. Short-circuits on the first positive check — so a user
// who's owner only pays 1 FGA Check round-trip, not 3.
func (h handlerDeps) resolvePermission(r *http.Request, user, objectType, objectID string) (string, error) {
	obj := objectType + ":" + objectID
	for _, rel := range []string{"owner", "editor", "viewer"} {
		ok, err := h.fga.Check(r.Context(), user, rel, obj)
		if err != nil {
			return "", err
		}
		if ok {
			return rel, nil
		}
	}
	return "", nil
}

// registerResourceRoutes mounts the doc + folder handlers. Called from
// newRouter inside the authenticated group.
func registerResourceRoutes(r chi.Router, h handlerDeps) {
	// Reads — require read:docs.
	r.With(requireScope("read:docs")).Get("/docs", h.listDocs)
	r.With(requireScope("read:docs")).Get("/docs/{id}", h.getDoc)
	r.With(requireScope("read:docs")).Get("/folders", h.listFolders)
	r.With(requireScope("read:docs")).Get("/folders/{id}", h.getFolder)
	r.With(requireScope("read:docs")).Get("/folders/{id}/docs", h.listFolderDocs)

	// Writes — require write:docs.
	r.With(requireScope("write:docs")).Post("/docs", h.createDoc)
	r.With(requireScope("write:docs")).Patch("/docs/{id}", h.updateDoc)
	r.With(requireScope("write:docs")).Delete("/docs/{id}", h.deleteDoc)
}

// --- handlers ---

// listDocs returns every doc the caller can view, enriched with the
// caller's permission tier on each. O(N × up-to-3) FGA checks;
// fine for seed-scale. Real production would use OpenFGA's ListObjects
// to filter at the authz tier first, then batch-Check for tiers.
func (h handlerDeps) listDocs(w http.ResponseWriter, r *http.Request) {
	user := userFromClaims(claimsFromCtx(r.Context()))
	all := h.store.ListDocs()
	visible := make([]docResponse, 0, len(all))
	for _, d := range all {
		perm, err := h.resolvePermission(r, user, "document", d.ID)
		if err != nil {
			writeError(w, http.StatusBadGateway, "authz_backend", err.Error())
			return
		}
		if perm == "" {
			continue
		}
		visible = append(visible, docResponse{Document: d, Permission: perm})
	}
	writeJSON(w, http.StatusOK, map[string]any{"docs": visible})
}

// getDoc returns one doc if the caller has viewer on it, enriched with
// the caller's permission tier. 404 before 403: leaking "this doc
// exists but you can't see it" is worse than "this doc doesn't exist."
func (h handlerDeps) getDoc(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	doc, ok := h.store.GetDoc(id)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "document not found")
		return
	}
	user := userFromClaims(claimsFromCtx(r.Context()))
	perm, err := h.resolvePermission(r, user, "document", id)
	if err != nil {
		writeError(w, http.StatusBadGateway, "authz_backend", err.Error())
		return
	}
	if perm == "" {
		// Intentionally 404 — "no such doc from your perspective."
		writeError(w, http.StatusNotFound, "not_found", "document not found")
		return
	}
	writeJSON(w, http.StatusOK, docResponse{Document: doc, Permission: perm})
}

// listFolders returns every folder the caller can view, with their
// permission tier on each. Used by the SPA's sidebar.
func (h handlerDeps) listFolders(w http.ResponseWriter, r *http.Request) {
	user := userFromClaims(claimsFromCtx(r.Context()))
	all := h.store.ListFolders()
	visible := make([]folderResponse, 0, len(all))
	for _, f := range all {
		perm, err := h.resolvePermission(r, user, "folder", f.ID)
		if err != nil {
			writeError(w, http.StatusBadGateway, "authz_backend", err.Error())
			return
		}
		if perm == "" {
			continue
		}
		visible = append(visible, folderResponse{Folder: f, Permission: perm})
	}
	writeJSON(w, http.StatusOK, map[string]any{"folders": visible})
}

// getFolder: viewer on the folder, response enriched with tier.
func (h handlerDeps) getFolder(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	f, ok := h.store.GetFolder(id)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "folder not found")
		return
	}
	user := userFromClaims(claimsFromCtx(r.Context()))
	perm, err := h.resolvePermission(r, user, "folder", id)
	if err != nil {
		writeError(w, http.StatusBadGateway, "authz_backend", err.Error())
		return
	}
	if perm == "" {
		writeError(w, http.StatusNotFound, "not_found", "folder not found")
		return
	}
	writeJSON(w, http.StatusOK, folderResponse{Folder: f, Permission: perm})
}

// listFolderDocs: viewer on the folder AND per-doc permission check
// (a user viewer on the folder but not on some specific doc —
// possible with tighter-than-inherited explicit rules — shouldn't see it).
// Each returned doc carries its own permission tier.
func (h handlerDeps) listFolderDocs(w http.ResponseWriter, r *http.Request) {
	folderID := chi.URLParam(r, "id")
	if _, ok := h.store.GetFolder(folderID); !ok {
		writeError(w, http.StatusNotFound, "not_found", "folder not found")
		return
	}
	user := userFromClaims(claimsFromCtx(r.Context()))

	folderPerm, err := h.resolvePermission(r, user, "folder", folderID)
	if err != nil {
		writeError(w, http.StatusBadGateway, "authz_backend", err.Error())
		return
	}
	if folderPerm == "" {
		writeError(w, http.StatusNotFound, "not_found", "folder not found")
		return
	}

	docs := h.store.ListFolderDocs(folderID)
	visible := make([]docResponse, 0, len(docs))
	for _, d := range docs {
		perm, err := h.resolvePermission(r, user, "document", d.ID)
		if err != nil {
			writeError(w, http.StatusBadGateway, "authz_backend", err.Error())
			return
		}
		if perm == "" {
			continue
		}
		visible = append(visible, docResponse{Document: d, Permission: perm})
	}
	writeJSON(w, http.StatusOK, map[string]any{"docs": visible})
}

// createDoc: any authenticated user with write:docs can create. On
// success we write two tuples to FGA:
//   - user:<sub> owner document:<new-id>
//   - folder:<parent> parent document:<new-id>  (if FolderID supplied)
//
// No outbox — docs live only in memory; no identity row to atomically
// pair with.
func (h handlerDeps) createDoc(w http.ResponseWriter, r *http.Request) {
	var req struct {
		FolderID string `json:"folder_id"`
		Title    string `json:"title"`
		Body     string `json:"body"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "malformed JSON")
		return
	}
	if req.Title == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "title required")
		return
	}
	// Folder existence + viewer check: you can only create a doc inside
	// a folder you can view.
	user := userFromClaims(claimsFromCtx(r.Context()))
	if req.FolderID != "" {
		if _, ok := h.store.GetFolder(req.FolderID); !ok {
			writeError(w, http.StatusBadRequest, "bad_request", "folder not found")
			return
		}
		allowed, err := h.fga.Check(r.Context(), user, "viewer", "folder:"+req.FolderID)
		if err != nil {
			writeError(w, http.StatusBadGateway, "authz_backend", err.Error())
			return
		}
		if !allowed {
			writeError(w, http.StatusForbidden, "forbidden", "no viewer access on folder")
			return
		}
	}

	// Strip "user:" prefix for OwnerSub — we store the sub itself.
	sub := claimsFromCtx(r.Context()).Subject
	doc := h.store.CreateDocument(req.FolderID, req.Title, req.Body, sub)

	tuples := []openfgaclient.ClientTupleKey{
		{User: user, Relation: "owner", Object: "document:" + doc.ID},
	}
	if req.FolderID != "" {
		tuples = append(tuples, openfgaclient.ClientTupleKey{
			User: "folder:" + req.FolderID, Relation: "parent", Object: "document:" + doc.ID,
		})
	}
	if err := fga.WriteAndDelete(r.Context(), h.fgaRawClient, tuples, nil, true); err != nil {
		// Doc is already in the store — we have a small window of
		// inconsistency. For the lab that's acceptable; in production
		// you'd roll back the in-memory insert or retry. Log + report.
		writeError(w, http.StatusBadGateway, "authz_backend", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, doc)
}

// updateDoc: editor on the doc.
func (h handlerDeps) updateDoc(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, ok := h.store.GetDoc(id); !ok {
		writeError(w, http.StatusNotFound, "not_found", "document not found")
		return
	}
	user := userFromClaims(claimsFromCtx(r.Context()))
	allowed, err := h.fga.Check(r.Context(), user, "editor", "document:"+id)
	if err != nil {
		writeError(w, http.StatusBadGateway, "authz_backend", err.Error())
		return
	}
	if !allowed {
		writeError(w, http.StatusForbidden, "forbidden", "editor access required")
		return
	}

	var req struct {
		Title string `json:"title"`
		Body  string `json:"body"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "malformed JSON")
		return
	}
	doc, err := h.store.UpdateDocument(id, req.Title, req.Body)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "document not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, doc)
}

// deleteDoc: owner only. Also removes the owner tuple from FGA.
func (h handlerDeps) deleteDoc(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, ok := h.store.GetDoc(id); !ok {
		writeError(w, http.StatusNotFound, "not_found", "document not found")
		return
	}
	user := userFromClaims(claimsFromCtx(r.Context()))
	allowed, err := h.fga.Check(r.Context(), user, "owner", "document:"+id)
	if err != nil {
		writeError(w, http.StatusBadGateway, "authz_backend", err.Error())
		return
	}
	if !allowed {
		writeError(w, http.StatusForbidden, "forbidden", "owner access required")
		return
	}

	if err := h.store.DeleteDocument(id); err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	// Best-effort tuple cleanup. OnMissingDeletes=ignore absorbs the
	// "nothing to delete" case if something's already diverged.
	deletes := []openfgaclient.ClientTupleKeyWithoutCondition{
		{User: user, Relation: "owner", Object: "document:" + id},
	}
	if err := fga.WriteAndDelete(r.Context(), h.fgaRawClient, nil, deletes, true); err != nil {
		// Doc is already deleted from the store; log but don't fail.
		// The tuple will become a dangling harmless entry.
		writeError(w, http.StatusOK, "partial_success",
			fmt.Sprintf("document deleted but FGA cleanup failed: %v", err))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- helpers ---

// userFromClaims formats an FGA user identifier from a token's sub.
// FGA expects "user:<id>"; sub is the bare UUID.
func userFromClaims(c *tokens.AccessClaims) string {
	if c == nil {
		return ""
	}
	return "user:" + c.Subject
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{
		"error":             code,
		"error_description": desc,
	})
}

// unused silences "imported but not used" on context if a handler gets
// deleted during edits; harmless to keep.
var _ = context.TODO
