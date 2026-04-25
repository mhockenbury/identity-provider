package admin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mhockenbury/identity-provider/internal/outbox"
	"github.com/mhockenbury/identity-provider/internal/users"
)

// Deps is the dependency bag the admin handlers need. Concrete types
// (not interfaces) for the stores — these are pinned dependencies, not
// pluggable points. Tests stub the underlying DB via the same patterns
// used elsewhere in the repo.
type Deps struct {
	Pool   *pgxpool.Pool
	Users  users.Store
	Groups *users.GroupStore
}

// MaxAttempts is the worker's poison-pill threshold. Mirrored here so
// the admin API's "is this row failed?" check matches the worker's
// "will I claim this row?" decision. Hardcoded rather than env-driven
// so the API isn't fooled by an OUTBOX_MAX_ATTEMPTS misconfig.
const MaxAttempts = 5

// Handler returns a chi.Router that mounts at /admin/api. Caller wraps
// it in the auth middleware (Authenticate) and CORS.
func Handler(d Deps) http.Handler {
	r := chi.NewRouter()

	r.Get("/users", listUsers(d))
	r.Post("/users", createUser(d))
	r.Post("/users/{id}/promote", promoteUser(d))
	r.Post("/users/{id}/demote", demoteUser(d))

	r.Get("/groups", listGroups(d))
	r.Post("/groups", createGroup(d))
	r.Get("/groups/{name}/members", listGroupMembers(d))
	r.Post("/groups/{name}/members", addGroupMember(d))
	r.Delete("/groups/{name}/members/{user_id}", removeGroupMember(d))

	r.Get("/outbox", listOutbox(d))
	r.Post("/outbox/{id}/retry", retryOutbox(d))
	r.Delete("/outbox/{id}", purgeOutbox(d))

	return r
}

// --- users ---

type userView struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	IsAdmin   bool   `json:"is_admin"`
	CreatedAt string `json:"created_at"`
}

func toUserView(u users.User) userView {
	return userView{
		ID:        u.ID.String(),
		Email:     u.Email,
		IsAdmin:   u.IsAdmin,
		CreatedAt: u.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
	}
}

func listUsers(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		all, err := d.Users.List(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "server_error", err.Error())
			return
		}
		out := make([]userView, 0, len(all))
		for _, u := range all {
			out = append(out, toUserView(u))
		}
		writeJSON(w, http.StatusOK, map[string]any{"users": out})
	}
}

func createUser(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", "malformed JSON")
			return
		}
		u, err := d.Users.Create(r.Context(), req.Email, req.Password)
		if err != nil {
			switch {
			case errors.Is(err, users.ErrEmailTaken):
				writeError(w, http.StatusConflict, "email_taken", "email already in use")
			case errors.Is(err, users.ErrInvalidEmail):
				writeError(w, http.StatusBadRequest, "invalid_email", err.Error())
			default:
				writeError(w, http.StatusInternalServerError, "server_error", err.Error())
			}
			return
		}
		writeJSON(w, http.StatusCreated, toUserView(u))
	}
}

func promoteUser(d Deps) http.HandlerFunc { return setAdminFlag(d, true) }
func demoteUser(d Deps) http.HandlerFunc  { return setAdminFlag(d, false) }

func setAdminFlag(d Deps, isAdmin bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := uuid.Parse(chi.URLParam(r, "id"))
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", "id must be UUID")
			return
		}
		if err := d.Users.SetAdmin(r.Context(), id, isAdmin); err != nil {
			if errors.Is(err, users.ErrNotFound) {
				writeError(w, http.StatusNotFound, "not_found", "user not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "server_error", err.Error())
			return
		}
		// Echo back the updated user so the caller sees the new flag.
		u, err := d.Users.GetByID(r.Context(), id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "server_error", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, toUserView(u))
	}
}

// --- groups ---

type groupView struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func listGroups(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		all, err := d.Groups.List(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "server_error", err.Error())
			return
		}
		out := make([]groupView, 0, len(all))
		for _, g := range all {
			out = append(out, groupView{ID: g.ID.String(), Name: g.Name})
		}
		writeJSON(w, http.StatusOK, map[string]any{"groups": out})
	}
}

func createGroup(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", "malformed JSON")
			return
		}
		g, err := d.Groups.Create(r.Context(), req.Name)
		if err != nil {
			if errors.Is(err, users.ErrGroupNameTaken) {
				writeError(w, http.StatusConflict, "name_taken", err.Error())
				return
			}
			writeError(w, http.StatusInternalServerError, "server_error", err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, groupView{ID: g.ID.String(), Name: g.Name})
	}
}

func listGroupMembers(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		g, err := d.Groups.GetByName(r.Context(), name)
		if err != nil {
			if errors.Is(err, users.ErrGroupNotFound) {
				writeError(w, http.StatusNotFound, "not_found", "group not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "server_error", err.Error())
			return
		}
		members, err := d.Groups.ListMembers(r.Context(), g.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "server_error", err.Error())
			return
		}
		out := make([]userView, 0, len(members))
		for _, u := range members {
			out = append(out, toUserView(u))
		}
		writeJSON(w, http.StatusOK, map[string]any{"members": out})
	}
}

func addGroupMember(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		var req struct {
			UserID    string `json:"user_id"`    // either user_id …
			UserEmail string `json:"user_email"` // … or user_email
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", "malformed JSON")
			return
		}
		if req.UserID == "" && req.UserEmail == "" {
			writeError(w, http.StatusBadRequest, "bad_request", "need user_id or user_email")
			return
		}

		g, err := d.Groups.GetByName(r.Context(), name)
		if err != nil {
			if errors.Is(err, users.ErrGroupNotFound) {
				writeError(w, http.StatusNotFound, "not_found", "group not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "server_error", err.Error())
			return
		}

		var u users.User
		if req.UserID != "" {
			id, perr := uuid.Parse(req.UserID)
			if perr != nil {
				writeError(w, http.StatusBadRequest, "bad_request", "user_id must be UUID")
				return
			}
			u, err = d.Users.GetByID(r.Context(), id)
		} else {
			u, err = d.Users.GetByEmail(r.Context(), req.UserEmail)
		}
		if err != nil {
			if errors.Is(err, users.ErrNotFound) {
				writeError(w, http.StatusNotFound, "not_found", "user not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "server_error", err.Error())
			return
		}

		// THE atomic write: membership row + outbox row in the same tx.
		// Same pattern as the CLI's `idp groups add-member`.
		tx, err := d.Pool.Begin(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "server_error", err.Error())
			return
		}
		defer func() { _ = tx.Rollback(r.Context()) }()

		if err := d.Groups.AddMemberTx(r.Context(), tx, u.ID, g.ID); err != nil {
			if errors.Is(err, users.ErrMembershipExists) {
				writeError(w, http.StatusConflict, "already_member", "user is already a member")
				return
			}
			writeError(w, http.StatusInternalServerError, "server_error", err.Error())
			return
		}
		event := outbox.GroupMembershipAdded{UserID: u.ID, GroupID: g.ID}
		if err := outbox.Enqueue(r.Context(), tx, event); err != nil {
			writeError(w, http.StatusInternalServerError, "server_error", err.Error())
			return
		}
		if err := tx.Commit(r.Context()); err != nil {
			writeError(w, http.StatusInternalServerError, "server_error", err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, toUserView(u))
	}
}

func removeGroupMember(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := chi.URLParam(r, "name")
		userIDStr := chi.URLParam(r, "user_id")
		userID, err := uuid.Parse(userIDStr)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", "user_id must be UUID")
			return
		}
		g, err := d.Groups.GetByName(r.Context(), name)
		if err != nil {
			if errors.Is(err, users.ErrGroupNotFound) {
				writeError(w, http.StatusNotFound, "not_found", "group not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "server_error", err.Error())
			return
		}

		tx, err := d.Pool.Begin(r.Context())
		if err != nil {
			writeError(w, http.StatusInternalServerError, "server_error", err.Error())
			return
		}
		defer func() { _ = tx.Rollback(r.Context()) }()

		if err := d.Groups.RemoveMemberTx(r.Context(), tx, userID, g.ID); err != nil {
			if errors.Is(err, users.ErrMembershipNotFound) {
				writeError(w, http.StatusNotFound, "not_found", "user is not a member")
				return
			}
			writeError(w, http.StatusInternalServerError, "server_error", err.Error())
			return
		}
		event := outbox.GroupMembershipRemoved{UserID: userID, GroupID: g.ID}
		if err := outbox.Enqueue(r.Context(), tx, event); err != nil {
			writeError(w, http.StatusInternalServerError, "server_error", err.Error())
			return
		}
		if err := tx.Commit(r.Context()); err != nil {
			writeError(w, http.StatusInternalServerError, "server_error", err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// --- outbox ---

type outboxView struct {
	ID           int64   `json:"id"`
	EventType    string  `json:"event_type"`
	Status       string  `json:"status"`
	AttemptCount int     `json:"attempt_count"`
	CreatedAt    string  `json:"created_at"`
	ProcessedAt  *string `json:"processed_at,omitempty"`
	Payload      string  `json:"payload"` // raw JSON as string for SPA display
	LastError    string  `json:"last_error,omitempty"`
}

// listOutbox supports ?status=pending|failed|all (default: pending).
func listOutbox(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		filter := r.URL.Query().Get("status")
		if filter == "" {
			filter = "pending"
		}

		var (
			q     string
			qArgs []any
		)
		switch filter {
		case "pending":
			q = `SELECT id, event_type, payload, created_at, processed_at, attempt_count, last_error
			     FROM fga_outbox
			     WHERE processed_at IS NULL AND attempt_count < $1
			     ORDER BY id`
			qArgs = []any{MaxAttempts}
		case "failed":
			q = `SELECT id, event_type, payload, created_at, processed_at, attempt_count, last_error
			     FROM fga_outbox
			     WHERE processed_at IS NULL AND attempt_count >= $1
			     ORDER BY id`
			qArgs = []any{MaxAttempts}
		case "all":
			q = `SELECT id, event_type, payload, created_at, processed_at, attempt_count, last_error
			     FROM fga_outbox
			     ORDER BY id`
		default:
			writeError(w, http.StatusBadRequest, "bad_request",
				"status must be pending|failed|all")
			return
		}

		rows, err := d.Pool.Query(r.Context(), q, qArgs...)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "server_error", err.Error())
			return
		}
		defer rows.Close()

		out := []outboxView{}
		for rows.Next() {
			var (
				v           outboxView
				createdAt   time.Time
				processedAt *time.Time
				payload     []byte
				lastErr     *string
			)
			if err := rows.Scan(
				&v.ID, &v.EventType, &payload, &createdAt,
				&processedAt, &v.AttemptCount, &lastErr,
			); err != nil {
				writeError(w, http.StatusInternalServerError, "server_error", err.Error())
				return
			}
			v.CreatedAt = createdAt.UTC().Format("2006-01-02T15:04:05Z")
			if processedAt != nil {
				s := processedAt.UTC().Format("2006-01-02T15:04:05Z")
				v.ProcessedAt = &s
			}
			v.Payload = string(payload)
			if lastErr != nil {
				v.LastError = *lastErr
			}
			switch {
			case processedAt != nil:
				v.Status = "processed"
			case v.AttemptCount >= MaxAttempts:
				v.Status = "failed"
			default:
				v.Status = "pending"
			}
			out = append(out, v)
		}
		writeJSON(w, http.StatusOK, map[string]any{"rows": out})
	}
}

func retryOutbox(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", "id must be integer")
			return
		}
		const q = `
            UPDATE fga_outbox
            SET attempt_count = 0, last_error = NULL
            WHERE id = $1 AND processed_at IS NULL`
		tag, err := d.Pool.Exec(r.Context(), q, id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "server_error", err.Error())
			return
		}
		if tag.RowsAffected() == 0 {
			writeError(w, http.StatusNotFound, "not_found",
				"row not found or already processed")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// purgeOutbox refuses to purge a still-pending row unless ?force=1 is
// set. Same guard as the `idp outbox purge` CLI: a purge on a fresh
// pending row silently desyncs identity vs FGA.
func purgeOutbox(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", "id must be integer")
			return
		}
		force := r.URL.Query().Get("force") == "1"
		if !force {
			var (
				processedAt  *time.Time
				attemptCount int
			)
			row := d.Pool.QueryRow(r.Context(),
				`SELECT processed_at, attempt_count FROM fga_outbox WHERE id = $1`, id)
			if err := row.Scan(&processedAt, &attemptCount); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					writeError(w, http.StatusNotFound, "not_found", "row not found")
					return
				}
				writeError(w, http.StatusInternalServerError, "server_error", err.Error())
				return
			}
			if processedAt == nil && attemptCount < MaxAttempts {
				writeError(w, http.StatusConflict, "still_pending",
					"row is still pending; pass ?force=1 to purge anyway")
				return
			}
		}

		tag, err := d.Pool.Exec(r.Context(),
			`DELETE FROM fga_outbox WHERE id = $1`, id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "server_error", err.Error())
			return
		}
		if tag.RowsAffected() == 0 {
			writeError(w, http.StatusNotFound, "not_found", "row not found")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// --- helpers ---

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

// Compile-time confirmation that we use context.
var _ = context.TODO
