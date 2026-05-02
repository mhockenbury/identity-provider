-- name: ListFolders :many
SELECT id, parent_id, name, created_at, updated_at
FROM folders
ORDER BY created_at;

-- name: GetFolder :one
SELECT id, parent_id, name, created_at, updated_at
FROM folders
WHERE id = $1;

-- name: ListDocuments :many
SELECT id, folder_id, title, body, owner_sub, created_at, updated_at
FROM documents
ORDER BY created_at;

-- name: ListDocumentsInFolder :many
SELECT id, folder_id, title, body, owner_sub, created_at, updated_at
FROM documents
WHERE folder_id = $1
ORDER BY created_at;

-- name: GetDocument :one
SELECT id, folder_id, title, body, owner_sub, created_at, updated_at
FROM documents
WHERE id = $1;

-- name: CreateDocument :one
INSERT INTO documents (folder_id, title, body, owner_sub)
VALUES ($1, $2, $3, $4)
RETURNING id, folder_id, title, body, owner_sub, created_at, updated_at;

-- name: UpdateDocument :one
-- COALESCE+NULLIF lets the caller pass '' to mean "leave field unchanged".
-- Matches the previous in-memory Store's "empty = no change" semantics.
UPDATE documents
SET title      = COALESCE(NULLIF(sqlc.arg(title)::text, ''), title),
    body       = COALESCE(NULLIF(sqlc.arg(body)::text, ''), body),
    updated_at = now()
WHERE id = sqlc.arg(id)
RETURNING id, folder_id, title, body, owner_sub, created_at, updated_at;

-- name: DeleteDocument :execrows
DELETE FROM documents WHERE id = $1;
