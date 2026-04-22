// Typed client for the docs-api.
//
// All calls go through the Vite dev proxy: `/api/docs/...` → :8083/...
// Returns parsed JSON or throws. Auth is injected by useAuthedFetch,
// so this file has no awareness of tokens — it accepts any fetch
// function with a standard signature. That keeps React Query's
// queryFn ergonomic and keeps the types in one place.

export type Permission = "owner" | "editor" | "viewer";

export type Doc = {
  id: string;
  folder_id?: string;
  title: string;
  body?: string;
  owner: string;
  created_at: string;
  updated_at: string;
  permission: Permission;
};

export type Folder = {
  id: string;
  parent_id?: string;
  name: string;
  permission: Permission;
};

// AuthedFetch is the shape useAuthedFetch returns — narrowed here so
// this module doesn't import React hooks.
type AuthedFetch = (
  input: RequestInfo | URL,
  init?: RequestInit,
) => Promise<Response>;

const BASE = "/api/docs";

async function parseOrThrow<T>(resp: Response): Promise<T> {
  if (!resp.ok) {
    const body = await resp.text();
    throw new Error(`HTTP ${resp.status}: ${body || resp.statusText}`);
  }
  return resp.json() as Promise<T>;
}

export async function listDocs(fetch: AuthedFetch): Promise<Doc[]> {
  const resp = await fetch(`${BASE}/docs`);
  const body = await parseOrThrow<{ docs: Doc[] }>(resp);
  return body.docs;
}

export async function getDoc(fetch: AuthedFetch, id: string): Promise<Doc> {
  const resp = await fetch(`${BASE}/docs/${id}`);
  return parseOrThrow<Doc>(resp);
}

export async function listFolders(fetch: AuthedFetch): Promise<Folder[]> {
  const resp = await fetch(`${BASE}/folders`);
  const body = await parseOrThrow<{ folders: Folder[] }>(resp);
  return body.folders;
}

export async function getFolder(
  fetch: AuthedFetch,
  id: string,
): Promise<Folder> {
  const resp = await fetch(`${BASE}/folders/${id}`);
  return parseOrThrow<Folder>(resp);
}

export async function listFolderDocs(
  fetch: AuthedFetch,
  folderID: string,
): Promise<Doc[]> {
  const resp = await fetch(`${BASE}/folders/${folderID}/docs`);
  const body = await parseOrThrow<{ docs: Doc[] }>(resp);
  return body.docs;
}

export async function updateDoc(
  fetch: AuthedFetch,
  id: string,
  patch: { title?: string; body?: string },
): Promise<Doc> {
  const resp = await fetch(`${BASE}/docs/${id}`, {
    method: "PATCH",
    body: JSON.stringify(patch),
  });
  return parseOrThrow<Doc>(resp);
}

export async function deleteDoc(
  fetch: AuthedFetch,
  id: string,
): Promise<void> {
  const resp = await fetch(`${BASE}/docs/${id}`, { method: "DELETE" });
  if (!resp.ok && resp.status !== 204) {
    const body = await resp.text();
    throw new Error(`HTTP ${resp.status}: ${body || resp.statusText}`);
  }
}

// --- permission helpers used by the UI ---

export function canEdit(perm: Permission): boolean {
  return perm === "owner" || perm === "editor";
}

export function canDelete(perm: Permission): boolean {
  return perm === "owner";
}
