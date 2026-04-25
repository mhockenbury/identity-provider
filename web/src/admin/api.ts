// Typed client for the IdP's admin JSON API.
//
// Calls go through the Vite dev proxy: `/api/admin/...` → :8080/admin/api/...
// Same fetch-injection pattern as src/docs/api.ts.

export type AdminUser = {
  id: string;
  email: string;
  is_admin: boolean;
  created_at: string;
};

export type AdminGroup = {
  id: string;
  name: string;
};

export type OutboxStatus = "pending" | "processed" | "failed";

export type OutboxRow = {
  id: number;
  event_type: string;
  status: OutboxStatus;
  attempt_count: number;
  created_at: string;
  processed_at?: string;
  payload: string; // raw JSON as a string so the SPA can pretty-print
  last_error?: string;
};

type AuthedFetch = (
  input: RequestInfo | URL,
  init?: RequestInit,
) => Promise<Response>;

const BASE = "/api/admin";

async function parseOrThrow<T>(resp: Response): Promise<T> {
  if (!resp.ok) {
    const body = await resp.text();
    throw new Error(`HTTP ${resp.status}: ${body || resp.statusText}`);
  }
  return resp.json() as Promise<T>;
}

// --- users ---

export async function listUsers(fetch: AuthedFetch): Promise<AdminUser[]> {
  const r = await fetch(`${BASE}/users`);
  const body = await parseOrThrow<{ users: AdminUser[] }>(r);
  return body.users;
}

export async function createUser(
  fetch: AuthedFetch,
  email: string,
  password: string,
): Promise<AdminUser> {
  const r = await fetch(`${BASE}/users`, {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
  return parseOrThrow<AdminUser>(r);
}

export async function setUserAdmin(
  fetch: AuthedFetch,
  id: string,
  isAdmin: boolean,
): Promise<AdminUser> {
  const path = isAdmin ? `${BASE}/users/${id}/promote` : `${BASE}/users/${id}/demote`;
  const r = await fetch(path, { method: "POST" });
  return parseOrThrow<AdminUser>(r);
}

// --- groups ---

export async function listGroups(fetch: AuthedFetch): Promise<AdminGroup[]> {
  const r = await fetch(`${BASE}/groups`);
  const body = await parseOrThrow<{ groups: AdminGroup[] }>(r);
  return body.groups;
}

export async function createGroup(
  fetch: AuthedFetch,
  name: string,
): Promise<AdminGroup> {
  const r = await fetch(`${BASE}/groups`, {
    method: "POST",
    body: JSON.stringify({ name }),
  });
  return parseOrThrow<AdminGroup>(r);
}

export async function listGroupMembers(
  fetch: AuthedFetch,
  groupName: string,
): Promise<AdminUser[]> {
  const r = await fetch(`${BASE}/groups/${groupName}/members`);
  const body = await parseOrThrow<{ members: AdminUser[] }>(r);
  return body.members;
}

export async function addGroupMember(
  fetch: AuthedFetch,
  groupName: string,
  userIDOrEmail: string,
): Promise<AdminUser> {
  const isEmail = userIDOrEmail.includes("@");
  const body = isEmail
    ? { user_email: userIDOrEmail }
    : { user_id: userIDOrEmail };
  const r = await fetch(`${BASE}/groups/${groupName}/members`, {
    method: "POST",
    body: JSON.stringify(body),
  });
  return parseOrThrow<AdminUser>(r);
}

export async function removeGroupMember(
  fetch: AuthedFetch,
  groupName: string,
  userID: string,
): Promise<void> {
  const r = await fetch(`${BASE}/groups/${groupName}/members/${userID}`, {
    method: "DELETE",
  });
  if (!r.ok && r.status !== 204) {
    const body = await r.text();
    throw new Error(`HTTP ${r.status}: ${body || r.statusText}`);
  }
}

// --- outbox ---

export async function listOutbox(
  fetch: AuthedFetch,
  status: "pending" | "failed" | "all" = "pending",
): Promise<OutboxRow[]> {
  const r = await fetch(`${BASE}/outbox?status=${status}`);
  const body = await parseOrThrow<{ rows: OutboxRow[] }>(r);
  return body.rows;
}

export async function retryOutbox(
  fetch: AuthedFetch,
  id: number,
): Promise<void> {
  const r = await fetch(`${BASE}/outbox/${id}/retry`, { method: "POST" });
  if (!r.ok && r.status !== 204) {
    const body = await r.text();
    throw new Error(`HTTP ${r.status}: ${body || r.statusText}`);
  }
}

export async function purgeOutbox(
  fetch: AuthedFetch,
  id: number,
  force = false,
): Promise<void> {
  const path = `${BASE}/outbox/${id}${force ? "?force=1" : ""}`;
  const r = await fetch(path, { method: "DELETE" });
  if (!r.ok && r.status !== 204) {
    const body = await r.text();
    throw new Error(`HTTP ${r.status}: ${body || r.statusText}`);
  }
}

// --- clients ---

export type AdminClient = {
  id: string;
  is_public: boolean;
  secret_set: boolean;
  redirect_uris: string[];
  allowed_grants: string[];
  allowed_scopes: string[];
  created_at: string;
};

// Returned by create + rotate-secret. The plaintext is shown to the user
// EXACTLY ONCE — it isn't returned by getClient or listClients.
export type AdminClientCreated = AdminClient & {
  plaintext_secret?: string;
};

export async function listClients(fetch: AuthedFetch): Promise<AdminClient[]> {
  const r = await fetch(`${BASE}/clients`);
  const body = await parseOrThrow<{ clients: AdminClient[] }>(r);
  return body.clients;
}

export async function getClient(
  fetch: AuthedFetch,
  id: string,
): Promise<AdminClient> {
  const r = await fetch(`${BASE}/clients/${encodeURIComponent(id)}`);
  return parseOrThrow<AdminClient>(r);
}

export async function createClient(
  fetch: AuthedFetch,
  req: {
    id: string;
    is_public: boolean;
    redirect_uris: string[];
    allowed_grants?: string[];
    allowed_scopes: string[];
  },
): Promise<AdminClientCreated> {
  const r = await fetch(`${BASE}/clients`, {
    method: "POST",
    body: JSON.stringify(req),
  });
  return parseOrThrow<AdminClientCreated>(r);
}

export async function updateClient(
  fetch: AuthedFetch,
  id: string,
  req: {
    redirect_uris: string[];
    allowed_grants: string[];
    allowed_scopes: string[];
  },
): Promise<AdminClient> {
  const r = await fetch(`${BASE}/clients/${encodeURIComponent(id)}`, {
    method: "PATCH",
    body: JSON.stringify(req),
  });
  return parseOrThrow<AdminClient>(r);
}

export async function rotateClientSecret(
  fetch: AuthedFetch,
  id: string,
): Promise<AdminClientCreated> {
  const r = await fetch(
    `${BASE}/clients/${encodeURIComponent(id)}/rotate-secret`,
    { method: "POST" },
  );
  return parseOrThrow<AdminClientCreated>(r);
}

export async function deleteClient(
  fetch: AuthedFetch,
  id: string,
): Promise<void> {
  const r = await fetch(`${BASE}/clients/${encodeURIComponent(id)}`, {
    method: "DELETE",
  });
  if (!r.ok && r.status !== 204) {
    const body = await r.text();
    throw new Error(`HTTP ${r.status}: ${body || r.statusText}`);
  }
}
