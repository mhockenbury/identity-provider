// OAuth clients admin: list, inspect, create, edit, rotate secret, delete.
//
// Critical UX point: client secrets are shown in plaintext exactly ONCE
// (on create + rotate-secret response). Subsequent reads only know
// "secret is set". The UI must surface this loud and clear so the
// operator copies the secret immediately.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import {
  type AdminClient,
  type AdminClientCreated,
  createClient,
  deleteClient,
  listClients,
  rotateClientSecret,
  updateClient,
} from "./api";
import { useAuthedFetch } from "../auth/useAuthedFetch";

export function ClientsAdmin() {
  const fetch = useAuthedFetch();
  const list = useQuery({
    queryKey: ["admin", "clients"],
    queryFn: () => listClients(fetch),
  });
  const [selected, setSelected] = useState<AdminClient | null>(null);
  const [creating, setCreating] = useState(false);

  // Holds the most-recently-revealed plaintext secret. Banner stays
  // visible until the operator dismisses it.
  const [secretBanner, setSecretBanner] = useState<{
    clientID: string;
    plaintext: string;
    context: "created" | "rotated";
  } | null>(null);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">OAuth Clients</h1>
        <button
          onClick={() => {
            setCreating(true);
            setSelected(null);
          }}
          className="rounded bg-blue-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-blue-700"
        >
          Create client
        </button>
      </div>

      {secretBanner && (
        <SecretBanner
          banner={secretBanner}
          onDismiss={() => setSecretBanner(null)}
        />
      )}

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-[320px_1fr]">
        <aside>
          {list.isLoading && (
            <p className="text-sm text-gray-600">Loading…</p>
          )}
          {list.error && (
            <p className="text-sm text-red-600">Error: {String(list.error)}</p>
          )}
          {list.data && list.data.length === 0 && (
            <p className="text-sm text-gray-600">No clients.</p>
          )}
          {list.data && list.data.length > 0 && (
            <ul className="divide-y divide-gray-200 rounded-lg border border-gray-200 bg-white">
              {list.data.map((c) => (
                <li key={c.id}>
                  <button
                    onClick={() => {
                      setSelected(c);
                      setCreating(false);
                    }}
                    className={`block w-full px-3 py-2 text-left text-sm hover:bg-gray-50 ${
                      selected?.id === c.id
                        ? "bg-blue-50 font-medium text-blue-900"
                        : "text-gray-900"
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="truncate">{c.id}</span>
                      <span
                        className={`text-xs ${
                          c.is_public ? "text-amber-700" : "text-gray-500"
                        }`}
                      >
                        {c.is_public ? "public" : "confidential"}
                      </span>
                    </div>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </aside>

        <div>
          {creating ? (
            <CreateClientForm
              onCreated={(c) => {
                setSecretBanner({
                  clientID: c.id,
                  plaintext: c.plaintext_secret ?? "",
                  context: "created",
                });
                setCreating(false);
                setSelected({ ...c });
              }}
              onCancel={() => setCreating(false)}
            />
          ) : selected ? (
            <ClientDetail
              client={selected}
              onChanged={(c) => setSelected(c)}
              onSecretRevealed={(plaintext) =>
                setSecretBanner({
                  clientID: selected.id,
                  plaintext,
                  context: "rotated",
                })
              }
              onDeleted={() => setSelected(null)}
            />
          ) : (
            <Empty />
          )}
        </div>
      </div>
    </div>
  );
}

function Empty() {
  return (
    <div className="rounded-lg border border-dashed border-gray-300 p-8 text-center text-sm text-gray-500">
      Select a client to inspect, or click "Create client" to register a new one.
    </div>
  );
}

// --- secret banner ---

function SecretBanner({
  banner,
  onDismiss,
}: Readonly<{
  banner: { clientID: string; plaintext: string; context: "created" | "rotated" };
  onDismiss: () => void;
}>) {
  const [copied, setCopied] = useState(false);
  if (!banner.plaintext) return null; // public clients
  const action =
    banner.context === "created"
      ? "Client created."
      : "Secret rotated.";
  return (
    <div className="rounded-lg border border-amber-300 bg-amber-50 p-4">
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0">
          <p className="font-medium text-amber-900">
            {action} Copy the secret now — it will never be shown again.
          </p>
          <p className="mt-1 text-xs text-amber-800">
            Client ID: <code className="font-mono">{banner.clientID}</code>
          </p>
          <pre className="mt-3 overflow-x-auto rounded bg-white p-2 font-mono text-sm text-gray-900 ring-1 ring-amber-200">
            {banner.plaintext}
          </pre>
        </div>
        <div className="flex shrink-0 flex-col gap-1.5">
          <button
            onClick={() => {
              navigator.clipboard.writeText(banner.plaintext);
              setCopied(true);
              setTimeout(() => setCopied(false), 2000);
            }}
            className="rounded bg-amber-600 px-3 py-1 text-xs font-medium text-white hover:bg-amber-700"
          >
            {copied ? "Copied" : "Copy"}
          </button>
          <button
            onClick={onDismiss}
            className="rounded border border-amber-300 px-3 py-1 text-xs hover:bg-amber-100"
          >
            Dismiss
          </button>
        </div>
      </div>
    </div>
  );
}

// --- create form ---

function CreateClientForm({
  onCreated,
  onCancel,
}: Readonly<{onCreated: (c: AdminClientCreated) => void;
  onCancel: () => void;}>) {
  const fetch = useAuthedFetch();
  const queryClient = useQueryClient();
  const [id, setID] = useState("");
  const [isPublic, setIsPublic] = useState(false);
  const [redirectURIsRaw, setRedirectURIsRaw] = useState("");
  const [scopesRaw, setScopesRaw] = useState("openid email");

  const create = useMutation({
    mutationFn: () =>
      createClient(fetch, {
        id: id.trim(),
        is_public: isPublic,
        redirect_uris: redirectURIsRaw
          .split(/\s+/)
          .map((s) => s.trim())
          .filter((s) => s.length > 0),
        allowed_scopes: scopesRaw
          .split(/\s+/)
          .map((s) => s.trim())
          .filter((s) => s.length > 0),
      }),
    onSuccess: (c) => {
      queryClient.invalidateQueries({ queryKey: ["admin", "clients"] });
      onCreated(c);
    },
  });

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        create.mutate();
      }}
      className="space-y-4 rounded-lg border border-gray-200 bg-white p-5"
    >
      <h2 className="text-lg font-semibold">Create OAuth Client</h2>
      <Field label="Client ID" hint="Lowercase identifier; immutable after creation.">
        <input
          required
          value={id}
          onChange={(e) => setID(e.target.value)}
          placeholder="my-spa"
          className="w-full rounded border border-gray-300 px-2 py-1 font-mono text-sm"
        />
      </Field>
      <Field label="Type">
        <label className="flex items-center gap-2 text-sm">
          <input
            type="radio"
            checked={!isPublic}
            onChange={() => setIsPublic(false)}
          />
          <span>
            <span className="font-medium">Confidential</span> — server-side app, gets a generated secret
          </span>
        </label>
        <label className="mt-2 flex items-center gap-2 text-sm">
          <input
            type="radio"
            checked={isPublic}
            onChange={() => setIsPublic(true)}
          />
          <span>
            <span className="font-medium">Public</span> — SPA / mobile, PKCE-only, no secret
          </span>
        </label>
      </Field>
      <Field label="Redirect URIs" hint="Whitespace-separated. Exact match enforced at /authorize.">
        <textarea
          required
          rows={3}
          value={redirectURIsRaw}
          onChange={(e) => setRedirectURIsRaw(e.target.value)}
          placeholder="http://localhost:5173/callback"
          className="w-full rounded border border-gray-300 px-2 py-1 font-mono text-sm"
        />
      </Field>
      <Field label="Allowed scopes" hint="Space-separated. Required scopes will not be granted if not listed here.">
        <input
          value={scopesRaw}
          onChange={(e) => setScopesRaw(e.target.value)}
          placeholder="openid email read:docs write:docs"
          className="w-full rounded border border-gray-300 px-2 py-1 font-mono text-sm"
        />
      </Field>
      <div className="flex gap-2">
        <button
          type="submit"
          disabled={create.isPending}
          className="rounded bg-blue-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50"
        >
          {create.isPending ? "Creating…" : "Create"}
        </button>
        <button
          type="button"
          onClick={onCancel}
          className="rounded border border-gray-300 px-4 py-1.5 text-sm hover:bg-gray-100"
        >
          Cancel
        </button>
        {create.error && (
          <span className="text-sm text-red-600">{String(create.error)}</span>
        )}
      </div>
    </form>
  );
}

// --- detail ---

function ClientDetail({
  client,
  onChanged,
  onSecretRevealed,
  onDeleted,
}: Readonly<{client: AdminClient;
  onChanged: (c: AdminClient) => void;
  onSecretRevealed: (plaintext: string) => void;
  onDeleted: () => void;}>) {
  const fetch = useAuthedFetch();
  const queryClient = useQueryClient();
  const [editing, setEditing] = useState(false);
  const [redirectURIsRaw, setRedirectURIsRaw] = useState(
    client.redirect_uris.join("\n"),
  );
  const [scopesRaw, setScopesRaw] = useState(client.allowed_scopes.join(" "));
  const [grantsRaw, setGrantsRaw] = useState(client.allowed_grants.join(" "));

  const update = useMutation({
    mutationFn: () =>
      updateClient(fetch, client.id, {
        redirect_uris: redirectURIsRaw
          .split(/\s+/)
          .map((s) => s.trim())
          .filter((s) => s.length > 0),
        allowed_grants: grantsRaw
          .split(/\s+/)
          .map((s) => s.trim())
          .filter((s) => s.length > 0),
        allowed_scopes: scopesRaw
          .split(/\s+/)
          .map((s) => s.trim())
          .filter((s) => s.length > 0),
      }),
    onSuccess: (c) => {
      queryClient.invalidateQueries({ queryKey: ["admin", "clients"] });
      onChanged(c);
      setEditing(false);
    },
  });

  const rotate = useMutation({
    mutationFn: () => rotateClientSecret(fetch, client.id),
    onSuccess: (c) => {
      onSecretRevealed(c.plaintext_secret ?? "");
      onChanged(c);
    },
  });

  const remove = useMutation({
    mutationFn: () => deleteClient(fetch, client.id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["admin", "clients"] });
      onDeleted();
    },
  });

  const handleDelete = () => {
    if (
      !confirm(
        `Delete client "${client.id}"? Active sessions for this client will break and consent rows will be removed.`,
      )
    ) {
      return;
    }
    remove.mutate();
  };

  const handleRotate = () => {
    if (
      !confirm(
        `Rotate the secret for "${client.id}"? Any backend currently using the old secret will start failing on /token.`,
      )
    ) {
      return;
    }
    rotate.mutate();
  };

  return (
    <section className="space-y-5 rounded-lg border border-gray-200 bg-white p-5">
      <header className="flex items-start justify-between gap-4 border-b border-gray-200 pb-4">
        <div>
          <h2 className="font-mono text-lg font-semibold">{client.id}</h2>
          <p className="mt-1 text-xs text-gray-600">
            {client.is_public ? "Public (PKCE-only)" : "Confidential"} ·
            secret_set: <code>{String(client.secret_set)}</code> · created{" "}
            {new Date(client.created_at).toLocaleDateString()}
          </p>
        </div>
        <div className="flex gap-1">
          {!client.is_public && (
            <button
              onClick={handleRotate}
              disabled={rotate.isPending}
              className="rounded border border-amber-300 px-2 py-1 text-xs text-amber-800 hover:bg-amber-50 disabled:opacity-40"
            >
              {rotate.isPending ? "Rotating…" : "Rotate secret"}
            </button>
          )}
          <button
            onClick={handleDelete}
            disabled={remove.isPending}
            className="rounded border border-red-300 px-2 py-1 text-xs text-red-700 hover:bg-red-50 disabled:opacity-40"
          >
            Delete
          </button>
        </div>
      </header>

      {editing ? (
        <div className="space-y-3">
          <Field
            label="Redirect URIs"
            hint="Whitespace-separated. Removing a URI breaks any active session redirected to it."
          >
            <textarea
              rows={3}
              value={redirectURIsRaw}
              onChange={(e) => setRedirectURIsRaw(e.target.value)}
              className="w-full rounded border border-gray-300 px-2 py-1 font-mono text-sm"
            />
          </Field>
          <Field
            label="Allowed grants"
            hint="Space-separated. Typically: authorization_code refresh_token"
          >
            <input
              value={grantsRaw}
              onChange={(e) => setGrantsRaw(e.target.value)}
              className="w-full rounded border border-gray-300 px-2 py-1 font-mono text-sm"
            />
          </Field>
          <Field
            label="Allowed scopes"
            hint="Removing a scope here doesn't revoke issued tokens — they remain valid until expiry. Subsequent /token calls won't grant the removed scope."
          >
            <input
              value={scopesRaw}
              onChange={(e) => setScopesRaw(e.target.value)}
              className="w-full rounded border border-gray-300 px-2 py-1 font-mono text-sm"
            />
          </Field>
          <div className="flex gap-2">
            <button
              onClick={() => update.mutate()}
              disabled={update.isPending}
              className="rounded bg-blue-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50"
            >
              {update.isPending ? "Saving…" : "Save"}
            </button>
            <button
              onClick={() => setEditing(false)}
              className="rounded border border-gray-300 px-3 py-1.5 text-sm hover:bg-gray-100"
            >
              Cancel
            </button>
            {update.error && (
              <span className="text-sm text-red-600">{String(update.error)}</span>
            )}
          </div>
        </div>
      ) : (
        <div className="space-y-3 text-sm">
          <Detail label="Redirect URIs">
            <ul className="font-mono text-sm">
              {client.redirect_uris.map((u) => (
                <li key={u} className="break-all">
                  {u}
                </li>
              ))}
            </ul>
          </Detail>
          <Detail label="Allowed grants">
            <code>{client.allowed_grants.join(" ")}</code>
          </Detail>
          <Detail label="Allowed scopes">
            <code>{client.allowed_scopes.join(" ")}</code>
          </Detail>
          <button
            onClick={() => setEditing(true)}
            className="rounded border border-gray-300 px-3 py-1.5 text-sm hover:bg-gray-100"
          >
            Edit
          </button>
        </div>
      )}
    </section>
  );
}

// --- tiny presentational helpers ---

function Field({
  label,
  hint,
  children,
}: Readonly<{label: string;
  hint?: string;
  children: React.ReactNode;}>) {
  return (
    <div>
      <label className="block text-sm font-medium text-gray-900">{label}</label>
      {hint && <p className="mt-0.5 text-xs text-gray-500">{hint}</p>}
      <div className="mt-1">{children}</div>
    </div>
  );
}

function Detail({
  label,
  children,
}: Readonly<{label: string;
  children: React.ReactNode;}>) {
  return (
    <div>
      <p className="text-xs font-semibold uppercase tracking-wide text-gray-500">
        {label}
      </p>
      <div className="mt-1 text-gray-900">{children}</div>
    </div>
  );
}
