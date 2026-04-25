// Users admin: list, create, promote/demote.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useAuth } from "react-oidc-context";
import {
  type AdminUser,
  createUser,
  listUsers,
  setUserAdmin,
} from "./api";
import { useAuthedFetch } from "../auth/useAuthedFetch";

export function UsersAdmin() {
  const fetch = useAuthedFetch();
  const auth = useAuth();
  const currentSub = auth.user?.profile.sub;

  const list = useQuery({
    queryKey: ["admin", "users"],
    queryFn: () => listUsers(fetch),
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Users</h1>
        <CreateUserForm />
      </div>

      {list.isLoading && <p className="text-sm text-gray-600">Loading…</p>}
      {list.error && (
        <p className="text-sm text-red-600">Error: {String(list.error)}</p>
      )}
      {list.data && (
        <table className="min-w-full divide-y divide-gray-200 rounded-lg border border-gray-200 bg-white text-sm">
          <thead className="bg-gray-50 text-left">
            <tr>
              <Th>Email</Th>
              <Th>Admin</Th>
              <Th>Created</Th>
              <Th>{" "}</Th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {list.data.map((u) => (
              <UserRow key={u.id} user={u} isMe={u.id === currentSub} />
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function UserRow({ user, isMe }: { user: AdminUser; isMe: boolean }) {
  const fetch = useAuthedFetch();
  const queryClient = useQueryClient();
  const toggle = useMutation({
    mutationFn: () => setUserAdmin(fetch, user.id, !user.is_admin),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["admin", "users"] });
    },
  });

  return (
    <tr>
      <Td>
        <div className="flex items-center gap-2">
          <span className="font-medium text-gray-900">{user.email}</span>
          {isMe && (
            <span className="rounded bg-gray-100 px-1.5 py-0.5 text-xs text-gray-600">
              you
            </span>
          )}
        </div>
        <p className="text-xs text-gray-500">{user.id}</p>
      </Td>
      <Td>
        {user.is_admin ? (
          <span className="rounded-full bg-green-100 px-2 py-0.5 text-xs font-medium text-green-800">
            admin
          </span>
        ) : (
          <span className="text-xs text-gray-500">no</span>
        )}
      </Td>
      <Td className="text-xs text-gray-600">
        {new Date(user.created_at).toLocaleDateString()}
      </Td>
      <Td className="text-right">
        <button
          onClick={() => toggle.mutate()}
          disabled={toggle.isPending || isMe}
          title={isMe ? "Can't change your own admin flag" : ""}
          className="rounded border border-gray-300 px-2 py-1 text-xs hover:bg-gray-100 disabled:opacity-40"
        >
          {toggle.isPending
            ? "…"
            : user.is_admin
              ? "Demote"
              : "Promote"}
        </button>
      </Td>
    </tr>
  );
}

function CreateUserForm() {
  const fetch = useAuthedFetch();
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const create = useMutation({
    mutationFn: () => createUser(fetch, email, password),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["admin", "users"] });
      setEmail("");
      setPassword("");
      setOpen(false);
    },
  });

  if (!open) {
    return (
      <button
        onClick={() => setOpen(true)}
        className="rounded bg-blue-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-blue-700"
      >
        Create user
      </button>
    );
  }

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        create.mutate();
      }}
      className="flex items-center gap-2"
    >
      <input
        type="email"
        required
        placeholder="email"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        className="rounded border border-gray-300 px-2 py-1 text-sm"
      />
      <input
        type="password"
        required
        minLength={8}
        placeholder="password (min 8)"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        className="rounded border border-gray-300 px-2 py-1 text-sm"
      />
      <button
        type="submit"
        disabled={create.isPending}
        className="rounded bg-blue-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50"
      >
        {create.isPending ? "Creating…" : "Save"}
      </button>
      <button
        type="button"
        onClick={() => setOpen(false)}
        className="rounded border border-gray-300 px-3 py-1.5 text-sm hover:bg-gray-100"
      >
        Cancel
      </button>
      {create.error && (
        <span className="text-sm text-red-600">{String(create.error)}</span>
      )}
    </form>
  );
}

function Th({ children }: { children: React.ReactNode }) {
  return (
    <th className="px-4 py-2 text-xs font-semibold uppercase tracking-wide text-gray-600">
      {children}
    </th>
  );
}
function Td({
  children,
  className = "",
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return <td className={`px-4 py-2 ${className}`}>{children}</td>;
}
