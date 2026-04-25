// Dashboard: at-a-glance counts. Each tile clicks through to its full
// management page.

import { useQueries } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { listClients, listGroups, listOutbox, listUsers } from "./api";
import { useAuthedFetch } from "../auth/useAuthedFetch";

export function Dashboard() {
  const fetch = useAuthedFetch();
  const queries = useQueries({
    queries: [
      { queryKey: ["admin", "users"], queryFn: () => listUsers(fetch) },
      { queryKey: ["admin", "groups"], queryFn: () => listGroups(fetch) },
      { queryKey: ["admin", "clients"], queryFn: () => listClients(fetch) },
      {
        queryKey: ["admin", "outbox", "pending"],
        queryFn: () => listOutbox(fetch, "pending"),
      },
      {
        queryKey: ["admin", "outbox", "failed"],
        queryFn: () => listOutbox(fetch, "failed"),
      },
    ],
  });
  const [usersQ, groupsQ, clientsQ, pendingQ, failedQ] = queries;

  return (
    <div>
      <h1 className="text-xl font-semibold">Dashboard</h1>
      <div className="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-5">
        <Tile to="/admin/users" label="Users" count={usersQ.data?.length} loading={usersQ.isLoading} />
        <Tile to="/admin/groups" label="Groups" count={groupsQ.data?.length} loading={groupsQ.isLoading} />
        <Tile to="/admin/clients" label="Clients" count={clientsQ.data?.length} loading={clientsQ.isLoading} />
        <Tile
          to="/admin/outbox"
          label="Outbox pending"
          count={pendingQ.data?.length}
          loading={pendingQ.isLoading}
        />
        <Tile
          to="/admin/outbox?status=failed"
          label="Outbox failed"
          count={failedQ.data?.length}
          loading={failedQ.isLoading}
          danger={(failedQ.data?.length ?? 0) > 0}
        />
      </div>
      {queries.some((q) => q.error) && (
        <p className="mt-4 text-sm text-red-600">
          Some data failed to load. Check the browser console.
        </p>
      )}
    </div>
  );
}

function Tile({
  to,
  label,
  count,
  loading,
  danger,
}: {
  to: string;
  label: string;
  count?: number;
  loading?: boolean;
  danger?: boolean;
}) {
  return (
    <Link
      to={to}
      className={`block rounded-lg border bg-white p-4 shadow-sm transition hover:shadow ${
        danger ? "border-red-300" : "border-gray-200"
      }`}
    >
      <p className="text-sm text-gray-600">{label}</p>
      <p
        className={`mt-1 text-3xl font-semibold ${
          danger ? "text-red-700" : "text-gray-900"
        }`}
      >
        {loading ? "…" : count ?? 0}
      </p>
    </Link>
  );
}
