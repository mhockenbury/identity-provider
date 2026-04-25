// Outbox admin: filterable list with retry/purge actions.
// Shows the same per-row truncated payload + last-error preview the
// `idp outbox list` CLI shows.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { listOutbox, purgeOutbox, retryOutbox } from "./api";
import { useAuthedFetch } from "../auth/useAuthedFetch";

type Filter = "pending" | "failed" | "all";

const FILTERS: { value: Filter; label: string }[] = [
  { value: "pending", label: "Pending" },
  { value: "failed", label: "Failed" },
  { value: "all", label: "All" },
];

export function OutboxAdmin() {
  const fetch = useAuthedFetch();
  const queryClient = useQueryClient();
  const [params, setParams] = useSearchParams();
  const filter = (params.get("status") as Filter) || "pending";

  const list = useQuery({
    queryKey: ["admin", "outbox", filter],
    queryFn: () => listOutbox(fetch, filter),
  });

  const refresh = () => queryClient.invalidateQueries({ queryKey: ["admin", "outbox"] });

  const retry = useMutation({
    mutationFn: (id: number) => retryOutbox(fetch, id),
    onSuccess: refresh,
  });

  const purge = useMutation({
    mutationFn: (vars: { id: number; force: boolean }) =>
      purgeOutbox(fetch, vars.id, vars.force),
    onSuccess: refresh,
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Outbox</h1>
        <button
          onClick={refresh}
          className="rounded border border-gray-300 px-3 py-1.5 text-sm hover:bg-gray-100"
        >
          Refresh
        </button>
      </div>

      <nav className="flex gap-1 text-sm">
        {FILTERS.map((f) => (
          <button
            key={f.value}
            onClick={() => setParams({ status: f.value })}
            className={`rounded px-3 py-1.5 ${
              filter === f.value
                ? "bg-blue-100 font-medium text-blue-900"
                : "text-gray-700 hover:bg-gray-100"
            }`}
          >
            {f.label}
          </button>
        ))}
      </nav>

      {list.isLoading && <p className="text-sm text-gray-600">Loading…</p>}
      {list.error && (
        <p className="text-sm text-red-600">Error: {String(list.error)}</p>
      )}
      {list.data && list.data.length === 0 && (
        <p className="text-sm text-gray-600">(no rows)</p>
      )}
      {list.data && list.data.length > 0 && (
        <div className="overflow-x-auto rounded-lg border border-gray-200 bg-white">
          <table className="min-w-full divide-y divide-gray-200 text-sm">
            <thead className="bg-gray-50 text-left">
              <tr>
                <Th>ID</Th>
                <Th>Type</Th>
                <Th>Status</Th>
                <Th>Attempts</Th>
                <Th>Created</Th>
                <Th>Payload / Error</Th>
                <Th>Actions</Th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {list.data.map((row) => (
                <tr key={row.id}>
                  <Td className="font-mono text-xs">{row.id}</Td>
                  <Td>{row.event_type}</Td>
                  <Td>
                    <StatusPill status={row.status} />
                  </Td>
                  <Td>{row.attempt_count}</Td>
                  <Td className="text-xs text-gray-600">
                    {new Date(row.created_at).toLocaleString()}
                  </Td>
                  <Td className="max-w-md">
                    <details>
                      <summary className="cursor-pointer truncate text-xs text-gray-700">
                        {row.last_error
                          ? truncate(row.last_error, 80)
                          : truncate(row.payload, 80)}
                      </summary>
                      <pre className="mt-2 overflow-x-auto rounded bg-gray-50 p-2 text-xs">
                        {JSON.stringify(JSON.parse(row.payload), null, 2)}
                      </pre>
                      {row.last_error && (
                        <pre className="mt-2 overflow-x-auto rounded bg-red-50 p-2 text-xs text-red-900">
                          {row.last_error}
                        </pre>
                      )}
                    </details>
                  </Td>
                  <Td>
                    <Actions
                      row={row}
                      onRetry={() => retry.mutate(row.id)}
                      onPurge={(force) => purge.mutate({ id: row.id, force })}
                      disabled={retry.isPending || purge.isPending}
                    />
                  </Td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function StatusPill({ status }: { status: string }) {
  const styles =
    status === "processed"
      ? "bg-gray-100 text-gray-700"
      : status === "failed"
        ? "bg-red-100 text-red-800"
        : "bg-blue-100 text-blue-800";
  return (
    <span
      className={`inline-flex rounded-full px-2 py-0.5 text-xs font-medium ${styles}`}
    >
      {status}
    </span>
  );
}

function Actions({
  row,
  onRetry,
  onPurge,
  disabled,
}: {
  row: { id: number; status: string };
  onRetry: () => void;
  onPurge: (force: boolean) => void;
  disabled: boolean;
}) {
  const [confirming, setConfirming] = useState<"retry" | "purge" | null>(null);
  // Pending rows shouldn't be purged without --force; failed rows can.
  const purgeNeedsForce = row.status === "pending";

  if (confirming) {
    const action = confirming === "retry" ? onRetry : () => onPurge(purgeNeedsForce);
    const verb = confirming === "retry" ? "Retry" : "Purge";
    return (
      <span className="flex gap-1">
        <button
          onClick={() => {
            action();
            setConfirming(null);
          }}
          disabled={disabled}
          className="rounded bg-red-600 px-2 py-1 text-xs text-white hover:bg-red-700 disabled:opacity-50"
        >
          Confirm {verb}
        </button>
        <button
          onClick={() => setConfirming(null)}
          className="rounded border border-gray-300 px-2 py-1 text-xs hover:bg-gray-100"
        >
          Cancel
        </button>
      </span>
    );
  }

  return (
    <span className="flex gap-1">
      {row.status !== "processed" && (
        <button
          onClick={() => setConfirming("retry")}
          disabled={disabled}
          className="rounded border border-gray-300 px-2 py-1 text-xs hover:bg-gray-100 disabled:opacity-40"
        >
          Retry
        </button>
      )}
      <button
        onClick={() => setConfirming("purge")}
        disabled={disabled}
        title={purgeNeedsForce ? "Will use --force (pending row)" : ""}
        className="rounded border border-red-300 px-2 py-1 text-xs text-red-700 hover:bg-red-50 disabled:opacity-40"
      >
        Purge
      </button>
    </span>
  );
}

function truncate(s: string, n: number): string {
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
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
  return <td className={`px-4 py-2 align-top ${className}`}>{children}</td>;
}
