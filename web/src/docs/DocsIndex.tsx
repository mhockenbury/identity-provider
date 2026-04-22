// Default right-pane content: list every doc the user can view, with
// their permission tier. Links to the detail view.

import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { listDocs } from "./api";
import { useAuthedFetch } from "../auth/useAuthedFetch";
import { PermissionBadge } from "./PermissionBadge";

export function DocsIndex() {
  const fetch = useAuthedFetch();
  const { data, isLoading, error } = useQuery({
    queryKey: ["docs"],
    queryFn: () => listDocs(fetch),
    staleTime: 30_000,
  });

  if (isLoading) {
    return <p className="text-sm text-gray-600">Loading…</p>;
  }
  if (error) {
    return (
      <p className="text-sm text-red-600">Error loading docs: {String(error)}</p>
    );
  }
  if (!data || data.length === 0) {
    return (
      <p className="text-sm text-gray-600">
        You don't have access to any docs yet.
      </p>
    );
  }

  return (
    <div>
      <div className="mb-4 flex items-center justify-between">
        <h1 className="text-xl font-semibold">All docs</h1>
        <p className="text-sm text-gray-500">{data.length} visible</p>
      </div>
      <ul className="divide-y divide-gray-200 rounded-lg border border-gray-200 bg-white">
        {data.map((d) => (
          <li key={d.id}>
            <Link
              to={`/docs/${d.id}`}
              className="flex items-center justify-between px-4 py-3 hover:bg-gray-50"
            >
              <div className="min-w-0">
                <p className="truncate font-medium text-gray-900">
                  {d.title}
                </p>
                <p className="truncate text-sm text-gray-500">
                  updated {new Date(d.updated_at).toLocaleString()}
                </p>
              </div>
              <PermissionBadge permission={d.permission} />
            </Link>
          </li>
        ))}
      </ul>
    </div>
  );
}
