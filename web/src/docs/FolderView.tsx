// Folder contents: header with folder name + permission, list of docs
// in the folder (non-recursive — matches docs-api behavior).

import { useQuery } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { getFolder, listFolderDocs } from "./api";
import { useAuthedFetch } from "../auth/useAuthedFetch";
import { PermissionBadge } from "./PermissionBadge";

export function FolderView() {
  const { id = "" } = useParams();
  const fetch = useAuthedFetch();

  const folder = useQuery({
    queryKey: ["folder", id],
    queryFn: () => getFolder(fetch, id),
    enabled: !!id,
    staleTime: 30_000,
  });

  const docs = useQuery({
    queryKey: ["folder-docs", id],
    queryFn: () => listFolderDocs(fetch, id),
    enabled: !!id,
    staleTime: 30_000,
  });

  if (folder.isLoading || docs.isLoading) {
    return <p className="text-sm text-gray-600">Loading…</p>;
  }
  if (folder.error) {
    return (
      <p className="text-sm text-red-600">Folder not available.</p>
    );
  }
  if (!folder.data) return null;

  return (
    <div>
      <div className="mb-4 flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold">{folder.data.name}</h1>
          <p className="text-sm text-gray-500">folder</p>
        </div>
        <PermissionBadge permission={folder.data.permission} />
      </div>

      {docs.data && docs.data.length === 0 ? (
        <p className="text-sm text-gray-600">No docs in this folder.</p>
      ) : (
        <ul className="divide-y divide-gray-200 rounded-lg border border-gray-200 bg-white">
          {docs.data?.map((d) => (
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
      )}
    </div>
  );
}
