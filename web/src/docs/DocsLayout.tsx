// Two-column layout for the docs product: folder sidebar on the left,
// content (doc list or doc detail) on the right via <Outlet />.
//
// Folder list is fetched once per mount; React Query caches it.
// Nesting is rendered by walking parent_id — good enough for the
// seed corpus; a real app would use react-arborist or similar.

import { useQuery } from "@tanstack/react-query";
import { Link, NavLink, Outlet } from "react-router-dom";
import { listFolders, listDocs, type Folder, type Doc } from "./api";
import { useAuthedFetch } from "../auth/useAuthedFetch";
import { PermissionBadge } from "./PermissionBadge";

export function DocsLayout() {
  const fetch = useAuthedFetch();

  const folders = useQuery({
    queryKey: ["folders"],
    queryFn: () => listFolders(fetch),
    staleTime: 30_000,
  });

  // Also pre-fetch the full doc list for the "all docs" and "orphan"
  // lookups. Cheap at seed-scale; React Query shares it with the
  // index page.
  const docs = useQuery({
    queryKey: ["docs"],
    queryFn: () => listDocs(fetch),
    staleTime: 30_000,
  });

  return (
    <div className="grid grid-cols-[260px_1fr] gap-6">
      <aside className="space-y-4">
        <section>
          <NavLink
            to="/docs"
            end
            className={({ isActive }) =>
              `block rounded px-2 py-1 text-sm ${
                isActive
                  ? "bg-blue-100 font-medium text-blue-900"
                  : "text-gray-700 hover:bg-gray-100"
              }`
            }
          >
            All docs
          </NavLink>
        </section>

        <section>
          <h2 className="px-2 text-xs font-semibold uppercase tracking-wide text-gray-500">
            Folders
          </h2>
          {folders.isLoading && (
            <p className="px-2 text-sm text-gray-500">Loading…</p>
          )}
          {folders.error && (
            <p className="px-2 text-sm text-red-600">
              Error loading folders.
            </p>
          )}
          {folders.data && (
            <FolderTree folders={folders.data} />
          )}
        </section>

        <section>
          <h2 className="px-2 text-xs font-semibold uppercase tracking-wide text-gray-500">
            Orphan docs
          </h2>
          {docs.data && <OrphanDocs docs={docs.data} />}
        </section>
      </aside>

      <div>
        <Outlet />
      </div>
    </div>
  );
}

// FolderTree renders folders as a flat list grouped by parent. Two
// levels is the maximum our seed corpus has, so we don't over-engineer
// with a recursive tree library.
function FolderTree({ folders }: Readonly<{folders: Folder[]}>) {
  const topLevel = folders.filter((f) => !f.parent_id);
  const children = (parentID: string) =>
    folders.filter((f) => f.parent_id === parentID);

  if (folders.length === 0) {
    return <p className="px-2 text-sm text-gray-500">No folders visible.</p>;
  }

  return (
    <ul className="space-y-0.5">
      {topLevel.map((f) => (
        <li key={f.id}>
          <FolderLink folder={f} />
          {children(f.id).length > 0 && (
            <ul className="ml-4 space-y-0.5 border-l border-gray-200 pl-2">
              {children(f.id).map((c) => (
                <li key={c.id}>
                  <FolderLink folder={c} />
                </li>
              ))}
            </ul>
          )}
        </li>
      ))}
    </ul>
  );
}

function FolderLink({ folder }: Readonly<{folder: Folder}>) {
  return (
    <NavLink
      to={`/docs/folders/${folder.id}`}
      className={({ isActive }) =>
        `flex items-center justify-between rounded px-2 py-1 text-sm ${
          isActive
            ? "bg-blue-100 font-medium text-blue-900"
            : "text-gray-700 hover:bg-gray-100"
        }`
      }
    >
      <span className="truncate">{folder.name}</span>
      <PermissionBadge permission={folder.permission} />
    </NavLink>
  );
}

// OrphanDocs shows docs without a folder_id. These only appear in the
// sidebar so the user can get to them — they're otherwise orphaned
// from the folder navigation.
function OrphanDocs({ docs }: Readonly<{docs: Doc[]}>) {
  const orphans = docs.filter((d) => !d.folder_id);
  if (orphans.length === 0) {
    return <p className="px-2 text-sm text-gray-500">None.</p>;
  }
  return (
    <ul className="space-y-0.5">
      {orphans.map((d) => (
        <li key={d.id}>
          <Link
            to={`/docs/${d.id}`}
            className="flex items-center justify-between rounded px-2 py-1 text-sm text-gray-700 hover:bg-gray-100"
          >
            <span className="truncate">{d.title}</span>
            <PermissionBadge permission={d.permission} />
          </Link>
        </li>
      ))}
    </ul>
  );
}
