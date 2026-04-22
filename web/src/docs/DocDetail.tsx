// Single-doc view with inline edit + delete. Buttons show/hide based
// on the caller's permission tier (enforced redundantly server-side —
// the SPA just hides affordances it knows won't succeed).

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import {
  canDelete,
  canEdit,
  deleteDoc,
  getDoc,
  updateDoc,
} from "./api";
import { useAuthedFetch } from "../auth/useAuthedFetch";
import { PermissionBadge } from "./PermissionBadge";

export function DocDetail() {
  const { id = "" } = useParams();
  const fetch = useAuthedFetch();
  const queryClient = useQueryClient();
  const navigate = useNavigate();

  const doc = useQuery({
    queryKey: ["doc", id],
    queryFn: () => getDoc(fetch, id),
    enabled: !!id,
  });

  const [editing, setEditing] = useState(false);
  const [titleDraft, setTitleDraft] = useState("");
  const [bodyDraft, setBodyDraft] = useState("");

  const patchMutation = useMutation({
    mutationFn: (patch: { title?: string; body?: string }) =>
      updateDoc(fetch, id, patch),
    onSuccess: (updated) => {
      queryClient.setQueryData(["doc", id], updated);
      // Broader caches might be showing the old title; invalidate.
      queryClient.invalidateQueries({ queryKey: ["docs"] });
      if (updated.folder_id) {
        queryClient.invalidateQueries({
          queryKey: ["folder-docs", updated.folder_id],
        });
      }
      setEditing(false);
    },
  });

  const deleteMutation = useMutation({
    mutationFn: () => deleteDoc(fetch, id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["docs"] });
      if (doc.data?.folder_id) {
        queryClient.invalidateQueries({
          queryKey: ["folder-docs", doc.data.folder_id],
        });
      }
      navigate("/docs");
    },
  });

  const handleEdit = () => {
    if (!doc.data) return;
    setTitleDraft(doc.data.title);
    setBodyDraft(doc.data.body ?? "");
    setEditing(true);
  };

  const handleSave = () => {
    patchMutation.mutate({
      title: titleDraft,
      body: bodyDraft,
    });
  };

  const handleDelete = () => {
    if (!confirm("Delete this document? This cannot be undone.")) return;
    deleteMutation.mutate();
  };

  if (doc.isLoading) {
    return <p className="text-sm text-gray-600">Loading…</p>;
  }
  if (doc.error) {
    return (
      <div className="rounded-lg border border-red-200 bg-red-50 p-4">
        <p className="text-sm text-red-800">
          Document not available (it may not exist, or you may not have
          permission to view it).
        </p>
      </div>
    );
  }
  if (!doc.data) return null;

  return (
    <article className="rounded-lg border border-gray-200 bg-white p-6">
      <header className="mb-6 border-b border-gray-200 pb-4">
        <div className="mb-2 flex items-start justify-between gap-4">
          {editing ? (
            <input
              className="flex-1 border-b border-gray-300 bg-transparent pb-1 text-xl font-semibold focus:border-blue-500 focus:outline-none"
              value={titleDraft}
              onChange={(e) => setTitleDraft(e.target.value)}
              autoFocus
            />
          ) : (
            <h1 className="text-xl font-semibold">{doc.data.title}</h1>
          )}
          <PermissionBadge permission={doc.data.permission} />
        </div>
        <p className="text-sm text-gray-500">
          Owner: <span className="font-mono">{doc.data.owner}</span> · Updated{" "}
          {new Date(doc.data.updated_at).toLocaleString()}
        </p>
      </header>

      {editing ? (
        <textarea
          className="min-h-[200px] w-full resize-y rounded border border-gray-300 p-2 font-sans focus:border-blue-500 focus:outline-none"
          value={bodyDraft}
          onChange={(e) => setBodyDraft(e.target.value)}
        />
      ) : (
        <div className="prose max-w-none whitespace-pre-wrap text-gray-900">
          {doc.data.body || (
            <span className="text-gray-400">(empty)</span>
          )}
        </div>
      )}

      <footer className="mt-6 flex gap-2 border-t border-gray-200 pt-4">
        {editing ? (
          <>
            <button
              onClick={handleSave}
              disabled={patchMutation.isPending}
              className="rounded bg-blue-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50"
            >
              {patchMutation.isPending ? "Saving…" : "Save"}
            </button>
            <button
              onClick={() => setEditing(false)}
              className="rounded border border-gray-300 px-4 py-1.5 text-sm hover:bg-gray-100"
            >
              Cancel
            </button>
          </>
        ) : (
          <>
            {canEdit(doc.data.permission) && (
              <button
                onClick={handleEdit}
                className="rounded border border-gray-300 px-4 py-1.5 text-sm hover:bg-gray-100"
              >
                Edit
              </button>
            )}
            {canDelete(doc.data.permission) && (
              <button
                onClick={handleDelete}
                disabled={deleteMutation.isPending}
                className="rounded border border-red-300 px-4 py-1.5 text-sm text-red-700 hover:bg-red-50 disabled:opacity-50"
              >
                {deleteMutation.isPending ? "Deleting…" : "Delete"}
              </button>
            )}
          </>
        )}
        {patchMutation.error && (
          <p className="ml-auto text-sm text-red-600">
            Save failed: {String(patchMutation.error)}
          </p>
        )}
        {deleteMutation.error && (
          <p className="ml-auto text-sm text-red-600">
            Delete failed: {String(deleteMutation.error)}
          </p>
        )}
      </footer>
    </article>
  );
}
