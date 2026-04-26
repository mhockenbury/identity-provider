// Groups admin: list + create + per-group member management.
// Selecting a group opens an inline panel with its members.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import {
  type AdminGroup,
  addGroupMember,
  createGroup,
  listGroupMembers,
  listGroups,
  removeGroupMember,
} from "./api";
import { useAuthedFetch } from "../auth/useAuthedFetch";

export function GroupsAdmin() {
  const fetch = useAuthedFetch();
  const list = useQuery({
    queryKey: ["admin", "groups"],
    queryFn: () => listGroups(fetch),
  });
  const [selected, setSelected] = useState<AdminGroup | null>(null);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">Groups</h1>
        <CreateGroupForm />
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-[300px_1fr]">
        <aside>
          {list.isLoading && (
            <p className="text-sm text-gray-600">Loading…</p>
          )}
          {list.error && (
            <p className="text-sm text-red-600">Error: {String(list.error)}</p>
          )}
          {list.data && list.data.length === 0 && (
            <p className="text-sm text-gray-600">No groups yet.</p>
          )}
          {list.data && list.data.length > 0 && (
            <ul className="divide-y divide-gray-200 rounded-lg border border-gray-200 bg-white">
              {list.data.map((g) => (
                <li key={g.id}>
                  <button
                    onClick={() => setSelected(g)}
                    className={`block w-full px-3 py-2 text-left text-sm hover:bg-gray-50 ${
                      selected?.id === g.id
                        ? "bg-blue-50 font-medium text-blue-900"
                        : "text-gray-900"
                    }`}
                  >
                    {g.name}
                  </button>
                </li>
              ))}
            </ul>
          )}
        </aside>
        <div>
          {selected ? (
            <GroupMembers group={selected} />
          ) : (
            <div className="rounded-lg border border-dashed border-gray-300 p-8 text-center text-sm text-gray-500">
              Select a group to manage its members.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function CreateGroupForm() {
  const fetch = useAuthedFetch();
  const queryClient = useQueryClient();
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");

  const create = useMutation({
    mutationFn: () => createGroup(fetch, name),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["admin", "groups"] });
      setName("");
      setOpen(false);
    },
  });

  if (!open) {
    return (
      <button
        onClick={() => setOpen(true)}
        className="rounded bg-blue-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-blue-700"
      >
        Create group
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
        required
        placeholder="group name"
        value={name}
        onChange={(e) => setName(e.target.value)}
        className="rounded border border-gray-300 px-2 py-1 text-sm"
      />
      <button
        type="submit"
        disabled={create.isPending}
        className="rounded bg-blue-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50"
      >
        Save
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

function GroupMembers({ group }: Readonly<{group: AdminGroup}>) {
  const fetch = useAuthedFetch();
  const queryClient = useQueryClient();
  const [newUser, setNewUser] = useState("");

  const members = useQuery({
    queryKey: ["admin", "groups", group.name, "members"],
    queryFn: () => listGroupMembers(fetch, group.name),
  });

  const add = useMutation({
    mutationFn: () => addGroupMember(fetch, group.name, newUser),
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["admin", "groups", group.name, "members"],
      });
      setNewUser("");
    },
  });

  const remove = useMutation({
    mutationFn: (userID: string) => removeGroupMember(fetch, group.name, userID),
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["admin", "groups", group.name, "members"],
      });
    },
  });

  return (
    <section className="rounded-lg border border-gray-200 bg-white p-4">
      <header className="mb-3 flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold">{group.name}</h2>
          <p className="text-xs text-gray-500">{group.id}</p>
        </div>
      </header>

      <form
        onSubmit={(e) => {
          e.preventDefault();
          add.mutate();
        }}
        className="mb-4 flex items-center gap-2"
      >
        <input
          required
          placeholder="email or user UUID"
          value={newUser}
          onChange={(e) => setNewUser(e.target.value)}
          className="flex-1 rounded border border-gray-300 px-2 py-1 text-sm"
        />
        <button
          type="submit"
          disabled={add.isPending}
          className="rounded bg-blue-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-50"
        >
          {add.isPending ? "Adding…" : "Add member"}
        </button>
      </form>
      {add.error && (
        <p className="mb-3 text-sm text-red-600">
          Add failed: {String(add.error)}
        </p>
      )}

      {members.isLoading && <p className="text-sm text-gray-600">Loading…</p>}
      {members.error && (
        <p className="text-sm text-red-600">Error: {String(members.error)}</p>
      )}
      {members.data && members.data.length === 0 && (
        <p className="text-sm text-gray-600">No members.</p>
      )}
      {members.data && members.data.length > 0 && (
        <ul className="divide-y divide-gray-100">
          {members.data.map((u) => (
            <li
              key={u.id}
              className="flex items-center justify-between py-2 text-sm"
            >
              <div>
                <p className="font-medium text-gray-900">{u.email}</p>
                <p className="text-xs text-gray-500">{u.id}</p>
              </div>
              <button
                onClick={() => remove.mutate(u.id)}
                disabled={remove.isPending}
                className="rounded border border-red-300 px-2 py-1 text-xs text-red-700 hover:bg-red-50 disabled:opacity-40"
              >
                Remove
              </button>
            </li>
          ))}
        </ul>
      )}
      {remove.error && (
        <p className="mt-3 text-sm text-red-600">
          Remove failed: {String(remove.error)}
        </p>
      )}
    </section>
  );
}
