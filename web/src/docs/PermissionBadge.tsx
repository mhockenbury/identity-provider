// Tiny badge that shows what permission the user has. Three colors so
// it's glanceable: owner=green, editor=blue, viewer=gray.

import type { Permission } from "./api";

const styles: Record<Permission, string> = {
  owner: "bg-green-100 text-green-800 ring-green-200",
  editor: "bg-blue-100 text-blue-800 ring-blue-200",
  viewer: "bg-gray-100 text-gray-700 ring-gray-200",
};

export function PermissionBadge({ permission }: { permission: Permission }) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset ${styles[permission]}`}
    >
      {permission}
    </span>
  );
}
