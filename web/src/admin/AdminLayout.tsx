// Admin section shell. Sub-nav across the top; child route renders below.
// Gated by admin scope: non-admins see a friendly "you don't have access"
// page instead of a 403 from the API.

import { NavLink, Outlet } from "react-router-dom";
import { useHasScope } from "../auth/useHasScope";

export function AdminLayout() {
  const isAdmin = useHasScope("admin");

  if (!isAdmin) {
    return (
      <div className="rounded-lg border border-yellow-200 bg-yellow-50 p-6">
        <h1 className="text-xl font-semibold text-yellow-900">
          Admin access required
        </h1>
        <p className="mt-2 text-sm text-yellow-900">
          Your token does not include the <code>admin</code> scope. If you
          believe you should have access, ask another admin to promote your
          account, then sign out and back in.
        </p>
      </div>
    );
  }

  const tab = "rounded px-3 py-1.5 text-sm hover:bg-gray-100";
  const tabActive = "bg-blue-100 font-medium text-blue-900";
  const linkClass = ({ isActive }: Readonly<{isActive: boolean}>) =>
    `${tab} ${isActive ? tabActive : "text-gray-700"}`;

  return (
    <div className="space-y-6">
      <nav className="flex items-center gap-2 border-b border-gray-200 pb-3">
        <NavLink to="/admin" end className={linkClass}>
          Dashboard
        </NavLink>
        <NavLink to="/admin/users" className={linkClass}>
          Users
        </NavLink>
        <NavLink to="/admin/groups" className={linkClass}>
          Groups
        </NavLink>
        <NavLink to="/admin/clients" className={linkClass}>
          Clients
        </NavLink>
        <NavLink to="/admin/outbox" className={linkClass}>
          Outbox
        </NavLink>
      </nav>
      <Outlet />
    </div>
  );
}
