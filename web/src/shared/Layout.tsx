// Layout wraps authenticated pages with the top nav. Public pages
// (landing, callback) render without this wrapper.

import { Link, Outlet } from "react-router-dom";
import { useAuth } from "react-oidc-context";
import { useHasScope } from "../auth/useHasScope";

export function Layout() {
  const auth = useAuth();
  const isAdmin = useHasScope("admin");
  const email = auth.user?.profile.email ?? auth.user?.profile.sub ?? "";

  return (
    <div className="flex min-h-full flex-col bg-gray-50 text-gray-900">
      <header className="border-b border-gray-200 bg-white">
        <div className="mx-auto flex max-w-5xl items-center justify-between px-6 py-3">
          <div className="flex items-center gap-6">
            <Link to="/docs" className="font-semibold">
              docs
            </Link>
            {isAdmin && (
              <Link
                to="/admin"
                className="text-sm text-gray-600 hover:text-gray-900"
              >
                admin
              </Link>
            )}
          </div>
          <div className="flex items-center gap-4 text-sm">
            <span className="text-gray-600">{email}</span>
            <button
              onClick={() => auth.signoutRedirect()}
              className="rounded border border-gray-300 px-3 py-1 hover:bg-gray-100"
            >
              Sign out
            </button>
          </div>
        </div>
      </header>
      <main className="mx-auto w-full max-w-5xl flex-1 px-6 py-6">
        <Outlet />
      </main>
    </div>
  );
}
