// App shell. Two AuthProviders, one per route subtree:
//   • docs subtree (/, /docs/*) — client_id=localdev-docs, aud=docs-api
//   • admin subtree (/admin/*)  — client_id=localdev-admin, aud=idp-admin
//
// Each provider has its own namespaced sessionStorage prefix so concurrent
// PKCE/state/nonce don't collide. Components read the nearest provider via
// useAuth(); useAuthedFetch resolves the right token automatically.
//
// We swap providers on the fly based on location.pathname so navigation
// between /docs and /admin doesn't need a hard reload. /callback is
// rendered under whichever tree the user was in when they triggered
// signinRedirect — react-oidc-context resolves the right userManager via
// the prefixed sessionStorage entry it wrote at signinRedirect time.

import { AuthProvider } from "react-oidc-context";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  BrowserRouter,
  Routes,
  Route,
  useLocation,
} from "react-router-dom";

import { docsOidcConfig, adminOidcConfig } from "./auth/config";
import { RequireAuth } from "./auth/RequireAuth";
import { Layout } from "./shared/Layout";
import { Landing } from "./pages/Landing";
import { Callback } from "./pages/Callback";
import { DocsLayout } from "./docs/DocsLayout";
import { DocsIndex } from "./docs/DocsIndex";
import { DocDetail } from "./docs/DocDetail";
import { FolderView } from "./docs/FolderView";
import { AdminLayout } from "./admin/AdminLayout";
import { Dashboard } from "./admin/Dashboard";
import { UsersAdmin } from "./admin/UsersAdmin";
import { GroupsAdmin } from "./admin/GroupsAdmin";
import { ClientsAdmin } from "./admin/ClientsAdmin";
import { OutboxAdmin } from "./admin/OutboxAdmin";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

function DocsRoutes() {
  return (
    <Routes>
      <Route path="/" element={<Landing />} />
      <Route path="/callback" element={<Callback />} />
      <Route
        element={
          <RequireAuth>
            <Layout />
          </RequireAuth>
        }
      >
        <Route path="/docs" element={<DocsLayout />}>
          <Route index element={<DocsIndex />} />
          <Route path=":id" element={<DocDetail />} />
          <Route path="folders/:id" element={<FolderView />} />
        </Route>
      </Route>
    </Routes>
  );
}

function AdminRoutes() {
  return (
    <Routes>
      <Route path="/admin/callback" element={<Callback />} />
      <Route
        path="/admin"
        element={
          <RequireAuth>
            <Layout />
          </RequireAuth>
        }
      >
        <Route element={<AdminLayout />}>
          <Route index element={<Dashboard />} />
          <Route path="users" element={<UsersAdmin />} />
          <Route path="groups" element={<GroupsAdmin />} />
          <Route path="clients" element={<ClientsAdmin />} />
          <Route path="outbox" element={<OutboxAdmin />} />
        </Route>
      </Route>
    </Routes>
  );
}

// Picks an AuthProvider based on the current pathname. /callback inherits
// whichever tree the user was in (defaults to docs if pathname is /callback
// — react-oidc-context's stateStore lookup will key the response back to
// the right userManager regardless).
function ProvidedRoutes() {
  const { pathname } = useLocation();
  if (pathname.startsWith("/admin")) {
    return (
      <AuthProvider {...adminOidcConfig}>
        <AdminRoutes />
      </AuthProvider>
    );
  }
  return (
    <AuthProvider {...docsOidcConfig}>
      <DocsRoutes />
    </AuthProvider>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <ProvidedRoutes />
      </BrowserRouter>
    </QueryClientProvider>
  );
}

export default App;
