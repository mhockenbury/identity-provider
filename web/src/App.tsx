// App shell: wires up the three providers (auth, query, router) that
// every page depends on.
//
// Order matters: AuthProvider at the top so children can call useAuth;
// QueryClientProvider wraps it so queries can read tokens; Router
// last so route components see both.

import { AuthProvider } from "react-oidc-context";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";

import { oidcConfig } from "./auth/config";
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

// Single QueryClient for the app. Defaults are fine for now; we'll
// tune staleTime per query where it matters.
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

function App() {
  return (
    <AuthProvider {...oidcConfig}>
      <QueryClientProvider client={queryClient}>
        <BrowserRouter>
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
              <Route path="/admin" element={<AdminLayout />}>
                <Route index element={<Dashboard />} />
                <Route path="users" element={<UsersAdmin />} />
                <Route path="groups" element={<GroupsAdmin />} />
                <Route path="clients" element={<ClientsAdmin />} />
                <Route path="outbox" element={<OutboxAdmin />} />
              </Route>
            </Route>
          </Routes>
        </BrowserRouter>
      </QueryClientProvider>
    </AuthProvider>
  );
}

export default App;
