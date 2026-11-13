import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { AuthProvider } from "./auth";
import { HelpProvider } from "./help";
import App from "./App";
import { ErrorBoundary } from "./components/StatusScreen";
import "./index.css";

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: (n, err) => n < 2 && (err as { status?: number }).status !== 401, refetchOnWindowFocus: false } },
});

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ErrorBoundary>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <AuthProvider>
          <HelpProvider>
            <App />
          </HelpProvider>
        </AuthProvider>
      </BrowserRouter>
    </QueryClientProvider>
    </ErrorBoundary>
  </React.StrictMode>,
);
