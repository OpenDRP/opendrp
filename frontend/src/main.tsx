import React from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { TooltipProvider } from "@/components/ui/tooltip";
import { Toaster } from "@/components/ui/toaster";
import { ThemeProvider } from "@/components/Theme/ThemeProvider";
import { ErrorBoundary } from "@/components/ErrorBoundary";
import App from "./App";
import { useAuthStore } from "@/store/auth";
import { canonicalNavigationUrl } from "@/lib/canonicalOrigin";
import "./index.css";

const canonicalOrigin = String(import.meta.env.VITE_CANONICAL_ORIGIN || "");
const canonicalUrl = canonicalNavigationUrl(window.location, canonicalOrigin);
if (canonicalUrl) {
  // A stale bookmark or an unrelated service on port 80 must not leave the SPA
  // talking to the wrong origin. Keep path/query/hash when moving to the one
  // configured browser origin; production leaves this build value empty.
  window.location.replace(canonicalUrl);
}

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      refetchOnWindowFocus: false,
      retry: 1,
    },
  },
});

// Ask the API whether this browser has a session — once, before the first render.
//
// Deliberately a call and not a side effect of importing the store. The store used
// to restore the session from a `persist` rehydration callback, which runs while the
// module graph is still being evaluated; that is exactly the moment when a cycle
// between two modules can hand the running code a binding that does not exist yet
// (`lib/session-bridge.ts` describes the failure at length). Here the app boots the
// same way in development and in the production bundle. Until the answer arrives
// the router waits on `isHydrated` and shows "Loading session...", rather than
// flashing a sign-in form at somebody who is signed in.
void useAuthStore.getState().restoreSession();

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ThemeProvider defaultTheme="light" storageKey="opendrp-ui-theme">
      <QueryClientProvider client={queryClient}>
        <TooltipProvider delayDuration={150}>
          <BrowserRouter>
            <ErrorBoundary>
              <App />
              <Toaster />
            </ErrorBoundary>
          </BrowserRouter>
        </TooltipProvider>
      </QueryClientProvider>
    </ThemeProvider>
  </React.StrictMode>,
);
