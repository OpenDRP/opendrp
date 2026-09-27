import { useQuery } from "@tanstack/react-query";

import { fetchModules } from "@/lib/modules";

/**
 * The module registry.
 *
 * Navigation, the per-module page and the settings list all read the same query,
 * so declaring a module on the core makes it appear everywhere at once — no
 * frontend change, which is the point of modules being data.
 */
export function useModules() {
  return useQuery({
    queryKey: ["modules"],
    queryFn: fetchModules,
    staleTime: 60_000,
    retry: false,
  });
}
