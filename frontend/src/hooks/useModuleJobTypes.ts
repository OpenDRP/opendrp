import { useQuery } from "@tanstack/react-query";

import { fetchConnectorModules } from "@/lib/connectors";
import { FALLBACK_MODULE_JOB_TYPES } from "@/lib/labels";

export type ModuleKey = keyof typeof FALLBACK_MODULE_JOB_TYPES;

/**
 * Job types for a module page's history, as declared by its registered
 * connectors.
 *
 * The list comes from the connector registry rather than a hardcoded table, so
 * a connector introduced after this build appears without a frontend change.
 * While the registry loads — or if it is unreachable — the built-in defaults
 * keep the history populated instead of silently showing an empty table.
 */
export function useModuleJobTypes(module: ModuleKey): string[] {
  const { data } = useQuery({
    queryKey: ["connector-modules"],
    queryFn: fetchConnectorModules,
    staleTime: 60_000,
    retry: false,
  });

  const declared = data?.modules?.[module]?.job_types;
  if (declared && declared.length > 0) return declared;
  return [...FALLBACK_MODULE_JOB_TYPES[module]];
}
