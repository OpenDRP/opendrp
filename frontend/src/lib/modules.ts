/**
 * Module registry and generic findings.
 *
 * Modules are data on this platform: a module's label, its finding fields, its
 * deduplication and its headline are declared on the core, and the core stores
 * its findings generically. Reading the registry is what lets this frontend show
 * a data source it was never built against — its page, columns and navigation
 * entry come from the declaration, not from code here.
 */

import { api } from "@/lib/api";
import type {
  ModuleFinding,
  ModuleListResponse,
  Paginated,
  RegistryModule,
} from "@/types/api";

/** Every registered module, including disabled ones. */
export function fetchModules(): Promise<ModuleListResponse> {
  return api.get<ModuleListResponse>("/modules").then((r) => r.data);
}

/** One page of generically stored findings, newest first. */
export function fetchModuleFindings(
  module: string,
  page = 1,
  size = 20,
): Promise<Paginated<ModuleFinding>> {
  return api
    .get<Paginated<ModuleFinding>>("/findings", { params: { module, page, size } })
    .then((r) => r.data);
}

/** Rename, redescribe or enable/disable a module (fields are immutable). */
export function updateModule(
  moduleId: string,
  payload: { label?: string; description?: string; enabled?: boolean },
): Promise<RegistryModule> {
  return api
    .patch<RegistryModule>(`/modules/${moduleId}`, payload)
    .then((r) => r.data);
}

/**
 * Modules this frontend should render generically.
 *
 * A module stored on its own table has a dedicated page; everything else is
 * served by the registry-driven findings view.
 */
export function declaredModules(modules: RegistryModule[] | undefined) {
  return (modules || []).filter((m) => m.storage === "generic");
}
