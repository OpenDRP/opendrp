import { api } from "@/lib/api";
import type { FindingStatus, ModuleFinding } from "@/types/api";

/**
 * Move a finding of a declared module through triage.
 *
 * Only the status is sent: the payload is what the source reported, and the
 * core rejects any attempt to rewrite it.
 */
export function updateFindingStatus(
  findingId: string,
  status: FindingStatus
): Promise<ModuleFinding> {
  return api
    .patch<ModuleFinding>(`/findings/${encodeURIComponent(findingId)}`, { status })
    .then((r) => r.data);
}
