import { endpoints } from "@/lib/api";
import type { Job } from "@/types/api";

const TERMINAL = new Set(["success", "partial", "error", "cancelled", "skipped"]);

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

/**
 * Wait for connector jobs without keeping a mutation open indefinitely.
 * The API is the source of truth; a browser disappearing cannot cancel the scan.
 */
export async function waitForScanJobs(
  jobIds: string[],
  options: { timeoutMs?: number; intervalMs?: number } = {},
): Promise<Job[]> {
  const timeoutMs = options.timeoutMs ?? 5 * 60_000;
  // Keeps lightweight test doubles and older embedded clients usable while the
  // production API always exposes getJob.
  if (typeof endpoints.getJob !== "function") return [];
  const intervalMs = options.intervalMs ?? 2_000;
  const started = Date.now();
  const latest = new Map<string, Job>();

  while (Date.now() - started <= timeoutMs) {
    const results = await Promise.allSettled(jobIds.map((id) => endpoints.getJob(id)));
    for (const result of results) {
      if (result.status === "fulfilled") latest.set(result.value.id, result.value);
    }
    const jobs = jobIds.map((id) => latest.get(id)).filter((job): job is Job => Boolean(job));
    if (jobs.length === jobIds.length && jobs.every((job) => TERMINAL.has(job.status))) return jobs;
    await delay(intervalMs);
  }
  return jobIds.map((id) => latest.get(id)).filter((job): job is Job => Boolean(job));
}

export function summarizeScanJobs(jobs: Job[]): { succeeded: number; failed: number; pending: number } {
  return {
    succeeded: jobs.filter((job) => job.status === "success").length,
    failed: jobs.filter((job) => ["error", "cancelled", "skipped"].includes(job.status)).length,
    pending: jobs.filter((job) => !TERMINAL.has(job.status)).length,
  };
}
