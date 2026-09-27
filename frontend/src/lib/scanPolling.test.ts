import { beforeEach, describe, expect, it, vi } from "vitest";
import { endpoints } from "@/lib/api";
import { summarizeScanJobs, waitForScanJobs } from "@/lib/scanPolling";

vi.mock("@/lib/api", () => ({
  endpoints: { getJob: vi.fn() },
}));

const getJob = endpoints.getJob as ReturnType<typeof vi.fn>;

const job = (id: string, status: "success" | "partial" | "error" | "running") => ({
  id,
  job_type: "phishing.dnstwist",
  status,
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
});

describe("scan polling", () => {
  beforeEach(() => getJob.mockReset());

  it("waits until every connector job is terminal", async () => {
    getJob
      .mockResolvedValueOnce(job("a", "running"))
      .mockResolvedValueOnce(job("b", "success"))
      .mockResolvedValueOnce(job("a", "partial"))
      .mockResolvedValueOnce(job("b", "success"));

    const result = await waitForScanJobs(["a", "b"], { intervalMs: 0, timeoutMs: 100 });
    expect(result.map((item) => item.status)).toEqual(["partial", "success"]);
    expect(getJob).toHaveBeenCalledTimes(4);
  });

  it("does not turn a timed-out running job into a false success", async () => {
    getJob.mockResolvedValue(job("a", "running"));
    const result = await waitForScanJobs(["a"], { intervalMs: 1, timeoutMs: 5 });
    expect(result[0].status).toBe("running");
  });

  it("distinguishes partial, failed, and still-running sources", () => {
    expect(summarizeScanJobs([
      job("a", "success"),
      job("b", "partial"),
      job("c", "error"),
      job("d", "running"),
    ])).toEqual({ succeeded: 1, failed: 1, pending: 1 });
  });
});
