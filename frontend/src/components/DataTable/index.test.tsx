import { fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { PaginatedDataTable, type DataTableColumn } from "@/components/DataTable";

type TestRow = { id: string; name: string; status: string };

const columns: DataTableColumn<TestRow>[] = [
  { key: "name", title: "Name", width: 120, minWidth: 80, render: (row) => row.name },
  { key: "status", title: "Status", render: (row) => row.status },
];

const rows: TestRow[] = [{ id: "row-1", name: "Example", status: "Active" }];

function renderTable(overrides: Partial<React.ComponentProps<typeof PaginatedDataTable<TestRow>>> = {}) {
  return render(
    <PaginatedDataTable<TestRow>
      columns={columns}
      rows={rows}
      total={21}
      page={1}
      pageSize={10}
      onPageChange={vi.fn()}
      onPageSizeChange={vi.fn()}
      storageKey="test-table"
      {...overrides}
    />,
  );
}

describe("PaginatedDataTable", () => {
  beforeEach(() => localStorage.clear());

  it("renders rows, metadata, and stable row attributes", () => {
    const { container } = renderTable({ getRowId: (row) => `stable-${row.id}`, getRowClassName: () => "highlight" });
    expect(screen.getByRole("table", { name: "Data table" })).toBeInTheDocument();
    expect(screen.getByText("Example")).toBeInTheDocument();
    expect(container.textContent).toContain("Showing");
    expect(container.textContent).toContain("1–10");
    expect(container.textContent).toContain("21");
    expect(document.getElementById("stable-row-1")).toHaveClass("highlight");
  });

  it("renders an empty state and initial skeletons", () => {
    const { rerender } = renderTable({ rows: [], total: 0, emptyText: "Nothing here" });
    expect(screen.getByText("Nothing here")).toBeInTheDocument();

    rerender(
      <PaginatedDataTable
        columns={columns}
        rows={[]}
        total={0}
        page={1}
        pageSize={10}
        onPageChange={vi.fn()}
        onPageSizeChange={vi.fn()}
        storageKey="test-table-loading"
        loading
        skeletonRows={2}
      />,
    );
    expect(screen.queryByText("Nothing here")).not.toBeInTheDocument();
    expect(document.querySelectorAll(".animate-pulse").length).toBeGreaterThan(0);
  });

  it("replaces an empty result set with an explicit error state on failure", () => {
    const onRetry = vi.fn();
    renderTable({ rows: [], total: 0, isError: true, onRetry });

    // A failed request must not read as "nothing found".
    expect(screen.getByText("Could not load this list")).toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(onRetry).toHaveBeenCalledOnce();
  });

  it("keeps already loaded rows visible when a background refresh fails", () => {
    renderTable({ isError: true });
    expect(screen.getByRole("table", { name: "Data table" })).toBeInTheDocument();
    expect(screen.getByText("Example")).toBeInTheDocument();
  });

  it("names every pagination control for assistive technology", () => {
    renderTable();
    expect(screen.getByRole("button", { name: "First page" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Previous page" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Next page" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Last page" })).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Items per page" })).toBeInTheDocument();
  });

  it("changes page through navigation and resizes a column with the keyboard", async () => {
    const user = userEvent.setup();
    const onPageChange = vi.fn();
    renderTable({ onPageChange });

    await user.click(screen.getByRole("button", { name: "2" }));
    expect(onPageChange).toHaveBeenCalledWith(2);

    const separator = screen.getByRole("separator", { name: "Resize Name column" });
    separator.focus();
    await user.keyboard("{ArrowRight}");
    expect(localStorage.getItem("test-table")).toContain("136");
  });
});
