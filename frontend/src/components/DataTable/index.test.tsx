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

  it("uses the supplied identity for RRset members across refreshes", () => {
    const error = vi.spyOn(console, "error");
    const members = ["one", "two"].map(name => ({ id: "rrset", name, status: "Active" }));
    const props = { columns, rows: members, total: 2, page: 1, pageSize: 10, onPageChange: vi.fn(), onPageSizeChange: vi.fn(), storageKey: "members", getRowId: (row: TestRow) => `${row.id}:${row.name}` };
    const { rerender } = render(<PaginatedDataTable {...props} />);
    expect(document.getElementById("rrset:one")).toHaveTextContent("one");
    expect(document.getElementById("rrset:two")).toHaveTextContent("two");
    rerender(<PaginatedDataTable {...props} rows={[members[1]]} total={1} />);
    expect(document.getElementById("rrset:one")).not.toBeInTheDocument();
    expect(document.getElementById("rrset:two")).toHaveTextContent("two");
    expect(error).not.toHaveBeenCalled();
    error.mockRestore();
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

  it("offers only page sizes the API accepts, and still shows a client-side one as All", () => {
    // The control used to end at `10000` while every list endpoint bounded `size`
    // at 200: picking that option answered HTTP 422 and replaced the table with an
    // error state. A size larger than the bound is still *shown* when a caller
    // hands the table rows it already holds, but it is never one of the sizes the
    // control offers.
    const apiPage = renderTable({ pageSize: 200, total: 400 });
    expect(screen.getByRole("combobox", { name: "Items per page" })).toHaveTextContent("200");
    apiPage.unmount();

    renderTable({ rows, total: 5, page: 1, pageSize: 10000 });
    expect(screen.getByRole("combobox", { name: "Items per page" })).toHaveTextContent("All");
  });

  it("counts a client-side page as one page without special-casing its size", () => {
    // `pages` used to be computed with `pageSize === 10000` spelled out, so any
    // other client-side size would have produced an empty page list.
    renderTable({ rows, total: 5, page: 1, pageSize: 10000 });
    expect(screen.getByRole("button", { name: "1" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "2" })).not.toBeInTheDocument();
  });

  it("names every pagination control for assistive technology", () => {
    renderTable();
    expect(screen.getByRole("button", { name: "First page" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Previous page" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Next page" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Last page" })).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Items per page" })).toBeInTheDocument();
  });

  it("turns a sortable header into a button that reports the field (AWI-04)", async () => {
    const user = userEvent.setup();
    const onSortChange = vi.fn();
    renderTable({
      columns: [{ ...columns[0], sortable: true }, columns[1]],
      sort: { field: "name", direction: "asc" },
      onSortChange,
    });

    // A sorted column says so to assistive technology, and the next click on it
    // reverses the direction rather than starting over.
    expect(screen.getByRole("columnheader", { name: /Name/ })).toHaveAttribute("aria-sort", "ascending");
    await user.click(screen.getByRole("button", { name: "Sort by Name" }));
    expect(onSortChange).toHaveBeenCalledWith({ field: "name", direction: "desc" });
  });

  it("reports the ticked rows without owning the selection (AWI-11)", async () => {
    const user = userEvent.setup();
    const onSelectedChange = vi.fn();
    renderTable({
      selectable: true,
      selectedIds: [],
      onSelectedChange,
      getRowId: (row) => row.id,
      getRowLabel: (row) => row.name,
    });

    await user.click(screen.getByRole("checkbox", { name: "Select Example" }));
    expect(onSelectedChange).toHaveBeenCalledWith(["row-1"]);
  });

  it("selects and clears every row on the page from the header (AWI-11)", async () => {
    const user = userEvent.setup();
    const onSelectedChange = vi.fn();
    const props = {
      selectable: true,
      onSelectedChange,
      getRowId: (row: TestRow) => row.id,
      getRowLabel: (row: TestRow) => row.name,
    };
    const { rerender } = renderTable({ ...props, selectedIds: [] });

    await user.click(screen.getByRole("checkbox", { name: "Select all rows on this page" }));
    expect(onSelectedChange).toHaveBeenCalledWith(["row-1"]);

    // The header is checked only for a full page, and clearing forwards the ids
    // that stay selected rather than an empty array that erases another page.
    rerender(
      <PaginatedDataTable
        columns={columns}
        rows={rows}
        total={1}
        page={1}
        pageSize={10}
        onPageChange={vi.fn()}
        onPageSizeChange={vi.fn()}
        storageKey="test-table"
        selectedIds={["row-1"]}
        {...props}
      />,
    );
    expect(screen.getByRole("checkbox", { name: "Select all rows on this page" })).toBeChecked();
    await user.click(screen.getByRole("checkbox", { name: "Select all rows on this page" }));
    expect(onSelectedChange).toHaveBeenLastCalledWith([]);
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
