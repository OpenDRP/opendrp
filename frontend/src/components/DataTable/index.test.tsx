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
    await user.click(screen.getByRole("button", { name: /^Sort by Name/ }));
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

  /**
   * The state a delete on the last page leaves behind: 15 rows over two pages, the
   * operator on page 2, and the row they removed was the only one there. The
   * server answers an empty page, so the table has to ask for the page that now
   * exists — otherwise it reports "nothing matches" about 14 matching rows and
   * prints a range that runs backwards ("16–15 of 15").
   */
  it("asks to move off a page the result no longer has", () => {
    const onPageChange = vi.fn();
    renderTable({ page: 3, pageSize: 10, total: 15, rows: [], onPageChange });

    expect(onPageChange).toHaveBeenCalledWith(2);
  });

  /**
   * The table used to report its own state only to the eye: an arrow beside the
   * sorted column, a width that changed while a handle was focused, a page number
   * drawn in a different colour. `aria-sort` described the `<th>`, which is not
   * where focus is, so activating the sort button announced nothing; the resize
   * handle was a focusable `separator` with no value, so the arrow keys changed a
   * number nobody could hear; and the current page was only a fill.
   */
  it("names the direction it is showing, and announces the one it applied", async () => {
    const user = userEvent.setup();
    const onSortChange = vi.fn();
    renderTable({
      columns: [{ ...columns[0], sortable: true }, columns[1]],
      sort: { field: "name", direction: "asc" },
      onSortChange,
    });

    expect(
      screen.getByRole("button", { name: "Sort by Name, currently ascending" }),
    ).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /^Sort by Name/ }));
    expect(screen.getByRole("status")).toHaveTextContent("Sorted by Name, descending.");
  });

  it("gives a resize handle a value, so the arrow keys are not silent", async () => {
    const user = userEvent.setup();
    renderTable();

    const handle = screen.getByRole("separator", { name: "Resize Name column" });
    expect(handle).toHaveAttribute("aria-orientation", "vertical");
    expect(handle).toHaveAttribute("aria-valuenow", "120");
    expect(handle).toHaveAttribute("aria-valuemin", "80");
    expect(handle).toHaveAttribute("aria-valuemax", "640");
    expect(handle).toHaveAttribute("aria-valuetext", "120 pixels");

    handle.focus();
    await user.keyboard("{ArrowRight}");
    expect(screen.getByRole("separator", { name: "Resize Name column" })).toHaveAttribute(
      "aria-valuenow",
      "136",
    );
  });

  it("marks the page it is showing", () => {
    renderTable();
    expect(screen.getByRole("button", { name: "1" })).toHaveAttribute("aria-current", "page");
    expect(screen.getByRole("button", { name: "2" })).not.toHaveAttribute("aria-current");
  });

  it("reaches every control in the table with the keyboard alone", async () => {
    const user = userEvent.setup();
    renderTable({
      columns: [{ ...columns[0], sortable: true }, { ...columns[1], sortable: true }],
      sort: null,
      onSortChange: vi.fn(),
    });

    // Header controls in reading order: the sort button, then the handle of the
    // same column, twice. No click and no pointer event is involved.
    await user.tab();
    expect(screen.getByRole("button", { name: "Sort by Name" })).toHaveFocus();
    await user.tab();
    expect(screen.getByRole("separator", { name: "Resize Name column" })).toHaveFocus();
    await user.tab();
    expect(screen.getByRole("button", { name: "Sort by Status" })).toHaveFocus();
    await user.tab();
    expect(screen.getByRole("separator", { name: "Resize Status column" })).toHaveFocus();
    await user.tab();
    expect(screen.getByRole("combobox", { name: "Items per page" })).toHaveFocus();
    // First and Previous are disabled on page 1, so the page buttons are the next
    // stops and the footer is reachable without a pointer.
    await user.tab();
    expect(screen.getByRole("button", { name: "1" })).toHaveFocus();
    await user.tab();
    expect(screen.getByRole("button", { name: "2" })).toHaveFocus();
  });
});
