import { describe, expect, it } from "vitest";
import { reducer } from "@/components/ui/use-toast";
import type { ToastProps } from "@/components/ui/toast";

type TestToast = ToastProps & { id: string; title?: string };
const toast = (id: string, title = id): TestToast => ({ id, title, open: true });

describe("toast reducer", () => {
  it("adds, updates, and limits toast state", () => {
    let state = { toasts: [] as TestToast[] };
    for (let index = 0; index < 6; index += 1) {
      state = reducer(state, { type: "ADD_TOAST", toast: toast(String(index)) });
    }
    expect(state.toasts).toHaveLength(5);
    expect(state.toasts[0].id).toBe("5");

    state = reducer(state, { type: "UPDATE_TOAST", toast: { id: "3", title: "updated" } });
    expect(state.toasts.find((item) => item.id === "3")?.title).toBe("updated");
  });

  it("dismisses one or all toasts and removes them", () => {
    const initial = { toasts: [toast("one"), toast("two")] };
    const oneDismissed = reducer(initial, { type: "DISMISS_TOAST", toastId: "one" });
    expect(oneDismissed.toasts.find((item) => item.id === "one")?.open).toBe(false);
    expect(oneDismissed.toasts.find((item) => item.id === "two")?.open).toBe(true);

    const allDismissed = reducer(initial, { type: "DISMISS_TOAST" });
    expect(allDismissed.toasts.every((item) => item.open === false)).toBe(true);
    expect(reducer(initial, { type: "REMOVE_TOAST", toastId: "one" }).toasts).toHaveLength(1);
    expect(reducer(initial, { type: "REMOVE_TOAST" }).toasts).toEqual([]);
  });
});
