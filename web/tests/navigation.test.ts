import assert from "node:assert/strict";
import test from "node:test";
import {
  pushConsoleNavigation,
  readConsoleNavigation,
  subscribeConsoleNavigation,
  type ConsoleNavigationState,
  type ConsoleNavigationTarget,
} from "../src/navigation.ts";

function fakeNavigation(initial: ConsoleNavigationState): ConsoleNavigationTarget & { dispatchPopState(): void } {
  const listeners = new Set<() => void>();
  const target = {
    location: { hash: `#${initial.page}` },
    history: {
      state: initial as unknown,
      pushState(data: unknown, _unused: string, url?: string | URL | null) {
        this.state = data;
        target.location.hash = String(url ?? "");
      },
      replaceState(data: unknown, _unused: string, url?: string | URL | null) {
        this.state = data;
        target.location.hash = String(url ?? "");
      },
    },
    addEventListener(_type: "popstate", listener: () => void) { listeners.add(listener); },
    removeEventListener(_type: "popstate", listener: () => void) { listeners.delete(listener); },
    dispatchPopState() { listeners.forEach((listener) => listener()); },
  } satisfies ConsoleNavigationTarget & { dispatchPopState(): void };
  return target;
}

test("advanced editor history remembers Policy as its origin", () => {
  const target = fakeNavigation({ page: "policy" });
  const entry = pushConsoleNavigation(target, "configuration", "policy");
  assert.deepEqual(entry, { page: "configuration", from: "policy" });
  assert.equal(target.location.hash, "#configuration");
  assert.deepEqual(readConsoleNavigation(target.location.hash, target.history.state), entry);
});

test("popstate restores the page so browser Back returns to Policy", () => {
  const target = fakeNavigation({ page: "configuration", from: "policy" });
  let current: ConsoleNavigationState | undefined;
  const unsubscribe = subscribeConsoleNavigation(target, (entry) => { current = entry; });

  target.location.hash = "#policy";
  target.history.state = { page: "policy" };
  target.dispatchPopState();

  assert.deepEqual(current, { page: "policy" });
  unsubscribe();
});
