import type { Page } from "./types";

export type ConsoleNavigationState = {
  page: Page;
  from?: Page;
};

type HistoryState = Partial<ConsoleNavigationState> | null;

export type ConsoleNavigationTarget = {
  location: { hash: string };
  history: {
    state: unknown;
    pushState(data: unknown, unused: string, url?: string | URL | null): void;
    replaceState(data: unknown, unused: string, url?: string | URL | null): void;
  };
  addEventListener(type: "popstate", listener: () => void): void;
  removeEventListener(type: "popstate", listener: () => void): void;
};

const pages: ReadonlySet<Page> = new Set([
  "overview",
  "sessions",
  "threats",
  "policy",
  "network",
  "configuration",
  "system",
]);

export function isPage(value: unknown): value is Page {
  return typeof value === "string" && pages.has(value as Page);
}

export function pageHash(page: Page): string {
  return `#${page}`;
}

export function readConsoleNavigation(hash: string, rawState: unknown): ConsoleNavigationState {
  const hashPage = hash.replace(/^#\/?/, "");
  const state = rawState && typeof rawState === "object" ? rawState as HistoryState : null;
  const page = isPage(hashPage) ? hashPage : isPage(state?.page) ? state.page : "overview";
  const from = isPage(state?.from) ? state.from : undefined;
  return from ? { page, from } : { page };
}

export function replaceConsoleNavigation(target: ConsoleNavigationTarget, entry: ConsoleNavigationState): void {
  target.history.replaceState(entry, "", pageHash(entry.page));
}

export function pushConsoleNavigation(target: ConsoleNavigationTarget, page: Page, from?: Page): ConsoleNavigationState {
  const entry = from ? { page, from } : { page };
  target.history.pushState(entry, "", pageHash(page));
  return entry;
}

export function subscribeConsoleNavigation(
  target: ConsoleNavigationTarget,
  listener: (entry: ConsoleNavigationState) => void,
): () => void {
  const handlePopState = () => listener(readConsoleNavigation(target.location.hash, target.history.state));
  target.addEventListener("popstate", handlePopState);
  return () => target.removeEventListener("popstate", handlePopState);
}
