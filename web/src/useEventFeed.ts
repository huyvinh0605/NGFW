import { useCallback, useEffect, useRef, useState } from "react";
import { api, APIError, errorMessage } from "./api";
import { normalizeEvent } from "./runtimeData";
import { normalizeThreatEvent, normalizeThreatEventPageData } from "./inspectionData";
import { eventKey, FEED_LIMIT, mergeEvents, record, requestPage, runtimePage, text, type EventFeed, type FeedStatus } from "./eventData";
import { authenticatedSocketProtocols, closeSocketAfterOpen, INITIAL_WEBSOCKET_DIAL_DELAY_MS, reconnectDelay } from "./wsLifecycle";
import type { SecurityEvent } from "./types";

export type EventMonitor = {
  events: SecurityEvent[];
  sources: Record<EventFeed, FeedStatus>;
  loading: boolean;
  refresh: () => Promise<void>;
};
const emptySources = (): EventMonitor["sources"] => ({ runtime: {}, security: {}, request: {} });

/** One owner for REST cursors + WS. Display pause is deliberately independent of ingestion. */
export function useEventFeed(token: string): EventMonitor {
  const [state, setState] = useState({ owner: token, events: [] as SecurityEvent[], sources: emptySources(), loading: false });
  const refreshRef = useRef<() => Promise<void>>(async () => {});
  useEffect(() => {
    let stopped = false, busy = false, after = "0", runtimeStream = "", securityCursor = "", securityStream = "", requestAfter = "0", attempt = 0, epoch = 0;
    let socket: WebSocket | undefined;
    const abort = new AbortController(), timers = new Set<number>(), revisions = new Set<string>(), retry = new Map<string, number>();
    const pending = new Map<string, SecurityEvent>(), retiredRuntime = new Set<string>();
    let flushTimer: number | undefined;
    setState({ owner: token, events: [], sources: emptySources(), loading: false });
    const schedule = (fn: () => void, ms: number) => {
      const id = window.setTimeout(() => { timers.delete(id); if (!stopped) fn(); }, ms);
      timers.add(id); return id;
    };
    const status = (feed: EventFeed, patch: FeedStatus) => {
      if (!stopped) setState(s => ({ ...s, sources: { ...s.sources, [feed]: { ...s.sources[feed], ...patch } } }));
    };
    const ingest = (items: SecurityEvent[], reset?: EventFeed) => {
      if (!stopped) setState(s => ({ ...s, events: mergeEvents(s.events, items, reset) }));
    };
    const changeRuntimeStream = (next: string) => {
      if (!next || retiredRuntime.has(next)) return false;
      if (runtimeStream && runtimeStream !== next) {
        retiredRuntime.add(runtimeStream);
        if (retiredRuntime.size > 8) retiredRuntime.delete(retiredRuntime.values().next().value!);
        epoch++; pending.clear(); after = "0"; ingest([], "runtime");
        requestAfter = "0"; ingest([], "request"); status("request", { gap: true });
        status("runtime", { gap: true });
      }
      runtimeStream = next; return true;
    };
    const read = (path: string) => api<unknown>(path, { signal: abort.signal }, token);
    const poll = async () => {
      if (stopped || busy) return;
      busy = true; setState(s => ({ ...s, loading: true }));
      const runtimeAfter = after;
      const requestEpoch = epoch;
      const paths = [
        `/api/v1/events?after=${runtimeAfter}&limit=200`,
        `/api/v1/security/events?limit=200${securityCursor ? `&cursor=${encodeURIComponent(securityCursor)}` : ""}`,
        `/api/v1/request-gate/evidence?after_sequence=${requestAfter}&limit=128`,
      ];
      try {
        const results = await Promise.allSettled(paths.map(read));
        if (stopped) return;
        const feeds: EventFeed[] = ["runtime", "security", "request"];
        results.forEach((result, i) => {
          const feed = feeds[i];
          try {
            if (result.status === "rejected") throw result.reason;
            const updated = new Date().toISOString();
            if (feed === "runtime") {
              const page = runtimePage(result.value);
              if (page.stream && !changeRuntimeStream(page.stream)) return;
              // A stream switch can require a second read from zero. Never use the old cursor on the new stream.
              if (runtimeAfter !== "0" && after === "0" && runtimeStream === page.stream) return;
              after = page.last ?? after;
              ingest(page.items);
              status(feed, { updated, error: undefined, hasMore: page.hasMore, stream: runtimeStream, ...(page.gap ? { gap: true } : {}) });
            } else if (feed === "security") {
              const raw = record(result.value);
              if (!Array.isArray(raw.items)) throw new Error("Security trả danh sách không hợp lệ");
              const page = normalizeThreatEventPageData(raw);
              const reset = Boolean(page.reset_required || securityStream && page.stream_id !== securityStream);
              securityStream = page.stream_id; securityCursor = page.next_cursor;
              ingest(page.items.map(e => ({ ...e, stream_id: securityStream })), reset ? "security" : undefined);
              status(feed, { updated, error: undefined, hasMore: page.has_more, stream: securityStream, evicted: page.evicted_count, ...(page.gap || reset ? { gap: true } : {}) });
            } else {
              if (requestEpoch !== epoch) return;
              const page = requestPage(result.value);
              requestAfter = page.next;
              ingest(page.items);
              status(feed, { updated, error: undefined, hasMore: page.hasMore });
            }
          } catch (error) { status(feed, { error: errorMessage(error) }); }
        });
        // M3 correlation updates keep their original sequence. Re-read references instead of expecting the cursor to advance.
        const ids = [...revisions].slice(0, 8); ids.forEach(id => revisions.delete(id));
        await Promise.all(ids.map(async id => {
          try {
            const stream = securityStream;
            const value = await read(`/api/v1/security/events/${encodeURIComponent(id)}`);
            const event = normalizeThreatEvent(value);
            retry.delete(id);
            if (!stopped && stream === securityStream && event) ingest([{ ...event, stream_id: stream }]);
          } catch (error) {
            if (!(error instanceof APIError && error.status === 404)) {
              status("security", { error: errorMessage(error) });
              const count = (retry.get(id) ?? 0) + 1;
              retry.set(id, count);
              if (count < 3 && revisions.size < 200) revisions.add(id);
              else retry.delete(id);
            } else retry.delete(id);
          }
        }));
      } finally {
        busy = false;
        if (!stopped) setState(s => ({ ...s, loading: false }));
      }
    };
    refreshRef.current = poll;
    const connect = () => {
      if (!token || stopped) return;
      const scheme = window.location.protocol === "https:" ? "wss" : "ws";
      socket = new WebSocket(`${scheme}://${window.location.host}/ws/events`, authenticatedSocketProtocols(token));
      socket.onopen = () => { attempt = 0; if (stopped && socket) closeSocketAfterOpen(socket); };
      socket.onerror = () => {};
      socket.onclose = () => { if (!stopped) schedule(connect, reconnectDelay(attempt++)); };
      socket.onmessage = message => {
        if (stopped) return;
        try {
          const envelope = record(JSON.parse(String(message.data)));
          if (envelope.success !== true) { status("runtime", { error: "WebSocket runtime không cung cấp dữ liệu" }); return; }
          const stream = text(envelope.stream_id);
          if (stream && !changeRuntimeStream(stream)) return;
          if (["gap", "stream_reset"].includes(text(envelope.type))) { status("runtime", { gap: true }); void poll(); return; }
          if (envelope.type === "heartbeat") return;
          const event = normalizeEvent(envelope.data);
          if (!event) return;
          const related = text(event.metadata?.related_event_id);
          if (event.category === "SecurityEventUpdated" && related && revisions.size < 200) revisions.add(related);
          const row = { ...event, feed: "runtime" as const, stream_id: stream || runtimeStream };
          pending.set(eventKey(row), row);
          if (pending.size > FEED_LIMIT) { pending.delete(pending.keys().next().value!); status("runtime", { gap: true }); }
          if (flushTimer === undefined) flushTimer = schedule(() => {
            ingest([...pending.values()]); pending.clear(); flushTimer = undefined;
          }, 200);
        } catch (error) { status("runtime", { error: errorMessage(error) }); }
      };
    };
    schedule(() => { void poll(); connect(); }, INITIAL_WEBSOCKET_DIAL_DELAY_MS);
    const interval = window.setInterval(() => { if (!document.hidden) void poll(); }, 5000);
    const visible = () => { if (!document.hidden) void poll(); };
    document.addEventListener("visibilitychange", visible);
    return () => {
      stopped = true; abort.abort(); refreshRef.current = async () => {};
      window.clearInterval(interval); timers.forEach(id => window.clearTimeout(id));
      document.removeEventListener("visibilitychange", visible);
      if (socket) closeSocketAfterOpen(socket);
      pending.clear(); revisions.clear();
    };
  }, [token]);
  const refresh = useCallback(async () => refreshRef.current(), []);
  return { ...(state.owner === token ? state : { events: [], sources: emptySources(), loading: false }), refresh };
}
