import { FormEvent, ReactNode, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, errorMessage, persistToken, storedToken } from "./api";
import {
  pushConsoleNavigation,
  readConsoleNavigation,
  replaceConsoleNavigation,
  subscribeConsoleNavigation,
} from "./navigation";
import {
  normalizeAuditPage,
  normalizeBlocks,
  normalizeConfigExport,
  normalizeEvent,
  normalizeEventPage,
  normalizeHealth,
  normalizeMLStatus,
  normalizeReputation,
  normalizeSessionDetail,
  normalizeSessionPage,
  normalizeStats,
} from "./runtimeData";
import { normalizeServiceList } from "./policy";
import { closeSocketAfterOpen, INITIAL_WEBSOCKET_DIAL_DELAY_MS, reconnectDelay } from "./wsLifecycle";
import type {
  AuditEntry,
  ConfigExport,
  Health,
  MLStatus,
  NGFWConfig,
  Page,
  ReputationEntry,
  SecurityEvent,
  SecurityPolicy,
  Session,
  SessionDetail,
  Stats,
  TemporaryBlock,
  User,
} from "./types";

type IconName =
  | "overview"
  | "sessions"
  | "threats"
  | "policy"
  | "network"
  | "configuration"
  | "system"
  | "refresh"
  | "search"
  | "plus"
  | "close"
  | "chevron"
  | "shield"
  | "lock"
  | "logout"
  | "check"
  | "warning"
  | "trash"
  | "edit"
  | "menu";

const iconPaths: Record<IconName, ReactNode> = {
  overview: <><rect x="3" y="3" width="7" height="7" rx="2"/><rect x="14" y="3" width="7" height="7" rx="2"/><rect x="3" y="14" width="7" height="7" rx="2"/><rect x="14" y="14" width="7" height="7" rx="2"/></>,
  sessions: <><path d="M4 6h16M4 12h16M4 18h16"/><circle cx="7" cy="6" r="1" fill="currentColor" stroke="none"/><circle cx="17" cy="12" r="1" fill="currentColor" stroke="none"/><circle cx="10" cy="18" r="1" fill="currentColor" stroke="none"/></>,
  threats: <><path d="M12 3 2.8 19a1.3 1.3 0 0 0 1.1 2h16.2a1.3 1.3 0 0 0 1.1-2L12 3Z"/><path d="M12 9v4"/><path d="M12 17h.01"/></>,
  policy: <><path d="M6 3h12a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2Z"/><path d="m8 9 2 2 4-4M8 16h8"/></>,
  network: <><rect x="9" y="2" width="6" height="6" rx="1"/><rect x="2" y="16" width="6" height="6" rx="1"/><rect x="16" y="16" width="6" height="6" rx="1"/><path d="M12 8v4M5 16v-2h14v2"/></>,
  configuration: <><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .34 1.88l.06.06-2.83 2.83-.06-.06a1.7 1.7 0 0 0-1.88-.34 1.7 1.7 0 0 0-1.03 1.56V21h-4v-.08A1.7 1.7 0 0 0 9 19.37a1.7 1.7 0 0 0-1.88.34l-.06.06-2.83-2.83.06-.06A1.7 1.7 0 0 0 4.63 15 1.7 1.7 0 0 0 3.08 14H3v-4h.08A1.7 1.7 0 0 0 4.63 9a1.7 1.7 0 0 0-.34-1.88l-.06-.06 2.83-2.83.06.06A1.7 1.7 0 0 0 9 4.63 1.7 1.7 0 0 0 10 3.08V3h4v.08A1.7 1.7 0 0 0 15 4.63a1.7 1.7 0 0 0 1.88-.34l.06-.06 2.83 2.83-.06.06A1.7 1.7 0 0 0 19.37 9 1.7 1.7 0 0 0 20.92 10H21v4h-.08A1.7 1.7 0 0 0 19.4 15Z"/></>,
  system: <><rect x="3" y="4" width="18" height="14" rx="2"/><path d="M8 21h8M12 18v3M7 9h2M7 13h5"/></>,
  refresh: <><path d="M20 6v5h-5"/><path d="M19 11a7.5 7.5 0 1 0 .4 4"/></>,
  search: <><circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/></>,
  plus: <path d="M12 5v14M5 12h14"/>,
  close: <path d="m6 6 12 12M18 6 6 18"/>,
  chevron: <path d="m9 18 6-6-6-6"/>,
  shield: <><path d="M12 2 4 5v6c0 5.2 3.3 9.1 8 11 4.7-1.9 8-5.8 8-11V5l-8-3Z"/><path d="m8.5 12 2.2 2.2 4.8-5"/></>,
  lock: <><rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></>,
  logout: <><path d="M10 17l5-5-5-5M15 12H3"/><path d="M14 3h5a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-5"/></>,
  check: <path d="m5 12 4 4L19 6"/>,
  warning: <><path d="M12 3 2.8 19a1.3 1.3 0 0 0 1.1 2h16.2a1.3 1.3 0 0 0 1.1-2L12 3Z"/><path d="M12 9v4M12 17h.01"/></>,
  trash: <><path d="M4 7h16M9 7V4h6v3M7 7l1 14h8l1-14M10 11v6M14 11v6"/></>,
  edit: <><path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L8 18l-4 1 1-4Z"/></>,
  menu: <path d="M4 7h16M4 12h16M4 17h16"/>,
};

function Icon({ name, size = 18 }: { name: IconName; size?: number }) {
  return <svg aria-hidden="true" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">{iconPaths[name]}</svg>;
}

const navItems: Array<{ page: Page; label: string; icon: IconName }> = [
  { page: "overview", label: "Tổng quan", icon: "overview" },
  { page: "sessions", label: "Sessions", icon: "sessions" },
  { page: "threats", label: "Sự kiện & kiểm soát", icon: "threats" },
  { page: "policy", label: "Chính sách", icon: "policy" },
  { page: "network", label: "Mạng", icon: "network" },
  { page: "configuration", label: "Cấu hình", icon: "configuration" },
  { page: "system", label: "Hệ thống", icon: "system" },
];

const pageMeta: Record<Page, { title: string; subtitle: string }> = {
  overview: { title: "Tổng quan runtime", subtitle: "Trạng thái M1/M2 và session theo thời gian thực" },
  sessions: { title: "Sessions", subtitle: "Theo dõi tuple, zone và quyết định L3/L4" },
  threats: { title: "Sự kiện & kiểm soát", subtitle: "Sự kiện runtime/policy, chặn tạm thời và dữ liệu quản trị" },
  policy: { title: "Chính sách bảo mật", subtitle: "Thứ tự first-match và profile áp dụng cho traffic" },
  network: { title: "Hạ tầng mạng", subtitle: "Interface, zone, route và NAT trong candidate hiện tại" },
  configuration: { title: "Cấu hình JSON nâng cao", subtitle: "Biên tập toàn bộ Candidate trong cùng workflow cấu hình" },
  system: { title: "Trạng thái hệ thống", subtitle: "Sức khỏe thành phần và giới hạn vận hành" },
};

const pageShortLabel: Record<Page, string> = {
  overview: "Tổng quan",
  sessions: "Sessions",
  threats: "Sự kiện & kiểm soát",
  policy: "Chính sách",
  network: "Mạng",
  configuration: "Cấu hình JSON",
  system: "Hệ thống",
};

function cx(...names: Array<string | false | null | undefined>) { return names.filter(Boolean).join(" "); }
function formatNumber(value: number | undefined) { return new Intl.NumberFormat("vi-VN").format(value ?? 0); }
function formatDate(value?: string) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "—" : new Intl.DateTimeFormat("vi-VN", { dateStyle: "short", timeStyle: "medium" }).format(date);
}
function relativeTime(value?: string) {
  if (!value) return "chưa có";
  const timestamp = Date.parse(value);
  if (Number.isNaN(timestamp)) return "chưa có";
  const seconds = Math.round((timestamp - Date.now()) / 1000);
  if (Math.abs(seconds) < 60) return "vừa xong";
  const formatter = new Intl.RelativeTimeFormat("vi", { numeric: "auto" });
  if (Math.abs(seconds) < 3600) return formatter.format(Math.round(seconds / 60), "minute");
  if (Math.abs(seconds) < 86400) return formatter.format(Math.round(seconds / 3600), "hour");
  return formatter.format(Math.round(seconds / 86400), "day");
}
function formatBytes(value: number | undefined) {
  const bytes = value ?? 0;
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KiB`;
  if (bytes < 1024 ** 3) return `${(bytes / 1024 ** 2).toFixed(1)} MiB`;
  return `${(bytes / 1024 ** 3).toFixed(1)} GiB`;
}
function riskClass(score: number) { return score >= 80 ? "critical" : score >= 60 ? "high" : score >= 30 ? "medium" : "low"; }
function severityClass(severity: unknown) {
  const normalized = typeof severity === "string" ? severity.trim().toLowerCase() : "";
  return ["info", "low", "medium", "high", "critical"].includes(normalized) ? normalized : "info";
}
function objectChanged(a: unknown, b: unknown) { return JSON.stringify(a) !== JSON.stringify(b); }

function Button({ children, icon, variant = "secondary", busy, ...props }: React.ButtonHTMLAttributes<HTMLButtonElement> & { icon?: IconName; variant?: "primary" | "secondary" | "ghost" | "danger"; busy?: boolean }) {
  return <button {...props} className={cx("button", `button-${variant}`, props.className)} disabled={busy || props.disabled}>{busy ? <span className="spinner"/> : icon ? <Icon name={icon} size={16}/> : null}<span>{children}</span></button>;
}

function Badge({ children, tone = "neutral" }: { children: ReactNode; tone?: string }) {
  return <span className={cx("badge", `badge-${tone}`)}>{children}</span>;
}

function EmptyState({ icon, title, description }: { icon: IconName; title: string; description: string }) {
  return <div className="empty-state"><div className="empty-icon"><Icon name={icon} size={22}/></div><strong>{title}</strong><p>{description}</p></div>;
}

type LiveData = {
  health: Health | null;
  stats: Stats | null;
  sessions: Session[];
  events: SecurityEvent[];
  blocks: TemporaryBlock[];
  reputation: ReputationEntry[];
  audit: AuditEntry[];
  ml: MLStatus | null;
};

const emptyLive: LiveData = { health: null, stats: null, sessions: [], events: [], blocks: [], reputation: [], audit: [], ml: null };

export default function App() {
  const initialNavigation = useRef(readConsoleNavigation(window.location.hash, window.history.state)).current;
  const [page, setPage] = useState<Page>(initialNavigation.page);
  const [pageOrigin, setPageOrigin] = useState<Page | undefined>(initialNavigation.from);
  const [menuOpen, setMenuOpen] = useState(false);
  const [live, setLive] = useState<LiveData>(emptyLive);
  const [config, setConfig] = useState<ConfigExport | null>(null);
  const [initialLoading, setInitialLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [connectionError, setConnectionError] = useState("");
  const [lastUpdated, setLastUpdated] = useState<string>();
  const [token, setToken] = useState(storedToken);
  const [user, setUser] = useState<User | null>(null);
  const [accessOpen, setAccessOpen] = useState(false);
  const [toast, setToast] = useState<{ tone: "success" | "error" | "info"; message: string } | null>(null);
  const liveLoading = useRef(false);
  const configLoading = useRef(false);
  const liveError = useRef("");
  const configError = useRef("");
  const commitInFlight = useRef(false);

  const refreshConnectionError = useCallback(() => {
    setConnectionError(liveError.current || configError.current);
  }, []);

  const notify = useCallback((tone: "success" | "error" | "info", message: string) => setToast({ tone, message }), []);
  useEffect(() => {
    if (!toast) return;
    const timer = window.setTimeout(() => setToast(null), 4200);
    return () => window.clearTimeout(timer);
  }, [toast]);

  const loadLive = useCallback(async (quiet = false) => {
    if (liveLoading.current) return;
    liveLoading.current = true;
    if (!quiet) setRefreshing(true);
    try {
      const endpointLabels = ["health", "sessions", "events", "blocks", "stats", "ML", "reputation", "audit"];
      // These resources have independent failure modes (notably the runtime
      // IPC-backed sessions/config paths), so keep healthy panels rendering
      // when one endpoint is unavailable.
      const results = await Promise.allSettled([
        api<unknown>("/api/v1/health"),
        api<unknown>("/api/v1/sessions"),
        api<unknown>("/api/v1/events"),
        api<unknown>("/api/v1/blocks"),
        api<unknown>("/api/v1/stats/system"),
        api<unknown>("/api/v1/ml/status"),
        api<unknown>("/api/v1/reputation"),
        api<unknown>("/api/v1/audit?limit=250"),
      ]);
      const read = <T,>(index: number, previous: T, normalize: (value: unknown) => T | null): T => {
        const result = results[index];
        if (result.status !== "fulfilled") return previous;
        try {
          const value = normalize(result.value);
          return value === null ? previous : value;
        } catch {
          // A malformed response must not take down the whole dashboard.
          return previous;
        }
      };
      setLive((current) => ({
        health: read(0, current.health, normalizeHealth),
        sessions: read(1, current.sessions, (value) => normalizeSessionPage(value)),
        events: read(2, current.events, (value) => normalizeEventPage(value)),
        blocks: read(3, current.blocks, (value) => normalizeBlocks(value)),
        stats: read(4, current.stats, (value) => normalizeStats(value)),
        ml: read(5, current.ml, normalizeMLStatus),
        reputation: read(6, current.reputation, (value) => normalizeReputation(value)),
        audit: read(7, current.audit, (value) => normalizeAuditPage(value)),
      }));
      const failures = results.flatMap((result, index) => result.status === "rejected" ? [`${endpointLabels[index]}: ${errorMessage(result.reason)}`] : []);
      liveError.current = failures.length ? `Một số nguồn dữ liệu tạm thời không khả dụng (${failures.join("; ")})` : "";
      if (results.some((result) => result.status === "fulfilled")) setLastUpdated(new Date().toISOString());
      refreshConnectionError();
    } finally {
      liveLoading.current = false;
      setInitialLoading(false);
      setRefreshing(false);
    }
  }, [refreshConnectionError]);

  const loadConfig = useCallback(async () => {
    if (configLoading.current) return;
    configLoading.current = true;
    try {
      const normalized = normalizeConfigExport(await api<unknown>("/api/v1/config"));
      if (!normalized) throw new Error("API trả về cấu hình không hợp lệ");
      setConfig(normalized);
      configError.current = "";
      refreshConnectionError();
    } catch (error) {
      configError.current = errorMessage(error);
      refreshConnectionError();
    } finally {
      configLoading.current = false;
    }
  }, [refreshConnectionError]);

  useEffect(() => {
    const initialTimer = window.setTimeout(() => {
      void loadLive();
      void loadConfig();
    }, 0);
    const timer = window.setInterval(() => void loadLive(true), 5000);
    return () => {
      window.clearTimeout(initialTimer);
      window.clearInterval(timer);
    };
  }, [loadConfig, loadLive]);

  useEffect(() => {
    if (!window.location.hash) replaceConsoleNavigation(window, initialNavigation);
    return subscribeConsoleNavigation(window, (entry) => {
      setPage(entry.page);
      setPageOrigin(entry.from);
      setMenuOpen(false);
    });
  }, [initialNavigation]);

  useEffect(() => {
    let stopped = false;
    const sockets = new Set<WebSocket>();
    const timers = new Set<number>();
    const startTimers = new Set<number>();
    const current = new Map<string, WebSocket>();
    const attempts = new Map<string, number>();
    const scheme = window.location.protocol === "https:" ? "wss" : "ws";
    const connect = <T,>(path: string, receive: (data: T) => void) => {
      const open = () => {
        if (stopped) return;
        const active = current.get(path);
        if (active && (active.readyState === WebSocket.CONNECTING || active.readyState === WebSocket.OPEN)) return;
        const socket = new WebSocket(`${scheme}://${window.location.host}${path}`);
        sockets.add(socket);
        current.set(path, socket);
        socket.onopen = () => {
          if (current.get(path) !== socket) {
            closeSocketAfterOpen(socket, "superseded connection");
            return;
          }
          attempts.set(path, 0);
          if (stopped) closeSocketAfterOpen(socket);
        };
        socket.onmessage = (message) => {
          try {
            const envelope = JSON.parse(String(message.data)) as { success?: unknown; data?: T };
            if (envelope && envelope.success === true) receive(envelope.data as T);
          } catch { /* polling remains the fallback for malformed frames */ }
        };
        socket.onerror = () => { /* onclose schedules a bounded reconnect */ };
        socket.onclose = () => {
          sockets.delete(socket);
          if (current.get(path) !== socket) return;
          current.delete(path);
          if (!stopped) {
            const attempt = attempts.get(path) ?? 0;
            attempts.set(path, attempt + 1);
            const timer = window.setTimeout(() => { timers.delete(timer); open(); }, reconnectDelay(attempt));
            timers.add(timer);
          }
        };
      };
      // React StrictMode mounts, cleans up, and mounts effects again in dev.
      // Leave enough time for that probe to finish before dialing, otherwise
      // the first socket is opened only to be closed during its handshake and
      // Vite reports a misleading EPIPE on the browser-facing socket.
      const timer = window.setTimeout(() => { startTimers.delete(timer); open(); }, INITIAL_WEBSOCKET_DIAL_DELAY_MS);
      startTimers.add(timer);
    };
    connect<unknown>("/ws/stats", (stats) => {
      try {
        const normalized = normalizeStats(stats);
        setLive((current) => ({ ...current, stats: normalized }));
      } catch { /* polling remains the fallback for malformed frames */ }
    });
    connect<unknown>("/ws/events", (value) => {
      try {
        const event = normalizeEvent(value);
        if (!event) return;
        setLive((current) => ({ ...current, events: [event, ...current.events.filter((item) => item.event_id !== event.event_id)].slice(0, 10000) }));
      } catch { /* polling remains the fallback for malformed frames */ }
    });
    return () => {
      stopped = true;
      startTimers.forEach((timer) => window.clearTimeout(timer));
      timers.forEach((timer) => window.clearTimeout(timer));
      sockets.forEach((socket) => closeSocketAfterOpen(socket));
      current.clear();
    };
  }, []);

  const requireAccess = useCallback(() => {
    if (token) return true;
    setAccessOpen(true);
    notify("info", "Cần đăng nhập hoặc API token để thay đổi cấu hình");
    return false;
  }, [notify, token]);

  const savePolicies = useCallback(async (policies: SecurityPolicy[]) => {
    if (!requireAccess()) return false;
    try {
      await api<SecurityPolicy[]>("/api/v1/policies", { method: "PUT", body: JSON.stringify(policies) }, token);
      await loadConfig();
      notify("success", "Đã cập nhật policy vào Candidate; hãy Validate trước Commit");
      return true;
    } catch (error) {
      // Refresh after a rejected request so the editor/table reflect the
      // authoritative Candidate rather than retaining a local optimistic row.
      await loadConfig();
      notify("error", errorMessage(error));
      return false;
    }
  }, [loadConfig, notify, requireAccess, token]);

  const saveCandidate = useCallback(async (candidate: NGFWConfig) => {
    if (!requireAccess()) return false;
    try {
      await api<NGFWConfig>("/api/v1/config/candidate", { method: "PUT", body: JSON.stringify(candidate) }, token);
      await loadConfig();
      notify("success", "Candidate đã được lưu; hãy Validate trước Commit");
      return true;
    } catch (error) {
      notify("error", errorMessage(error));
      return false;
    }
  }, [loadConfig, notify, requireAccess, token]);

  const validateCandidate = useCallback(async () => {
    if (!requireAccess()) return false;
    try {
      await api<{ valid: boolean }>("/api/v1/policies/validate", { method: "POST" }, token);
      notify("success", "Candidate hợp lệ. Nếu Candidate khác Running, nút Commit sẽ được bật.");
      await loadConfig();
      return true;
    } catch (error) {
      notify("error", errorMessage(error));
      return false;
    }
  }, [loadConfig, notify, requireAccess, token]);

  const commitCandidate = useCallback(async (comment: string) => {
    if (commitInFlight.current || !requireAccess() || !config) return false;
    commitInFlight.current = true;
    try {
      await api("/api/v1/policies/commit", {
        method: "POST",
        body: JSON.stringify({ expected_version: config.version.version, author: user?.username ?? "console", comment: comment || "UI commit" }),
      }, token);
      await loadConfig();
      notify("success", `Đã kích hoạt cấu hình phiên bản ${config.version.version + 1}`);
      return true;
    } catch (error) {
      notify("error", errorMessage(error));
      await loadConfig();
      return false;
    } finally {
      commitInFlight.current = false;
    }
  }, [config, loadConfig, notify, requireAccess, token, user]);

  const rollback = useCallback(async () => {
    if (!requireAccess() || !window.confirm("Khôi phục cấu hình phiên bản trước?")) return false;
    try {
      await api("/api/v1/policies/rollback", { method: "POST" }, token);
      await loadConfig();
      notify("success", "Đã rollback về cấu hình trước");
      return true;
    } catch (error) {
      notify("error", errorMessage(error));
      return false;
    }
  }, [loadConfig, notify, requireAccess, token]);

  const terminateSession = useCallback(async (id: string) => {
    if (!requireAccess() || !window.confirm("Kết thúc session này?")) return false;
    try {
      await api(`/api/v1/sessions/${encodeURIComponent(id)}`, { method: "DELETE" }, token);
      await loadLive(true);
      notify("success", "Session đã được kết thúc");
      return true;
    } catch (error) {
      notify("error", errorMessage(error));
      return false;
    }
  }, [loadLive, notify, requireAccess, token]);

  const addBlock = useCallback(async (input: { indicator: string; reason: string; minutes: number; source_event?: string }) => {
    if (!requireAccess()) return false;
    try {
      await api<TemporaryBlock>("/api/v1/blocks", {
        method: "POST",
        body: JSON.stringify({ indicator: input.indicator, reason: input.reason, source_event: input.source_event, expires_at: new Date(Date.now() + input.minutes * 60_000).toISOString() }),
      }, token);
      await loadLive(true);
      notify("success", `Đã chặn tạm thời ${input.indicator}`);
      return true;
    } catch (error) {
      notify("error", errorMessage(error));
      return false;
    }
  }, [loadLive, notify, requireAccess, token]);

  const deleteBlock = useCallback(async (id: string) => {
    if (!requireAccess()) return false;
    try {
      await api(`/api/v1/blocks/${encodeURIComponent(id)}`, { method: "DELETE" }, token);
      await loadLive(true);
      notify("success", "Đã gỡ temporary block");
      return true;
    } catch (error) {
      notify("error", errorMessage(error));
      return false;
    }
  }, [loadLive, notify, requireAccess, token]);

  const addReputation = useCallback(async (entry: ReputationEntry) => {
    if (!requireAccess()) return false;
    try {
      await api("/api/v1/reputation", { method: "POST", body: JSON.stringify(entry) }, token);
      await loadLive(true);
      notify("success", `Đã cập nhật reputation cho ${entry.indicator}`);
      return true;
    } catch (error) {
      notify("error", errorMessage(error));
      return false;
    }
  }, [loadLive, notify, requireAccess, token]);

  const deleteReputation = useCallback(async (indicator: string) => {
    if (!requireAccess()) return false;
    try {
      await api(`/api/v1/reputation?indicator=${encodeURIComponent(indicator)}`, { method: "DELETE" }, token);
      await loadLive(true);
      notify("success", "Đã xóa reputation indicator");
      return true;
    } catch (error) {
      notify("error", errorMessage(error));
      return false;
    }
  }, [loadLive, notify, requireAccess, token]);

  const authenticate = useCallback(async (username: string, password: string) => {
    try {
      const result = await api<{ token: string; user: User }>("/api/v1/auth/login", { method: "POST", body: JSON.stringify({ username, password }) }, "");
      persistToken(result.token);
      setToken(result.token);
      setUser(result.user);
      setAccessOpen(false);
      notify("success", `Đã đăng nhập với vai trò ${result.user.role}`);
      return true;
    } catch (error) {
      notify("error", errorMessage(error));
      return false;
    }
  }, [notify]);

  const useAPIToken = useCallback((value: string) => {
    const clean = value.trim();
    persistToken(clean);
    setToken(clean);
    setUser(null);
    setAccessOpen(false);
    notify("success", "Đã lưu API token cho phiên quản trị");
  }, [notify]);

  const signOut = useCallback(async () => {
    if (token) {
      try { await api("/api/v1/auth/logout", { method: "POST" }, token); } catch { /* local token is still cleared */ }
    }
    persistToken("");
    setToken("");
    setUser(null);
    notify("info", "Đã khóa các thao tác thay đổi");
  }, [notify, token]);

  const hasCandidateChanges = !!config && objectChanged(config.running, config.candidate);
  const criticalEvents = live.events.filter((event) => event.severity === "CRITICAL" || event.severity === "HIGH").length;

  function navigate(next: Page, origin?: Page) {
    if (next === page) {
      setMenuOpen(false);
      return;
    }
    const entry = pushConsoleNavigation(window, next, next === "configuration" ? (origin ?? page) : undefined);
    setPage(next);
    setPageOrigin(entry.from);
    setMenuOpen(false);
  }

  function navigateBack(origin: Page) {
    if (pageOrigin === origin) {
      window.history.back();
      return;
    }
    navigate(origin);
  }

  return <div className="app-shell">
    <aside className={cx("sidebar", menuOpen && "open")}>
      <div className="brand">
        <div className="brand-mark"><Icon name="shield" size={23}/></div>
        <div><strong>SENTINEL</strong><span>NGFW CONSOLE</span></div>
      </div>
      <nav aria-label="Điều hướng chính">
        <p className="nav-label">VẬN HÀNH</p>
        {navItems.slice(0, 3).map((item) => <button key={item.page} className={cx("nav-item", page === item.page && "active")} onClick={() => navigate(item.page)}><Icon name={item.icon}/><span>{item.label}</span>{item.page === "threats" && criticalEvents > 0 && <b>{criticalEvents}</b>}</button>)}
        <p className="nav-label">QUẢN TRỊ</p>
        {navItems.slice(3).map((item) => <button key={item.page} className={cx("nav-item", page === item.page && "active")} onClick={() => navigate(item.page)}><Icon name={item.icon}/><span>{item.label}</span>{item.page === "configuration" && hasCandidateChanges && <i/>}</button>)}
      </nav>
      <div className="sidebar-footer">
        <button className="access-card" onClick={() => setAccessOpen(true)}>
          <span className={cx("avatar", token && "unlocked")}>{user?.username?.slice(0, 2).toUpperCase() ?? <Icon name="lock" size={16}/>}</span>
          <span><strong>{user?.username ?? (token ? "API token" : "Chỉ đọc")}</strong><small>{user?.role ?? (token ? "Quyền ghi đã mở" : "Mở quyền thay đổi")}</small></span>
          <Icon name="chevron" size={15}/>
        </button>
      </div>
    </aside>
    {menuOpen && <button className="sidebar-scrim" aria-label="Đóng menu" onClick={() => setMenuOpen(false)}/>}

    <div className="workspace">
      <header className="topbar">
        <div className="title-wrap">
          <button className="mobile-menu" aria-label="Mở menu" onClick={() => setMenuOpen(true)}><Icon name="menu"/></button>
          <div><h1>{pageMeta[page].title}</h1><p>{pageMeta[page].subtitle}</p></div>
        </div>
        <div className="top-actions">
          {hasCandidateChanges && <button className="pending-config" onClick={() => navigate("configuration")}><span/> Candidate chưa commit</button>}
          <span className={cx("health-pill", live.health?.status ?? "unknown")}><i/>{live.health?.status === "healthy" ? "Runtime healthy" : live.health?.status === "degraded" ? "Runtime suy giảm" : "Đang kết nối"}</span>
          <Button variant="ghost" icon="refresh" busy={refreshing} onClick={() => { void loadLive(); void loadConfig(); }}>Làm mới</Button>
        </div>
      </header>

      {connectionError && <div className="connection-banner"><Icon name="warning"/><div><strong>Không cập nhật được dữ liệu</strong><span>{connectionError}. Dữ liệu cũ vẫn được giữ trên màn hình.</span></div><Button variant="ghost" onClick={() => { void loadLive(); void loadConfig(); }}>Thử lại</Button></div>}

      <main className="content">
        {initialLoading && !live.health ? <div className="page-loading"><span className="spinner large"/><p>Đang kết nối tới appliance…</p></div> : <>
          {page === "overview" && <OverviewPage live={live} config={config} lastUpdated={lastUpdated} onNavigate={navigate}/>} 
          {page === "sessions" && <SessionsPage sessions={live.sessions} onTerminate={terminateSession} onNeedAccess={() => setAccessOpen(true)}/>} 
          {page === "threats" && <ThreatsPage events={live.events} blocks={live.blocks} reputation={live.reputation} audit={live.audit} onAddBlock={addBlock} onDeleteBlock={deleteBlock} onAddReputation={addReputation} onDeleteReputation={deleteReputation}/>} 
          {page === "policy" && <PolicyPage
            config={config}
            onSave={savePolicies}
            onValidate={validateCandidate}
            onCommit={commitCandidate}
            onRollback={rollback}
            onOpenAdvanced={() => navigate("configuration", "policy")}
          />}
          {page === "network" && <NetworkPage config={config} onNavigate={navigate}/>} 
          {page === "configuration" && <ConfigurationPage
            config={config}
            originPage={pageOrigin}
            onBack={(origin) => navigateBack(origin)}
            onSave={saveCandidate}
            onValidate={validateCandidate}
            onCommit={commitCandidate}
            onRollback={rollback}
          />}
          {page === "system" && <SystemPage live={live} config={config} token={token} user={user} onAccess={() => setAccessOpen(true)} onSignOut={signOut}/>} 
        </>}
      </main>
    </div>

    {accessOpen && <AccessModal token={token} user={user} onClose={() => setAccessOpen(false)} onLogin={authenticate} onToken={useAPIToken} onSignOut={signOut}/>} 
    {toast && <div role="status" className={cx("toast", `toast-${toast.tone}`)}><Icon name={toast.tone === "success" ? "check" : toast.tone === "error" ? "warning" : "lock"}/><span>{toast.message}</span><button aria-label="Đóng" onClick={() => setToast(null)}><Icon name="close" size={14}/></button></div>}
  </div>;
}

function OverviewPage({ live, config, lastUpdated, onNavigate }: { live: LiveData; config: ConfigExport | null; lastUpdated?: string; onNavigate: (page: Page) => void }) {
  const allowed = live.sessions.filter((session) => session.decision === "ALLOW").length;
  const unavailableDecisions = live.sessions.filter((session) => session.decision_status !== "EVALUATED").length;
  const healthyComponents = live.health ? Object.values(live.health.components).filter((item) => item.status === "ok" || item.status === "healthy").length : 0;
  const componentCount = live.health ? Object.keys(live.health.components).length : 0;
  const recentEvents = [...live.events].sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp)).slice(0, 5);

  return <div className="page-stack">
    <section className="hero-panel">
      <div className="hero-copy">
        <div className="hero-kicker"><span className={cx("pulse", live.health?.status === "healthy" && "active")}/>{live.health?.status === "healthy" ? "M1/M2 runtime active" : "M1/M2 runtime needs attention"}</div>
        <h2>{live.health?.status === "healthy" ? "Firewall và session runtime đang hoạt động" : "Một số thành phần runtime đang suy giảm"}</h2>
        <p>Traffic được Linux dataplane xử lý, liên kết với conntrack session và đối chiếu policy L3/L4 phiên bản <strong>v{config?.version.version ?? 0}</strong>.</p>
        <div className="pipeline" aria-label="Luồng xử lý M2">
          {[
            ["Traffic", "network"], ["Conntrack", "sessions"], ["Session", "overview"], ["L3/L4 Policy", "policy"], ["Linux", "shield"],
          ].map(([label, icon], index, all) => <div className="pipeline-step" key={label}><span><Icon name={icon as IconName} size={15}/></span><small>{label}</small>{index < all.length - 1 && <i/>}</div>)}
        </div>
      </div>
      <div className="hero-score">
        <div className={cx("protection-ring", live.health?.status === "healthy" ? "good" : "warn")}><strong>{live.health?.status === "healthy" ? "OK" : live.health?.status === "degraded" ? "!" : "—"}</strong><span>Runtime health</span></div>
        <p>Cập nhật {relativeTime(lastUpdated)}</p>
      </div>
    </section>

    <section className="metric-grid">
      <MetricCard label="Sessions hoạt động" value={formatNumber(live.stats?.active_sessions ?? live.sessions.length)} detail={`${allowed} được phép`} icon="sessions" tone="blue" onClick={() => onNavigate("sessions")}/>
      <MetricCard label="Decision chưa sẵn sàng" value={formatNumber(unavailableDecisions)} detail="Unavailable hoặc invalidated" icon="warning" tone={unavailableDecisions ? "amber" : "green"} onClick={() => onNavigate("sessions")}/>
      <MetricCard label="Runtime / policy events" value={formatNumber(live.events.length)} detail={`${live.events.filter((event) => event.event_class === "security").length} security`} icon="threats" tone="amber" onClick={() => onNavigate("threats")}/>
      <MetricCard label="Temporary blocks" value={formatNumber(live.blocks.length)} detail={`${formatNumber(live.stats?.event_queue_dropped)} event bị bỏ`} icon="shield" tone="purple" onClick={() => onNavigate("threats")}/>
    </section>

    <div className="overview-grid">
      <section className="panel span-2">
        <div className="panel-heading"><div><h2>Sự kiện runtime gần đây</h2><p>Lifecycle session và thay đổi quyết định policy</p></div><button className="text-button" onClick={() => onNavigate("threats")}>Xem tất cả <Icon name="chevron" size={14}/></button></div>
        {recentEvents.length ? <div className="event-list">{recentEvents.map((event) => <div className="event-row" key={event.event_id}><span className={cx("severity-mark", severityClass(event.severity))}/><div><strong>{event.category || event.signature_id || "Runtime event"}</strong><p>{event.event_class} · {event.detector} · session {event.session_id || "unavailable"}</p></div><Badge tone="blue">{event.event_class}</Badge><time>{relativeTime(event.timestamp)}</time></div>)}</div> : <EmptyState icon="check" title="Chưa có sự kiện runtime" description="Session lifecycle và policy events sẽ xuất hiện khi conntrack có traffic."/>}
      </section>

      <section className="panel">
        <div className="panel-heading"><div><h2>Thành phần</h2><p>{healthyComponents}/{componentCount} đang hoạt động</p></div></div>
        <div className="component-list">{live.health && Object.entries(live.health.components).map(([name, item]) => <div className="component-row" key={name}><span className={cx("component-dot", item.status)}/><div><strong>{item.name || name}</strong><small>{item.message || "Hoạt động bình thường"}</small></div><span>{item.status}</span></div>)}</div>
      </section>

      <section className="panel span-2">
        <div className="panel-heading"><div><h2>Nhận diện ứng dụng</h2><p>Trạng thái milestone hiện tại</p></div></div>
        <EmptyState icon="sessions" title="App-ID chưa khả dụng trong M2" description="DPI và nhận diện ứng dụng thuộc milestone M3; giao diện không suy diễn ứng dụng từ port."/>
      </section>

      <section className="panel posture-card">
        <div className="panel-heading"><div><h2>Policy posture</h2><p>Candidate hiện tại</p></div></div>
        <div className="posture-line"><span>Default inter-zone</span><Badge tone={config?.candidate.default_deny ? "high" : "medium"}>{config?.candidate.default_deny ? "DENY" : "ALLOW"}</Badge></div>
        <div className="posture-line"><span>Policies bật</span><strong>{config?.candidate.policies.filter((policy) => policy.enabled).length ?? 0}</strong></div>
        <div className="posture-line"><span>Security profiles</span><strong>{config?.candidate.security_profiles.length ?? 0}</strong></div>
        <div className="posture-line"><span>Candidate</span><Badge tone={config && objectChanged(config.running, config.candidate) ? "medium" : "low"}>{config && objectChanged(config.running, config.candidate) ? "Chờ commit" : "Đồng bộ"}</Badge></div>
      </section>
    </div>
  </div>;
}

function MetricCard({ label, value, detail, icon, tone, onClick }: { label: string; value: string; detail: string; icon: IconName; tone: string; onClick: () => void }) {
  return <button className="metric-card" onClick={onClick}><span className={cx("metric-icon", tone)}><Icon name={icon}/></span><div><span>{label}</span><strong>{value}</strong><small>{detail}</small></div><Icon name="chevron" size={15}/></button>;
}

function SessionsPage({ sessions, onTerminate, onNeedAccess }: { sessions: Session[]; onTerminate: (id: string) => Promise<boolean>; onNeedAccess: () => void }) {
  const [query, setQuery] = useState("");
  const [decision, setDecision] = useState("ALL");
  const [selected, setSelected] = useState<SessionDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [terminating, setTerminating] = useState("");

  const filtered = useMemo(() => sessions.filter((session) => {
    const haystack = `${session.client_ip} ${session.server_ip} ${session.application} ${session.policy_id} ${session.id}`.toLowerCase();
    return haystack.includes(query.toLowerCase()) && (decision === "ALL" || session.decision === decision);
  }), [decision, query, sessions]);

  async function openDetail(id: string) {
    setDetailLoading(true);
    try {
      const detail = normalizeSessionDetail(await api<unknown>(`/api/v1/sessions/${encodeURIComponent(id)}`));
      if (!detail) throw new Error("API trả về chi tiết session không hợp lệ");
      setSelected(detail);
    }
    catch { setSelected(null); }
    finally { setDetailLoading(false); }
  }

  async function terminate(id: string) {
    setTerminating(id);
    const done = await onTerminate(id);
    setTerminating("");
    if (done) setSelected(null);
  }

  return <div className="page-stack">
    <section className="toolbar panel compact">
      <div className="search-box"><Icon name="search" size={16}/><input aria-label="Tìm session" placeholder="Tìm IP, ứng dụng, policy hoặc session ID…" value={query} onChange={(event) => setQuery(event.target.value)}/>{query && <button aria-label="Xóa tìm kiếm" onClick={() => setQuery("")}><Icon name="close" size={13}/></button>}</div>
      <div className="filter-group"><select aria-label="Lọc decision" value={decision} onChange={(event) => setDecision(event.target.value)}><option value="ALL">Mọi decision</option><option>ALLOW</option><option>DROP</option><option>REJECT</option><option>RATE_LIMIT</option><option>RESET_SESSION</option><option>TEMP_BLOCK</option></select></div>
      <span className="result-count">{filtered.length}/{sessions.length} sessions</span>
    </section>

    <section className="panel table-panel">
      <div className="table-scroll"><table><thead><tr><th>Client</th><th>Server</th><th>App / Protocol</th><th>Zones</th><th>Risk</th><th>Decision</th><th>Path</th><th/></tr></thead><tbody>
        {filtered.map((session) => <tr className="clickable-row" key={session.id} onClick={() => void openDetail(session.id)}><td><strong className="mono">{session.client_ip}</strong><small>:{session.client_port}</small></td><td><strong className="mono">{session.server_ip}</strong><small>:{session.server_port}</small></td><td><strong>{session.application_available ? session.application : "Unavailable (M2)"}</strong><small>{session.protocol?.toUpperCase()} · {session.tcp_state || "active"}</small></td><td><span className="zone-route"><Badge>{session.source_zone || "unknown"}</Badge><span>→</span><Badge>{session.destination_zone || "unknown"}</Badge></span></td><td><span className={cx("risk-value", session.risk_available && riskClass(session.risk_score))}>{session.risk_available ? session.risk_score : "Unavailable"}</span></td><td><Badge tone={session.decision === "ALLOW" ? "low" : session.decision ? "critical" : "medium"}>{session.decision || (session.decision_status === "INVALIDATED" ? "INVALIDATED" : "UNAVAILABLE")}</Badge></td><td><span className={cx("path-label", session.path_classification === "FAST" ? "fast" : session.path_classification === "INSPECT" ? "inspect" : "unavailable")} title={session.fast_path_reason}><i/>{session.path_classification === "UNAVAILABLE" ? "Unavailable" : session.path_classification === "FAST" ? "Fast" : "Inspect"}</span></td><td><button className="icon-button danger-hover" title="Kết thúc session" disabled={terminating === session.id} onClick={(event) => { event.stopPropagation(); void terminate(session.id); }}>{terminating === session.id ? <span className="spinner"/> : <Icon name="close" size={15}/>}</button></td></tr>)}
        {!filtered.length && <tr><td colSpan={8}><EmptyState icon="sessions" title={sessions.length ? "Không tìm thấy session" : "Chưa có session hoạt động"} description={sessions.length ? "Thử thay đổi bộ lọc hoặc từ khóa tìm kiếm." : "Session sẽ xuất hiện khi engine nhận được traffic."}/></td></tr>}
      </tbody></table></div>
    </section>
    {(selected || detailLoading) && <SessionDrawer detail={selected} loading={detailLoading} onClose={() => setSelected(null)} onTerminate={terminate} onNeedAccess={onNeedAccess}/>} 
  </div>;
}

function SessionDrawer({ detail, loading, onClose, onTerminate }: { detail: SessionDetail | null; loading: boolean; onClose: () => void; onTerminate: (id: string) => Promise<void>; onNeedAccess: () => void }) {
  const session = detail?.session;
  const context = detail?.security_context;
  return <div className="drawer-layer"><button className="drawer-scrim" aria-label="Đóng chi tiết" onClick={onClose}/><aside className="drawer" aria-label="Chi tiết session"><div className="drawer-header"><div><span className="eyebrow">SESSION DETAIL</span><h2>{session?.application || "Đang tải…"}</h2></div><button className="icon-button" aria-label="Đóng" onClick={onClose}><Icon name="close"/></button></div>
    {loading || !session || !context ? <div className="drawer-loading"><span className="spinner large"/></div> : <div className="drawer-body">
      <div className="risk-summary"><div className={cx("risk-orb", session.risk_available && riskClass(session.risk_score))}><strong>{session.risk_available ? session.risk_score : "—"}</strong><span>RISK</span></div><div><Badge tone={session.decision === "ALLOW" ? "low" : session.decision ? "critical" : "medium"}>{session.decision || (session.decision_status === "INVALIDATED" ? "INVALIDATED" : "UNAVAILABLE")}</Badge><h3>{session.risk_available ? context.risk.level || "Unknown risk" : "Risk engine chưa có trong M2"}</h3><p>{context.policy.reason || session.decision_reason || session.policy_id || "Decision chưa khả dụng"}</p></div></div>
      <DetailSection title="Kết nối"><DetailPair label="Client" value={`${session.client_ip}:${session.client_port}`}/><DetailPair label="Server" value={`${session.server_ip}:${session.server_port}`}/><DetailPair label="Zone" value={`${session.source_zone} → ${session.destination_zone}`}/><DetailPair label="Protocol" value={`${session.protocol?.toUpperCase()} · ${session.tcp_state || "—"}`}/><DetailPair label="Bắt đầu" value={formatDate(session.start_time)}/><DetailPair label="Lần cuối" value={relativeTime(session.last_seen)}/></DetailSection>
      <DetailSection title="Lưu lượng">{session.counters_available ? <div className="traffic-pair"><div><span>↑ Original</span><strong>{formatBytes(session.bytes_up)}</strong><small>{formatNumber(session.packets_up)} packets</small></div><div><span>↓ Reply</span><strong>{formatBytes(session.bytes_down)}</strong><small>{formatNumber(session.packets_down)} packets</small></div></div> : <p className="muted">Unavailable: conntrack chưa cung cấp counters cho session này.</p>}</DetailSection>
      <DetailSection title="Security context"><DetailPair label="Policy" value={context.policy.matched_policy_id || session.policy_id || "default"}/><DetailPair label="Scope" value={context.policy.scope || "SESSION"}/><DetailPair label="ML" value={context.ml.available ? `${context.ml.predicted_class || "BENIGN"} · ${Math.round(context.ml.confidence * 100)}%` : "Unavailable"}/><DetailPair label="TLS" value={String(context.tls.available ? context.tls.tls_version || "Observed" : "Unavailable")}/><DetailPair label="Signals" value={String(context.signals?.length ?? 0)}/></DetailSection>
      {!!context.risk.contributions?.length && <DetailSection title="Risk contributions"><div className="contribution-list">{context.risk.contributions.map((item, index) => <div key={`${item.source}-${index}`}><span>{item.source}</span><div><i style={{ width: `${Math.min(100, item.value * 2.5)}%` }}/></div><strong>+{item.value}</strong><small>{item.reason}</small></div>)}</div></DetailSection>}
    </div>}
    {session && <div className="drawer-footer"><Button variant="danger" icon="close" onClick={() => void onTerminate(session.id)}>Kết thúc session</Button></div>}
  </aside></div>;
}

function DetailSection({ title, children }: { title: string; children: ReactNode }) { return <section className="detail-section"><h3>{title}</h3>{children}</section>; }
function DetailPair({ label, value }: { label: string; value: string }) { return <div className="detail-pair"><span>{label}</span><strong>{value}</strong></div>; }

type ThreatTab = "events" | "blocks" | "reputation" | "audit";
function ThreatsPage({ events, blocks, reputation, audit, onAddBlock, onDeleteBlock, onAddReputation, onDeleteReputation }: {
  events: SecurityEvent[];
  blocks: TemporaryBlock[];
  reputation: ReputationEntry[];
  audit: AuditEntry[];
  onAddBlock: (input: { indicator: string; reason: string; minutes: number; source_event?: string }) => Promise<boolean>;
  onDeleteBlock: (id: string) => Promise<boolean>;
  onAddReputation: (entry: ReputationEntry) => Promise<boolean>;
  onDeleteReputation: (indicator: string) => Promise<boolean>;
}) {
  const [tab, setTab] = useState<ThreatTab>("events");
  const [severity, setSeverity] = useState("ALL");
  const [eventClass, setEventClass] = useState("ALL");
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<SecurityEvent | null>(null);
  const [blockForm, setBlockForm] = useState({ indicator: "", reason: "Manual block", minutes: 15 });
  const [repForm, setRepForm] = useState({ indicator: "", indicator_type: "IP", reputation_score: 80, category: "malicious" });
  const [saving, setSaving] = useState(false);
  const orderedEvents = useMemo(() => [...events].sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp)).filter((event) => {
    const text = `${event.event_class} ${event.category} ${event.detector} ${event.session_id} ${event.source_ip} ${event.destination_ip} ${event.signature_id}`.toLowerCase();
    return (severity === "ALL" || event.severity === severity) && (eventClass === "ALL" || event.event_class === eventClass) && text.includes(query.toLowerCase());
  }), [eventClass, events, query, severity]);

  async function submitBlock(event: FormEvent) {
    event.preventDefault();
    if (!blockForm.indicator.trim()) return;
    setSaving(true);
    const ok = await onAddBlock({ ...blockForm, indicator: blockForm.indicator.trim() });
    setSaving(false);
    if (ok) setBlockForm({ indicator: "", reason: "Manual block", minutes: 15 });
  }
  async function submitReputation(event: FormEvent) {
    event.preventDefault();
    if (!repForm.indicator.trim()) return;
    const now = Math.floor(Date.now() / 1000);
    setSaving(true);
    const ok = await onAddReputation({ ...repForm, indicator: repForm.indicator.trim(), source: "console", first_seen: now, last_updated: now, expires_at: 0, enabled: true });
    setSaving(false);
    if (ok) setRepForm({ indicator: "", indicator_type: "IP", reputation_score: 80, category: "malicious" });
  }

  return <div className="page-stack">
    <section className="subnav panel compact"><button className={cx(tab === "events" && "active")} onClick={() => setTab("events")}>Events <Badge>{events.length}</Badge></button><button className={cx(tab === "blocks" && "active")} onClick={() => setTab("blocks")}>Temporary blocks <Badge>{blocks.length}</Badge></button><button className={cx(tab === "reputation" && "active")} onClick={() => setTab("reputation")}>Reputation <Badge>{reputation.length}</Badge></button><button className={cx(tab === "audit" && "active")} onClick={() => setTab("audit")}>Audit log <Badge>{audit.length}</Badge></button></section>

    {tab === "events" && <>
      <section className="toolbar panel compact"><div className="search-box"><Icon name="search" size={16}/><input placeholder="Tìm loại event, session, detector hoặc IP…" value={query} onChange={(event) => setQuery(event.target.value)}/></div><select aria-label="Lọc loại event" value={eventClass} onChange={(event) => setEventClass(event.target.value)}><option value="ALL">Mọi loại event</option><option value="runtime">Runtime</option><option value="policy">Policy</option><option value="security">Security</option></select><select value={severity} onChange={(event) => setSeverity(event.target.value)}><option value="ALL">Mọi severity</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option><option>INFO</option></select><span className="result-count">{orderedEvents.length} events</span></section>
      <section className="panel table-panel"><div className="table-scroll"><table><thead><tr><th>Thời gian</th><th>Loại</th><th>Sự kiện</th><th>Session</th><th>Severity</th><th>Chi tiết</th></tr></thead><tbody>{orderedEvents.map((event) => <tr className="clickable-row" key={event.event_id} onClick={() => setSelected(event)}><td><time>{relativeTime(event.timestamp)}</time><small>{formatDate(event.timestamp)}</small></td><td><Badge tone={event.event_class === "security" ? "critical" : event.event_class === "policy" ? "medium" : "blue"}>{event.event_class}</Badge></td><td><strong>{event.category || "Unknown"}</strong><small>{event.detector}{event.signature_id ? ` · ${event.signature_id}` : ""}</small></td><td className="mono">{event.session_id || "—"}</td><td><Badge tone={severityClass(event.severity)}>{event.severity}</Badge></td><td>{event.evidence || "—"}</td></tr>)}{!orderedEvents.length && <tr><td colSpan={6}><EmptyState icon="check" title="Không có event phù hợp" description="Hệ thống chưa ghi nhận sự kiện theo bộ lọc hiện tại."/></td></tr>}</tbody></table></div></section>
    </>}

    {tab === "blocks" && <div className="split-grid">
      <section className="panel form-panel"><div className="panel-heading"><div><h2>Thêm temporary block</h2><p>Chặn source indicator có thời hạn trong enforcement layer</p></div></div><form onSubmit={submitBlock}><label>IP hoặc indicator<input required placeholder="203.0.113.42" value={blockForm.indicator} onChange={(event) => setBlockForm({ ...blockForm, indicator: event.target.value })}/></label><label>Lý do<input required value={blockForm.reason} onChange={(event) => setBlockForm({ ...blockForm, reason: event.target.value })}/></label><label>Thời hạn<select value={blockForm.minutes} onChange={(event) => setBlockForm({ ...blockForm, minutes: Number(event.target.value) })}><option value={5}>5 phút</option><option value={15}>15 phút</option><option value={60}>1 giờ</option><option value={1440}>24 giờ</option></select></label><Button type="submit" variant="primary" icon="shield" busy={saving}>Áp dụng block</Button></form></section>
      <section className="panel"><div className="panel-heading"><div><h2>Đang chặn</h2><p>{blocks.length} indicator còn hiệu lực</p></div></div>{blocks.length ? <div className="block-list">{blocks.map((block) => <div className="block-row" key={block.id}><span className="block-icon"><Icon name="shield"/></span><div><strong className="mono">{block.indicator}</strong><p>{block.reason}</p><small>Hết hạn {formatDate(block.expires_at)} · {relativeTime(block.created_at)}</small></div><Button variant="ghost" icon="trash" onClick={() => void onDeleteBlock(block.id)}>Gỡ</Button></div>)}</div> : <EmptyState icon="shield" title="Không có temporary block" description="Tạo block thủ công hoặc từ một security event."/>}</section>
    </div>}

    {tab === "reputation" && <div className="split-grid">
      <section className="panel form-panel"><div className="panel-heading"><div><h2>Reputation registry</h2><p>Chỉ lưu dữ liệu quản trị; M2 chưa dùng registry này để chấm risk hoặc enforce</p></div></div><form onSubmit={submitReputation}><label>Indicator<input required placeholder="bad.example hoặc 203.0.113.42" value={repForm.indicator} onChange={(event) => setRepForm({ ...repForm, indicator: event.target.value })}/></label><div className="form-row"><label>Loại<select value={repForm.indicator_type} onChange={(event) => setRepForm({ ...repForm, indicator_type: event.target.value })}><option>IP</option><option>DOMAIN</option><option>URL</option><option>HASH</option></select></label><label>Điểm tham chiếu<input type="number" min="0" max="100" value={repForm.reputation_score} onChange={(event) => setRepForm({ ...repForm, reputation_score: Number(event.target.value) })}/></label></div><label>Category<input value={repForm.category} onChange={(event) => setRepForm({ ...repForm, category: event.target.value })}/></label><Button type="submit" variant="primary" icon="plus" busy={saving}>Lưu indicator</Button></form></section>
      <section className="panel"><div className="panel-heading"><div><h2>Local reputation</h2><p>{reputation.length} indicator đã đăng ký</p></div></div>{reputation.length ? <div className="block-list">{reputation.map((entry) => <div className="block-row" key={entry.indicator}><span className={cx("score-box", riskClass(entry.reputation_score))}>{entry.reputation_score}</span><div><strong className="mono">{entry.indicator}</strong><p>{entry.indicator_type} · {entry.category || "uncategorized"}</p><small>{entry.source || "local"} · {entry.enabled ? "enabled" : "disabled"}</small></div><Button variant="ghost" icon="trash" onClick={() => void onDeleteReputation(entry.indicator)}>Xóa</Button></div>)}</div> : <EmptyState icon="threats" title="Chưa có reputation indicator" description="Thêm IP, domain hoặc URL để detector sử dụng."/>}</section>
    </div>}

    {tab === "audit" && <section className="panel table-panel"><div className="panel-heading padded"><div><h2>Management audit log</h2><p>Các thao tác làm thay đổi trạng thái; không lưu credentials hoặc payload</p></div><Badge tone="blue">{audit.length} gần nhất</Badge></div><div className="table-scroll"><table><thead><tr><th>Thời gian</th><th>Actor</th><th>Action</th><th>Resource</th><th>Result</th><th>Thông tin</th></tr></thead><tbody>{audit.map((entry) => <tr key={entry.id}><td><strong>{relativeTime(entry.timestamp)}</strong><small>{formatDate(entry.timestamp)}</small></td><td><strong>{entry.actor}</strong><small>{entry.role || "unknown role"}</small></td><td><Badge tone="blue">{entry.action}</Badge></td><td><strong>{entry.resource}</strong><small className="mono">{entry.resource_id || "—"}</small></td><td><Badge tone={entry.result === "SUCCESS" ? "low" : "critical"}>{entry.result}</Badge></td><td>{entry.message || "—"}</td></tr>)}{!audit.length && <tr><td colSpan={6}><EmptyState icon="policy" title="Chưa có audit entry" description="Các thao tác commit, block, terminate và cập nhật candidate sẽ xuất hiện tại đây."/></td></tr>}</tbody></table></div></section>}

    {selected && <EventDrawer event={selected} onClose={() => setSelected(null)} onBlock={async () => { if (selected.source_ip) { const ok = await onAddBlock({ indicator: selected.source_ip, reason: `${selected.detector}: ${selected.category}`, minutes: 60, source_event: selected.event_id }); if (ok) setSelected(null); } }}/>} 
  </div>;
}

function EventDrawer({ event, onClose, onBlock }: { event: SecurityEvent; onClose: () => void; onBlock: () => Promise<void> }) {
  return <div className="drawer-layer"><button className="drawer-scrim" aria-label="Đóng" onClick={onClose}/><aside className="drawer"><div className="drawer-header"><div><span className="eyebrow">{event.event_class.toUpperCase()} EVENT</span><h2>{event.category}</h2></div><button className="icon-button" onClick={onClose}><Icon name="close"/></button></div><div className="drawer-body"><div className="event-hero"><Badge tone={event.event_class === "security" ? severityClass(event.severity) : "blue"}>{event.event_class}</Badge>{event.event_class === "security" && <strong>{Math.round(event.confidence * 100)}% confidence</strong>}<span>{formatDate(event.timestamp)}</span></div><DetailSection title="Nguồn sự kiện"><DetailPair label="Class" value={event.event_class}/><DetailPair label="Producer" value={event.detector}/><DetailPair label="Signature" value={event.signature_id || "Unavailable"}/><DetailPair label="Recommended" value={event.recommended_action || "Unavailable"}/></DetailSection><DetailSection title="Liên kết"><DetailPair label="Source" value={event.source_ip || "Unavailable"}/><DetailPair label="Destination" value={event.destination_ip || "Unavailable"}/><DetailPair label="Session" value={event.session_id || "Unavailable"}/></DetailSection>{event.evidence && <DetailSection title="Chi tiết"><pre className="evidence">{event.evidence}</pre></DetailSection>}{event.metadata && <DetailSection title="Metadata"><pre className="json-preview">{JSON.stringify(event.metadata, null, 2)}</pre></DetailSection>}</div>{event.event_class === "security" && event.source_ip && <div className="drawer-footer"><Button variant="danger" icon="shield" onClick={() => void onBlock()}>Chặn source trong 1 giờ</Button></div>}</aside></div>;
}

export function PolicyPage({ config, onSave, onValidate, onCommit, onRollback, onOpenAdvanced }: { config: ConfigExport | null; onSave: (policies: SecurityPolicy[]) => Promise<boolean>; onValidate: () => Promise<boolean>; onCommit: (comment: string) => Promise<boolean>; onRollback: () => Promise<boolean>; onOpenAdvanced: () => void }) {
  const [editing, setEditing] = useState<SecurityPolicy | null>(null);
  const [comment, setComment] = useState("");
  const [busy, setBusy] = useState("");
  const saveInFlight = useRef(false);
  const policies = useMemo(() => [...(config?.candidate.policies ?? [])].sort((a, b) => a.priority - b.priority), [config]);
  const dirty = !!config && objectChanged(config.running, config.candidate);
  const defaultPolicy: SecurityPolicy = { id: "", name: "", priority: (policies[policies.length - 1]?.priority ?? 0) + 10, source_zones: [], destination_zones: [], services: [], applications: [], action: "ALLOW", scope: "SESSION", log_start: true, log_end: true, enabled: true };

  async function savePolicy(policy: SecurityPolicy) {
    if (saveInFlight.current) return;
    saveInFlight.current = true;
    const next = policies.filter((item) => item.id !== policy.id);
    next.push(policy);
    setBusy("save");
    try {
      const ok = await onSave(next);
      if (ok) setEditing(null);
    } finally {
      setBusy("");
      saveInFlight.current = false;
    }
  }
  async function deletePolicy(policy: SecurityPolicy) {
    if (saveInFlight.current) return;
    if (!window.confirm(`Xóa policy “${policy.name}” khỏi candidate?`)) return;
    saveInFlight.current = true;
    setBusy(policy.id);
    try { await onSave(policies.filter((item) => item.id !== policy.id)); }
    finally { setBusy(""); saveInFlight.current = false; }
  }
  async function togglePolicy(policy: SecurityPolicy) {
    if (saveInFlight.current) return;
    saveInFlight.current = true;
    setBusy(policy.id);
    try { await onSave(policies.map((item) => item.id === policy.id ? { ...item, enabled: !item.enabled } : item)); }
    finally { setBusy(""); saveInFlight.current = false; }
  }

  return <div className="page-stack">
    <ConfigStatusBar config={config} dirty={dirty} comment={comment} onComment={setComment} busy={busy} onValidate={async () => { setBusy("validate"); await onValidate(); setBusy(""); }} onCommit={async () => { setBusy("commit"); const ok = await onCommit(comment); setBusy(""); if (ok) setComment(""); }} onRollback={async () => { setBusy("rollback"); await onRollback(); setBusy(""); }}/>
    <section className="panel table-panel">
      <div className="panel-heading padded"><div><h2>Security policy rules</h2><p>Ưu tiên số nhỏ được đánh giá trước; default {config?.candidate.default_deny ? "deny" : "allow"}</p></div><div className="panel-heading-actions"><Button variant="ghost" icon="configuration" title="Mở trình soạn thảo nâng cao cho cùng Candidate hiện tại" onClick={onOpenAdvanced}>Mở JSON nâng cao</Button><Button variant="primary" icon="plus" onClick={() => setEditing(defaultPolicy)}>Thêm policy</Button></div></div>
      <div className="table-scroll"><table><thead><tr><th>Thứ tự</th><th>Policy</th><th>Source → Destination</th><th>Service L3/L4</th><th>Tương thích M2</th><th>Action</th><th>Scope</th><th>Trạng thái</th><th/></tr></thead><tbody>{policies.map((policy) => { const scope = (policy.scope || "SESSION").toUpperCase(); const compatible = scope === "SESSION" && !policy.applications?.length && !policy.security_profile_id && policy.minimum_risk == null && policy.maximum_risk == null && ["ALLOW", "DROP", "REJECT"].includes(policy.action.toUpperCase()); return <tr key={policy.id} className={!policy.enabled ? "disabled-row" : ""}><td><span className="priority-box">{policy.priority}</span></td><td><strong>{policy.name}</strong><small className="mono">{policy.id}</small></td><td><span className="zone-route"><span>{policy.source_zones?.join(", ") || "any"}</span><span>→</span><span>{policy.destination_zones?.join(", ") || "any"}</span></span></td><td><strong>{policy.services?.join(", ") || "any"}</strong><small className="field-hint">Ví dụ: tcp:80, tcp:443, udp:53</small></td><td><Badge tone={compatible ? "low" : "critical"}>{compatible ? "Compatible" : "Validate sẽ từ chối"}</Badge></td><td><Badge tone={policy.action === "ALLOW" ? "low" : "critical"}>{policy.action}</Badge></td><td>{scope}</td><td><button className={cx("toggle", policy.enabled && "on")} aria-label={policy.enabled ? "Tắt policy" : "Bật policy"} disabled={busy === policy.id} onClick={() => void togglePolicy(policy)}><i/></button></td><td><div className="row-actions"><button className="icon-button" title="Sửa" onClick={() => setEditing(policy)}><Icon name="edit" size={15}/></button><button className="icon-button danger-hover" title="Xóa" onClick={() => void deletePolicy(policy)}><Icon name="trash" size={15}/></button></div></td></tr>; })}{!policies.length && <tr><td colSpan={9}><EmptyState icon="policy" title="Chưa có policy" description="Thêm rule đầu tiên; traffic liên zone vẫn theo default action."/></td></tr>}</tbody></table></div>
    </section>
    <section className="panel"><div className="panel-heading"><div><h2>Security profiles</h2><p>{config?.candidate.security_profiles.length ?? 0} định nghĩa được lưu cho milestone sau; M2 không chạy DPI, IDS, ML, TLS inspection hoặc risk engine.</p></div><Badge tone="medium">Unavailable in M2</Badge></div></section>
    {editing && <PolicyEditor value={editing} zones={config?.candidate.zones.map((zone) => zone.id) ?? []} profiles={config?.candidate.security_profiles.map((profile) => profile.id) ?? []} busy={busy === "save"} onClose={() => setEditing(null)} onSave={savePolicy}/>} 
  </div>;
}

export function ConfigStatusBar({ config, dirty, comment, onComment, busy, onValidate, onCommit, onRollback }: { config: ConfigExport | null; dirty: boolean; comment: string; onComment: (value: string) => void; busy: string; onValidate: () => Promise<void>; onCommit: () => Promise<void>; onRollback: () => Promise<void> }) {
  const validationReady = !!config?.candidate_valid && (!config.candidate_validation_state || config.candidate_validation_state === "VALID");
  const commitDisabled = !dirty || !validationReady || busy === "commit";
  const commitTitle = !dirty
    ? "Candidate đã đồng bộ với Running; không có thay đổi để commit"
    : !validationReady
      ? config?.candidate_validation_state === "STALE" || config?.candidate_validation_state === "NOT_RUN"
        ? "Candidate chưa được Validate sau thay đổi; hãy chạy Validate"
        : "Candidate chưa hợp lệ; hãy sửa lỗi và Validate"
      : "Kích hoạt Candidate thành Running và áp dụng dataplane";
  const validationLabel = !config?.candidate_valid ? "Validation: không hợp lệ" : config.candidate_validation_state === "VALID" || !config.candidate_validation_state ? "Validation: hợp lệ" : `Validation: ${config.candidate_validation_state.toLowerCase()}`;
  return <section className={cx("config-bar", dirty && "dirty")}><div className="config-state"><span className="config-version" aria-label={`Running version ${config?.version.version ?? 0}`}>Running<br/>v{config?.version.version ?? 0}</span><div><strong>{dirty ? "Candidate changed — chưa Commit" : "Candidate synced với Running · không có thay đổi để commit"}</strong><small>{validationLabel}{config?.version.author ? ` · Running commit bởi ${config.version.author}` : ""}</small></div></div><div className="commit-controls"><input aria-label="Ghi chú commit" placeholder="Ghi chú cho commit…" value={comment} onChange={(event) => onComment(event.target.value)}/><Button icon="check" busy={busy === "validate"} title="Chỉ kiểm tra Candidate; không áp dụng dataplane" onClick={() => void onValidate()}>Validate</Button><Button variant="ghost" busy={busy === "rollback"} title="Khôi phục previous known-good theo backend và áp dụng lại dataplane" onClick={() => void onRollback()}>Rollback</Button><Button variant="primary" icon="shield" busy={busy === "commit"} disabled={commitDisabled} title={commitTitle} onClick={() => void onCommit()}>Commit</Button></div></section>;
}

export function PolicyEditor({ value, zones, profiles, busy, onClose, onSave }: { value: SecurityPolicy; zones: string[]; profiles: string[]; busy: boolean; onClose: () => void; onSave: (policy: SecurityPolicy) => Promise<void> }) {
  const [draft, setDraft] = useState<SecurityPolicy>(() => ({ ...value, source_zones: [...(value.source_zones ?? [])], destination_zones: [...(value.destination_zones ?? [])], services: [...(value.services ?? [])], applications: [...(value.applications ?? [])] }));
  const [servicesText, setServicesText] = useState(() => (value.services ?? []).join(", "));
  const [applicationsText, setApplicationsText] = useState(() => (value.applications ?? []).join(", "));
  const [priorityText, setPriorityText] = useState(() => String(value.priority ?? ""));
  const [priorityError, setPriorityError] = useState("");
  const [serviceError, setServiceError] = useState("");
  const isNew = !value.id;
  function toggleZone(field: "source_zones" | "destination_zones", zone: string) {
    const current = draft[field] ?? [];
    setDraft({ ...draft, [field]: current.includes(zone) ? current.filter((item) => item !== zone) : [...current, zone] });
  }
  function submit(event: FormEvent) {
    event.preventDefault();
    if (busy) return;
    const trimmedPriority = priorityText.trim();
    if (!trimmedPriority) {
      setPriorityError("Priority bắt buộc phải có giá trị.");
      return;
    }
    const priority = Number(trimmedPriority);
    if (!Number.isInteger(priority) || priority < 0) {
      setPriorityError("Priority phải là số nguyên từ 0 trở lên.");
      return;
    }
    setPriorityError("");
    let services: string[];
    try {
      services = normalizeServiceList(servicesText);
    } catch (error) {
      setServiceError(error instanceof Error ? error.message : "Service không hợp lệ.");
      return;
    }
    setServiceError("");
    void onSave({ ...draft, id: draft.id.trim(), name: draft.name.trim(), priority, services, applications: applicationsText.split(",").map((item) => item.trim()).filter(Boolean) });
  }
  return <div className="modal-layer"><button className="modal-scrim" aria-label="Đóng" onClick={onClose}/><form className="modal policy-modal" onSubmit={submit}><div className="modal-header"><div><span className="eyebrow">CANDIDATE POLICY</span><h2>{isNew ? "Thêm policy" : `Sửa ${value.name}`}</h2></div><button type="button" className="icon-button" onClick={onClose}><Icon name="close"/></button></div><div className="modal-body">
    <div className="form-row"><label>ID<input required disabled={!isNew} pattern="[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}" value={draft.id} onChange={(event) => setDraft({ ...draft, id: event.target.value })} placeholder="allow-lan-web"/></label><label>Tên hiển thị<input required value={draft.name} onChange={(event) => setDraft({ ...draft, name: event.target.value })} placeholder="LAN web access"/></label><label>Priority<input aria-label="Policy priority" type="number" min="0" aria-required="true" aria-invalid={Boolean(priorityError)} value={priorityText} onChange={(event) => { setPriorityText(event.target.value); if (priorityError) setPriorityError(""); }}/>{priorityError && <small className="field-error" role="alert">{priorityError}</small>}</label></div>
    <div className="form-row two"><fieldset><legend>Source zones</legend><div className="choice-grid">{zones.map((zone) => <label className="choice" key={zone}><input type="checkbox" checked={draft.source_zones?.includes(zone) ?? false} onChange={() => toggleZone("source_zones", zone)}/><span>{zone}</span></label>)}</div><small>Không chọn = any zone</small></fieldset><fieldset><legend>Destination zones</legend><div className="choice-grid">{zones.map((zone) => <label className="choice" key={zone}><input type="checkbox" checked={draft.destination_zones?.includes(zone) ?? false} onChange={() => toggleZone("destination_zones", zone)}/><span>{zone}</span></label>)}</div><small>Không chọn = any zone</small></fieldset></div>
    <div className="form-row two"><label>Services <small>Bắt buộc ghi protocol, ví dụ tcp:80, tcp:443, udp:53</small><input aria-label="Services" aria-invalid={Boolean(serviceError)} value={servicesText} onChange={(event) => { setServicesText(event.target.value); if (serviceError) setServiceError(""); }} placeholder="tcp:80, tcp:443"/>{serviceError && <small className="field-error" role="alert">{serviceError}</small>}</label><label>Applications <small>M3+; phải để trống để tương thích M2</small><input aria-label="Applications" value={applicationsText} onChange={(event) => setApplicationsText(event.target.value)} placeholder="Không khả dụng trong M2"/></label></div>
    <div className="form-row"><label>Action<select value={draft.action} onChange={(event) => setDraft({ ...draft, action: event.target.value })}><option>ALLOW</option><option>DROP</option><option>REJECT</option></select></label><label>Scope<select value={draft.scope || "SESSION"} onChange={(event) => setDraft({ ...draft, scope: event.target.value })}><option>SESSION</option></select><small>M2 chỉ hỗ trợ SESSION scope.</small></label><label>Security profile <small>M3+; phải để trống trong M2</small><select value={draft.security_profile_id || ""} onChange={(event) => setDraft({ ...draft, security_profile_id: event.target.value || undefined })}><option value="">Không áp dụng</option>{profiles.map((profile) => <option key={profile}>{profile}</option>)}</select></label></div>
    <div className="form-row"><label>Minimum risk <small>M3+; để trống trong M2</small><input type="number" min="0" max="100" value={draft.minimum_risk ?? ""} onChange={(event) => setDraft({ ...draft, minimum_risk: event.target.value === "" ? undefined : Number(event.target.value) })}/></label><label>Maximum risk <small>M3+; để trống trong M2</small><input type="number" min="0" max="100" value={draft.maximum_risk ?? ""} onChange={(event) => setDraft({ ...draft, maximum_risk: event.target.value === "" ? undefined : Number(event.target.value) })}/></label><div className="switch-stack"><label className="switch-line"><input type="checkbox" checked={draft.enabled} onChange={(event) => setDraft({ ...draft, enabled: event.target.checked })}/><span>Policy được bật</span></label><label className="switch-line"><input type="checkbox" checked={draft.log_start} onChange={(event) => setDraft({ ...draft, log_start: event.target.checked })}/><span>Log khi bắt đầu</span></label><label className="switch-line"><input type="checkbox" checked={draft.log_end} onChange={(event) => setDraft({ ...draft, log_end: event.target.checked })}/><span>Log khi kết thúc</span></label></div></div>
  </div><div className="modal-footer"><Button type="button" variant="ghost" onClick={onClose}>Hủy</Button><Button type="submit" variant="primary" icon="check" busy={busy}>Lưu vào Candidate</Button></div></form></div>;
}

function NetworkPage({ config, onNavigate }: { config: ConfigExport | null; onNavigate: (page: Page) => void }) {
  const candidate = config?.candidate;
  return <div className="page-stack">
    <section className="network-summary">{candidate?.zones.map((zone) => <article className="zone-card" key={zone.id}><div className={cx("zone-orb", zone.id)}><Icon name={zone.id === "wan" ? "network" : zone.id === "mgmt" ? "lock" : "shield"}/></div><div><span>{zone.id.toUpperCase()}</span><strong>{zone.name}</strong><small>{zone.description || "Không có mô tả"}</small></div><b>{candidate.interfaces.filter((item) => item.zone_id === zone.id).length} NIC</b></article>)}</section>
    <section className="panel"><div className="panel-heading"><div><h2>Interfaces</h2><p>Ánh xạ logical interface tới Linux network device</p></div><Badge tone={config && objectChanged(config.running.interfaces, config.candidate.interfaces) ? "medium" : "low"}>{config && objectChanged(config.running.interfaces, config.candidate.interfaces) ? "Candidate changed" : "Synced"}</Badge></div><div className="interface-grid">{candidate?.interfaces.map((item) => <article className="interface-card" key={item.id}><div className="interface-head"><span className={cx("link-dot", item.admin_state && "up")}/><div><strong>{item.name}</strong><small>{item.system_name} · {item.mode}</small></div><Badge>{item.zone_id.toUpperCase()}</Badge></div><div className="interface-address">{item.ipv4_addresses?.map((address) => <code key={address}>{address}</code>)}{!item.ipv4_addresses?.length && <span>Chưa gán IPv4</span>}</div><div className="interface-stats"><span>MTU <strong>{item.mtu || 1500}</strong></span><span>RX <strong>{formatBytes(item.rx_bytes)}</strong></span><span>TX <strong>{formatBytes(item.tx_bytes)}</strong></span></div></article>)}</div></section>
    <div className="split-grid equal">
      <section className="panel table-panel"><div className="panel-heading padded"><div><h2>Static routes</h2><p>{candidate?.routes.length ?? 0} route trong candidate</p></div></div><div className="table-scroll"><table><thead><tr><th>Destination</th><th>Gateway</th><th>Interface</th><th>Metric</th><th/></tr></thead><tbody>{candidate?.routes.map((route) => <tr key={route.id}><td><strong className="mono">{route.destination_cidr}</strong><small>{route.description || route.id}</small></td><td className="mono">{route.gateway || "direct"}</td><td><Badge>{route.interface_id}</Badge></td><td>{route.metric}</td><td><span className={cx("state-dot", route.enabled && "on")}/></td></tr>)}{!candidate?.routes.length && <tr><td colSpan={5}><EmptyState icon="network" title="Không có static route" description="Cấu hình route trong JSON candidate."/></td></tr>}</tbody></table></div></section>
      <section className="panel table-panel"><div className="panel-heading padded"><div><h2>NAT rules</h2><p>{candidate?.nat_rules.length ?? 0} rule theo priority</p></div></div><div className="table-scroll"><table><thead><tr><th>Rule</th><th>Zones</th><th>Translation</th><th>Priority</th><th/></tr></thead><tbody>{[...(candidate?.nat_rules ?? [])].sort((a, b) => a.priority - b.priority).map((rule) => <tr key={rule.id}><td><strong>{rule.name}</strong><small>{rule.type}</small></td><td><span className="zone-route"><span>{rule.source_zone || "any"}</span><span>→</span><span>{rule.destination_zone || "any"}</span></span></td><td><code>{rule.translated_address ? `${rule.translated_address}${rule.translated_port ? `:${rule.translated_port}` : ""}` : rule.type}</code></td><td>{rule.priority}</td><td><span className={cx("state-dot", rule.enabled && "on")}/></td></tr>)}{!candidate?.nat_rules.length && <tr><td colSpan={5}><EmptyState icon="network" title="Không có NAT rule" description="Candidate chưa định nghĩa SNAT, DNAT hoặc masquerade."/></td></tr>}</tbody></table></div></section>
    </div>
    <p className="page-hint"><Icon name="configuration" size={15}/> Chỉnh sửa interface, zone, route và NAT an toàn trong mục <button onClick={() => onNavigate("configuration")}>Cấu hình JSON</button>, sau đó validate trước khi commit.</p>
  </div>;
}

export function ConfigurationPage({ config, originPage, onBack, onSave, onValidate, onCommit, onRollback }: { config: ConfigExport | null; originPage?: Page; onBack: (origin: Page) => void; onSave: (candidate: NGFWConfig) => Promise<boolean>; onValidate: () => Promise<boolean>; onCommit: (comment: string) => Promise<boolean>; onRollback: () => Promise<boolean> }) {
  const [editor, setEditor] = useState("");
  const [editorDirty, setEditorDirty] = useState(false);
  const [parseError, setParseError] = useState("");
  const [comment, setComment] = useState("");
  const [busy, setBusy] = useState("");
  const saveInFlight = useRef(false);
  useEffect(() => {
    if (config && !editorDirty) setEditor(JSON.stringify(config.candidate, null, 2));
  }, [config, editorDirty]);
  const dirty = !!config && objectChanged(config.running, config.candidate);
  const changedSections = config ? [
    ["Interfaces", config.running.interfaces, config.candidate.interfaces], ["Zones", config.running.zones, config.candidate.zones], ["Routes", config.running.routes, config.candidate.routes], ["NAT", config.running.nat_rules, config.candidate.nat_rules], ["Policies", config.running.policies, config.candidate.policies], ["Profiles", config.running.security_profiles, config.candidate.security_profiles],
  ].filter(([, running, candidate]) => objectChanged(running, candidate)).map(([name]) => String(name)) : [];

  async function saveEditor() {
    if (saveInFlight.current) return;
    try {
      const parsed = JSON.parse(editor) as NGFWConfig;
      setParseError("");
      saveInFlight.current = true;
      setBusy("save");
      const ok = await onSave(parsed);
      if (ok) setEditorDirty(false);
    } catch (error) {
      setParseError(error instanceof Error ? error.message : "JSON không hợp lệ");
    } finally {
      setBusy("");
      saveInFlight.current = false;
    }
  }
  function formatEditor() {
    try {
      const formatted = JSON.stringify(JSON.parse(editor), null, 2);
      setEditor(formatted);
      setEditorDirty(formatted !== (config ? JSON.stringify(config.candidate, null, 2) : ""));
      setParseError("");
    }
    catch (error) { setParseError(error instanceof Error ? error.message : "JSON không hợp lệ"); }
  }
  function loadRunningIntoEditor() {
    if (!config) return;
    if (editorDirty || dirty) {
      const warning = dirty
        ? "Candidate hiện có thay đổi chưa commit. Nạp Running sẽ ghi đè các thay đổi này trong trình soạn thảo (Candidate backend chỉ thay đổi nếu sau đó bạn bấm Lưu vào Candidate). Tiếp tục?"
        : "Trình soạn thảo có thay đổi chưa lưu. Nạp Running sẽ ghi đè nội dung đang chỉnh. Tiếp tục?";
      if (!window.confirm(warning)) return;
    }
    const runningText = JSON.stringify(config.running, null, 2);
    const candidateText = JSON.stringify(config.candidate, null, 2);
    setEditor(runningText);
    setEditorDirty(runningText !== candidateText);
    setParseError("");
  }

  return <div className="page-stack">
    {originPage && <div className="configuration-context"><button type="button" className="back-link" onClick={() => onBack(originPage)}>← Quay lại {pageShortLabel[originPage]}</button><nav className="breadcrumb" aria-label="Breadcrumb"><span>{pageShortLabel[originPage]}</span><Icon name="chevron" size={12}/><strong>Cấu hình JSON</strong></nav></div>}
    <section className="advanced-editor-note"><Icon name="configuration" size={17}/><div><strong>Advanced Configuration Editor</strong><span>Trang Chính sách và trình soạn thảo này dùng chung một Candidate backend và cùng quy trình Commit.</span></div></section>
    <ConfigStatusBar config={config} dirty={dirty} comment={comment} onComment={setComment} busy={busy} onValidate={async () => { setBusy("validate"); await onValidate(); setBusy(""); }} onCommit={async () => { setBusy("commit"); const ok = await onCommit(comment); setBusy(""); if (ok) setComment(""); }} onRollback={async () => { setBusy("rollback"); await onRollback(); setBusy(""); }}/>
    <div className="config-layout">
      <section className="panel editor-panel"><div className="panel-heading"><div><h2>Candidate JSON</h2><p>Trình soạn thảo → Lưu vào Candidate → Validate → Commit</p></div><div className="editor-actions"><Badge tone={editorDirty ? "medium" : "low"}>{editorDirty ? "Editor chưa lưu" : "Editor đồng bộ Candidate"}</Badge><Button variant="ghost" disabled={!config} title="Chỉ thay nội dung trình soạn thảo, không áp dụng cấu hình." onClick={loadRunningIntoEditor}>Nạp Running vào trình soạn thảo</Button><Button variant="ghost" title="Định dạng JSON trong trình soạn thảo" onClick={formatEditor}>Format</Button><Button variant="primary" icon="check" busy={busy === "save"} disabled={!editorDirty} title="Chỉ cập nhật Candidate backend; chưa Commit hoặc áp dụng dataplane" onClick={() => void saveEditor()}>Lưu vào Candidate</Button></div></div>{parseError && <div className="inline-error"><Icon name="warning" size={15}/>{parseError}</div>}<textarea className="code-editor" spellCheck={false} value={editor} onChange={(event) => { const value = event.target.value; setEditor(value); setEditorDirty(value !== (config ? JSON.stringify(config.candidate, null, 2) : "")); setParseError(""); }} aria-label="Candidate configuration JSON"/></section>
      <aside className="config-aside">
        <section className="panel"><div className="panel-heading"><div><h2>Thay đổi</h2><p>So với running v{config?.version.version ?? 0}</p></div></div>{changedSections.length ? <div className="change-list">{changedSections.map((name) => <div key={name}><span className="change-dot"/><strong>{name}</strong><Badge tone="medium">Changed</Badge></div>)}</div> : <EmptyState icon="check" title="Không có thay đổi" description="Candidate đang giống running configuration."/>}</section>
        <section className="panel limits"><div className="panel-heading"><div><h2>Resource limits</h2><p>Giá trị candidate; HTTP/ML/inspection là reserved M3+</p></div></div><DetailPair label="Active sessions" value={formatNumber(config?.candidate.max_sessions)}/><DetailPair label="Event queue" value={formatNumber(config?.candidate.max_events_queue)}/><DetailPair label="HTTP body (M3+)" value={formatBytes(config?.candidate.max_http_body_inspection)}/><DetailPair label="HTTP headers (M3+)" value={formatBytes(config?.candidate.max_http_header_size)}/><DetailPair label="ML timeout (M3+)" value={`${config?.candidate.ml_timeout_millis ?? 0} ms`}/><DetailPair label="Inspection deadline (M3+)" value={`${config?.candidate.request_inspection_timeout_millis ?? 0} ms`}/></section>
        <section className="panel version-card"><span className="eyebrow">LAST KNOWN GOOD</span><strong>Version {config?.version.version ?? 0}</strong><p>{config?.version.comment || "Chưa có commit được lưu"}</p><small>{formatDate(config?.version.timestamp)}</small>{config?.version.checksum && <code title={config.version.checksum}>{config.version.checksum.slice(0, 14)}…</code>}</section>
      </aside>
    </div>
  </div>;
}

function SystemPage({ live, config, token, user, onAccess, onSignOut }: { live: LiveData; config: ConfigExport | null; token: string; user: User | null; onAccess: () => void; onSignOut: () => Promise<void> }) {
  const components = Object.entries(live.health?.components ?? {});
  return <div className="page-stack">
    <section className="system-grid">{components.map(([name, item]) => <article className="system-card" key={name}><div className={cx("system-status-icon", item.status)}><Icon name={item.status === "down" ? "warning" : "check"}/></div><div><span>{name}</span><strong>{item.name || name}</strong><p>{item.message || "Component hoạt động bình thường"}</p><small>Cập nhật {relativeTime(item.updated_at)}</small></div><Badge tone={item.status === "down" ? "critical" : item.status === "degraded" ? "medium" : "low"}>{item.status}</Badge></article>)}</section>
    <div className="split-grid equal">
      <section className="panel"><div className="panel-heading"><div><h2>Runtime protection</h2><p>Khả năng bảo vệ quan sát được từ API</p></div></div><div className="setting-list"><div><span>Management API</span><Badge tone={live.health ? "low" : "critical"}>{live.health ? "ONLINE" : "OFFLINE"}</Badge></div><div><span>ML inference</span><Badge tone={live.ml?.configured ? "low" : "medium"}>{live.ml?.configured ? "CONFIGURED" : "EXTERNAL / OFF"}</Badge></div><div><span>Event queue loss</span><strong>{formatNumber(live.stats?.event_queue_dropped)}</strong></div><div><span>Default inter-zone</span><Badge tone={config?.candidate.default_deny ? "low" : "critical"}>{config?.candidate.default_deny ? "DENY" : "ALLOW"}</Badge></div><div><span>Config version</span><strong>v{config?.version.version ?? 0}</strong></div></div></section>
      <section className="panel access-panel"><div className="panel-heading"><div><h2>Quyền truy cập</h2><p>Thông tin xác thực chỉ được lưu trong browser local storage</p></div><span className={cx("large-avatar", token && "unlocked")}>{user?.username?.slice(0, 2).toUpperCase() ?? <Icon name="lock"/>}</span></div><div className="access-summary"><DetailPair label="Danh tính" value={user?.username ?? (token ? "API token" : "Anonymous")}/><DetailPair label="Vai trò" value={user?.role ?? (token ? "Token access" : "Read only")}/><DetailPair label="Thao tác ghi" value={token ? "Đã mở" : "Đã khóa"}/></div><div className="button-row"><Button variant="primary" icon="lock" onClick={onAccess}>{token ? "Đổi thông tin xác thực" : "Mở quyền thay đổi"}</Button>{token && <Button variant="ghost" icon="logout" onClick={() => void onSignOut()}>Đăng xuất</Button>}</div></section>
    </div>
    <section className="panel"><div className="panel-heading"><div><h2>Giới hạn vận hành</h2><p>Các ngưỡng bảo vệ tài nguyên từ candidate configuration</p></div></div><div className="limit-grid"><Limit label="Sessions" value={formatNumber(config?.candidate.max_sessions)} hint="Tối đa đồng thời"/><Limit label="Event queue" value={formatNumber(config?.candidate.max_events_queue)} hint="Security signals"/><Limit label="HTTP body" value={formatBytes(config?.candidate.max_http_body_inspection)} hint="Dữ liệu kiểm tra"/><Limit label="Header" value={formatBytes(config?.candidate.max_http_header_size)} hint="Mỗi request"/><Limit label="URL" value={formatBytes(config?.candidate.max_url_length)} hint="Chiều dài tối đa"/><Limit label="Deadline" value={`${config?.candidate.request_inspection_timeout_millis ?? 0} ms`} hint="Request inspection"/></div></section>
    <UserManagement token={token} currentUser={user} onAccess={onAccess}/>
  </div>;
}

function Limit({ label, value, hint }: { label: string; value: string; hint: string }) { return <div className="limit-item"><span>{label}</span><strong>{value}</strong><small>{hint}</small></div>; }

function UserManagement({ token, currentUser, onAccess }: { token: string; currentUser: User | null; onAccess: () => void }) {
  const [users, setUsers] = useState<User[]>([]);
  const [available, setAvailable] = useState<boolean | null>(null);
  const [message, setMessage] = useState("");
  const [formOpen, setFormOpen] = useState(false);
  const [saving, setSaving] = useState("");

  const loadUsers = useCallback(async () => {
    if (!token) { setUsers([]); setAvailable(null); return; }
    try {
      setUsers(await api<User[]>("/api/v1/users", {}, token));
      setAvailable(true);
      setMessage("");
    } catch (error) {
      setAvailable(false);
      setMessage(errorMessage(error));
    }
  }, [token]);

  useEffect(() => { void loadUsers(); }, [loadUsers]);

  async function updateUser(user: User, change: Partial<User>) {
    setSaving(user.id);
    try {
      await api<User>(`/api/v1/users/${encodeURIComponent(user.id)}`, { method: "PUT", body: JSON.stringify({ username: change.username ?? user.username, role: change.role ?? user.role, enabled: change.enabled ?? user.enabled }) }, token);
      setMessage(currentUser?.id === user.id ? "Tài khoản hiện tại đã đổi; hãy đăng nhập lại nếu token bị thu hồi." : "Đã cập nhật tài khoản.");
      await loadUsers();
    } catch (error) { setMessage(errorMessage(error)); }
    finally { setSaving(""); }
  }

  async function deleteUser(user: User) {
    if (!window.confirm(`Xóa tài khoản “${user.username}”?`)) return;
    setSaving(user.id);
    try {
      await api(`/api/v1/users/${encodeURIComponent(user.id)}`, { method: "DELETE" }, token);
      setMessage("Đã xóa tài khoản.");
      await loadUsers();
    } catch (error) { setMessage(errorMessage(error)); }
    finally { setSaving(""); }
  }

  return <section className="panel table-panel user-panel"><div className="panel-heading padded"><div><h2>Tài khoản quản trị</h2><p>RBAC ADMIN, OPERATOR và VIEWER; mật khẩu được băm bằng Argon2id</p></div>{token && available && <Button variant="primary" icon="plus" onClick={() => setFormOpen(true)}>Thêm tài khoản</Button>}</div>
    {!token ? <div className="inline-access"><Icon name="lock"/><div><strong>Cần quyền ADMIN để quản lý tài khoản</strong><p>Đăng nhập hoặc nhập API token trước.</p></div><Button variant="secondary" onClick={onAccess}>Mở quyền</Button></div> : available === false ? <div className="inline-access"><Icon name="warning"/><div><strong>Account authentication chưa khả dụng</strong><p>{message}</p></div></div> : <><div className="table-scroll"><table><thead><tr><th>Tài khoản</th><th>Vai trò</th><th>Trạng thái</th><th>Session hiện tại</th><th/></tr></thead><tbody>{users.map((item) => <tr key={item.id}><td><strong>{item.username}</strong><small className="mono">{item.id}</small></td><td><select value={item.role} disabled={saving === item.id} onChange={(event) => void updateUser(item, { role: event.target.value })}><option>ADMIN</option><option>OPERATOR</option><option>VIEWER</option></select></td><td><button className={cx("toggle", item.enabled && "on")} disabled={saving === item.id} onClick={() => void updateUser(item, { enabled: !item.enabled })}><i/></button></td><td>{currentUser?.id === item.id ? <Badge tone="blue">Đang đăng nhập</Badge> : <span className="muted">—</span>}</td><td><button className="icon-button danger-hover" disabled={saving === item.id || currentUser?.id === item.id} title="Xóa tài khoản" onClick={() => void deleteUser(item)}>{saving === item.id ? <span className="spinner"/> : <Icon name="trash" size={15}/>}</button></td></tr>)}</tbody></table></div>{message && <div className="user-message">{message}</div>}</>}
    {formOpen && <UserEditor busy={saving === "new"} onClose={() => setFormOpen(false)} onSave={async (input) => { setSaving("new"); try { await api<User>("/api/v1/users", { method: "POST", body: JSON.stringify(input) }, token); setMessage("Đã tạo tài khoản mới."); setFormOpen(false); await loadUsers(); } catch (error) { setMessage(errorMessage(error)); } finally { setSaving(""); } }}/>} 
  </section>;
}

function UserEditor({ busy, onClose, onSave }: { busy: boolean; onClose: () => void; onSave: (value: { username: string; password: string; role: string; enabled: boolean }) => Promise<void> }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("VIEWER");
  return <div className="modal-layer"><button className="modal-scrim" aria-label="Đóng" onClick={onClose}/><form className="modal access-modal" onSubmit={(event) => { event.preventDefault(); void onSave({ username: username.trim(), password, role, enabled: true }); }}><div className="modal-header"><div><span className="eyebrow">RBAC USER</span><h2>Thêm tài khoản</h2></div><button type="button" className="icon-button" onClick={onClose}><Icon name="close"/></button></div><div className="modal-body auth-form"><label>Tên đăng nhập<input required autoComplete="off" value={username} onChange={(event) => setUsername(event.target.value)}/></label><label>Mật khẩu<input required minLength={12} type="password" autoComplete="new-password" value={password} onChange={(event) => setPassword(event.target.value)}/><small>Tối thiểu 12 ký tự được khuyến nghị.</small></label><label>Vai trò<select value={role} onChange={(event) => setRole(event.target.value)}><option value="VIEWER">VIEWER · chỉ xem</option><option value="OPERATOR">OPERATOR · vận hành</option><option value="ADMIN">ADMIN · toàn quyền</option></select></label></div><div className="modal-footer"><Button type="button" variant="ghost" onClick={onClose}>Hủy</Button><Button type="submit" variant="primary" icon="plus" busy={busy}>Tạo tài khoản</Button></div></form></div>;
}

function AccessModal({ token, user, onClose, onLogin, onToken, onSignOut }: { token: string; user: User | null; onClose: () => void; onLogin: (username: string, password: string) => Promise<boolean>; onToken: (token: string) => void; onSignOut: () => Promise<void> }) {
  const [mode, setMode] = useState<"account" | "token">("token");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [apiToken, setAPIToken] = useState(token);
  const [busy, setBusy] = useState(false);
  async function login(event: FormEvent) { event.preventDefault(); setBusy(true); await onLogin(username, password); setBusy(false); }
  function saveToken(event: FormEvent) { event.preventDefault(); if (apiToken.trim()) onToken(apiToken); }
  return <div className="modal-layer"><button className="modal-scrim" aria-label="Đóng" onClick={onClose}/><div className="modal access-modal"><div className="modal-header"><div><span className="eyebrow">MANAGEMENT ACCESS</span><h2>{token ? "Thông tin xác thực" : "Mở quyền thay đổi"}</h2></div><button className="icon-button" onClick={onClose}><Icon name="close"/></button></div><div className="access-intro"><span className={cx("access-shield", token && "active")}><Icon name={token ? "check" : "lock"} size={25}/></span><div><strong>{token ? `Đã mở bằng ${user?.username ?? "API token"}` : "Console đang ở chế độ chỉ đọc"}</strong><p>GET monitoring luôn khả dụng. Các thay đổi cần ADMIN hoặc OPERATOR theo endpoint.</p></div></div><div className="auth-tabs"><button className={cx(mode === "token" && "active")} onClick={() => setMode("token")}>API token</button><button className={cx(mode === "account" && "active")} onClick={() => setMode("account")}>Tài khoản</button></div>{mode === "token" ? <form className="modal-body auth-form" onSubmit={saveToken}><label>Bearer token<input type="password" autoComplete="off" required value={apiToken} onChange={(event) => setAPIToken(event.target.value)} placeholder="Ví dụ: dev-token"/></label><p className="form-note">Khi chạy local, giá trị này phải trùng với <code>NGFW_API_TOKEN</code>.</p><Button type="submit" variant="primary" icon="lock">Lưu token</Button></form> : <form className="modal-body auth-form" onSubmit={login}><label>Tên đăng nhập<input autoComplete="username" required value={username} onChange={(event) => setUsername(event.target.value)}/></label><label>Mật khẩu<input type="password" autoComplete="current-password" required value={password} onChange={(event) => setPassword(event.target.value)}/></label><p className="form-note">API phải được khởi động với <code>NGFW_ADMIN_USER</code> và <code>NGFW_ADMIN_PASSWORD</code>.</p><Button type="submit" variant="primary" icon="lock" busy={busy}>Đăng nhập</Button></form>}{token && <div className="modal-footer"><Button variant="ghost" icon="logout" onClick={() => void onSignOut()}>Xóa token và đăng xuất</Button></div>}</div></div>;
}
