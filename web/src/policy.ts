import type { ConfigExport, NGFWConfig, SecurityPolicy } from "./types";

export type ParsedService = { protocol: "tcp" | "udp" | "icmp" | "icmpv6"; first?: number; last?: number };

export function parseService(value: string): ParsedService {
  const raw = value.trim();
  const parts = raw.split(":");
  if (parts.length > 2 || !parts[0]) throw new Error(`Invalid service ${JSON.stringify(value)}`);
  const protocol = parts[0].trim().toLowerCase();
  if (!["tcp", "udp", "icmp", "icmpv6"].includes(protocol)) throw new Error(`Invalid service ${JSON.stringify(value)}`);
  if (parts.length === 1) {
    if (protocol === "tcp" || protocol === "udp") throw new Error(`Invalid service ${JSON.stringify(value)}`);
    return { protocol: protocol as ParsedService["protocol"] };
  }
  if (protocol === "icmp" || protocol === "icmpv6") throw new Error(`Invalid service ${JSON.stringify(value)}`);
  const ports = parts[1].trim().split("-");
  if (ports.length > 2 || !ports[0].trim() || (ports.length === 2 && !ports[1].trim())) throw new Error(`Invalid service ${JSON.stringify(value)}`);
  const first = Number(ports[0].trim());
  const last = ports.length === 2 ? Number(ports[1].trim()) : first;
  if (!Number.isInteger(first) || !Number.isInteger(last) || first < 1 || last < first || last > 65535) throw new Error(`Invalid service ${JSON.stringify(value)}`);
  return { protocol: protocol as ParsedService["protocol"], first, last };
}

export function normalizeService(value: string): string {
  const parsed = parseService(value);
  if (parsed.first == null) return parsed.protocol;
  return parsed.first === parsed.last ? `${parsed.protocol}:${parsed.first}` : `${parsed.protocol}:${parsed.first}-${parsed.last}`;
}

export function normalizeServiceList(value: string | string[]): string[] {
  const raw = Array.isArray(value) ? value : value.split(",");
  if (!Array.isArray(value) && value.trim() === "") return [];
  const unique = new Set<string>();
  for (const item of raw) {
    const trimmed = item.trim();
    if (!trimmed) throw new Error("Invalid empty service selector");
    unique.add(normalizeService(trimmed));
  }
  return [...unique].sort((left, right) => {
    const a = parseService(left);
    const b = parseService(right);
    if (a.protocol !== b.protocol) return a.protocol.localeCompare(b.protocol, "en");
    if (a.first == null || b.first == null) return a.first == null ? 1 : -1;
    return a.first - b.first || (a.last ?? a.first) - (b.last ?? b.first);
  });
}

function normalizeArray(values?: string[], lower = true): string[] {
  const unique = new Set((values ?? []).map((item) => {
    const value = item.trim();
    return lower ? value.toLowerCase() : value;
  }).filter(Boolean));
  return [...unique].sort((a, b) => a.localeCompare(b, "en"));
}

export function canonicalizePolicy(policy: SecurityPolicy): SecurityPolicy {
  return {
    ...policy,
    source_zones: normalizeArray(policy.source_zones),
    destination_zones: normalizeArray(policy.destination_zones),
    source_addresses: normalizeArray(policy.source_addresses),
    destination_addresses: normalizeArray(policy.destination_addresses),
    services: normalizeServiceList(policy.services ?? []),
    applications: normalizeArray(policy.applications),
    security_profile_id: policy.security_profile_id?.trim().toLowerCase() || undefined,
    scope: (policy.scope || "SESSION").trim().toUpperCase(),
    action: policy.action.trim().toUpperCase(),
  };
}

export function policiesEquivalent(left: SecurityPolicy, right: SecurityPolicy): boolean {
  const a = canonicalizePolicy(left);
  const b = canonicalizePolicy(right);
  const withoutIdentity = (policy: SecurityPolicy) => {
    const { id: _id, name: _name, priority: _priority, ...effective } = policy;
    return effective;
  };
  return JSON.stringify(withoutIdentity(a)) === JSON.stringify(withoutIdentity(b));
}

export function candidateDiff(running: NGFWConfig, candidate: NGFWConfig): boolean {
  return JSON.stringify(running) !== JSON.stringify(candidate);
}

export function canCommit(config: ConfigExport | null, busy = ""): boolean {
  if (!config || busy === "commit" || !candidateDiff(config.running, config.candidate)) return false;
  return config.candidate_valid && (!config.candidate_validation_state || config.candidate_validation_state === "VALID");
}
