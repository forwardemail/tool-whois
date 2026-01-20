import { normalizeWhoisStatus } from "../whoisStatus.js";

export function findStatus(statuses: string | string[], domain: string): string[] {
  return (Array.isArray(statuses)
    ? statuses
    : statuses && typeof statuses === "object"
      ? Object.keys(statuses)
      : typeof statuses === "string"
        ? statuses.trim().split(/\s*,\s*/)
        : []
  ).map((status) => normalizeWhoisStatus(status));
}
