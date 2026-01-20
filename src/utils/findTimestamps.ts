import { WhoisTimestampFields } from "../../whois.js";
import { eventMap } from "../index.js";

/**
 * Extracts timestamps from RDAP events array.
 * Properly iterates through events and breaks when a match is found.
 */
export function findTimestamps(values: any[]) {
  const ts: Record<WhoisTimestampFields, Date | null> = {
    created: null,
    updated: null,
    expires: null,
  };

  let events: any[] = [];

  if (Array.isArray(values)) {
    events = values;
  } else if (typeof values === "object" && values !== null) {
    events = Object.values(values);
  }

  // Iterate through each event type we're looking for
  for (const [eventAction, field] of eventMap) {
    // Skip if we already have a value for this field
    if (ts[field] !== null) {
      continue;
    }

    // Find matching event and extract date
    for (const ev of events) {
      if (ev?.eventAction?.toLocaleLowerCase() === eventAction && ev.eventDate) {
        const dateStr = ev.eventDate.toString().replace(/\+0000Z$/, "Z");
        const d = new Date(dateStr);
        if (!isNaN(d.valueOf())) {
          ts[field] = d;
          break; // Found valid date, stop searching for this field
        }
      }
    }
  }

  return ts;
}
