/**
 * Safely converts a value to an array.
 * Handles cases where the value might be null, undefined, or a non-iterable object.
 */
export function toArray<T>(value: T | T[] | null | undefined): T[] {
  if (value === null || value === undefined) {
    return [];
  }
  if (Array.isArray(value)) {
    return value;
  }
  // Handle object case - some RDAP responses return objects instead of arrays
  if (typeof value === "object") {
    return Object.values(value) as T[];
  }
  return [];
}
