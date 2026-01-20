/**
 * Escapes special regex characters in a string.
 * Prevents ReDoS attacks when using user input in RegExp constructor.
 */
export function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
