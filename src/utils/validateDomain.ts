/**
 * Validates domain input format.
 * Returns sanitized domain or throws on invalid input.
 */
export function validateDomain(domain: string): string {
  if (!domain || typeof domain !== 'string') {
    throw new Error('Domain must be a non-empty string');
  }
  // Basic sanitization - trim whitespace
  const sanitized = domain.trim().toLowerCase();
  if (sanitized.length === 0) {
    throw new Error('Domain must be a non-empty string');
  }
  if (sanitized.length > 253) {
    throw new Error('Domain name too long');
  }
  return sanitized;
}
