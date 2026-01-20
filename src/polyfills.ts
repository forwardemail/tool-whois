/**
 * Polyfills for Node.js 18 compatibility.
 * String.prototype.toWellFormed was added in Node.js 20.
 */

// Extend String interface for TypeScript
declare global {
  interface String {
    toWellFormed(): string;
    isWellFormed(): boolean;
  }
}

// Polyfill for String.prototype.toWellFormed (ES2024)
// Replaces lone surrogates with U+FFFD (replacement character)
if (typeof String.prototype.toWellFormed !== 'function') {
  String.prototype.toWellFormed = function () {
    const str = String(this);
    const len = str.length;
    let result = '';

    for (let i = 0; i < len; i++) {
      const code = str.charCodeAt(i);

      // Check for lone surrogates
      if (code >= 0xD800 && code <= 0xDBFF) {
        // High surrogate
        if (i + 1 < len) {
          const next = str.charCodeAt(i + 1);
          if (next >= 0xDC00 && next <= 0xDFFF) {
            // Valid surrogate pair
            result += str[i] + str[i + 1];
            i++;
            continue;
          }
        }
        // Lone high surrogate - replace with U+FFFD
        result += '\uFFFD';
      } else if (code >= 0xDC00 && code <= 0xDFFF) {
        // Lone low surrogate - replace with U+FFFD
        result += '\uFFFD';
      } else {
        result += str[i];
      }
    }

    return result;
  };
}

// Polyfill for String.prototype.isWellFormed (ES2024)
if (typeof String.prototype.isWellFormed !== 'function') {
  String.prototype.isWellFormed = function () {
    const str = String(this);
    const len = str.length;

    for (let i = 0; i < len; i++) {
      const code = str.charCodeAt(i);

      if (code >= 0xD800 && code <= 0xDBFF) {
        // High surrogate - check for valid pair
        if (i + 1 >= len) return false;
        const next = str.charCodeAt(i + 1);
        if (next < 0xDC00 || next > 0xDFFF) return false;
        i++; // Skip the low surrogate
      } else if (code >= 0xDC00 && code <= 0xDFFF) {
        // Lone low surrogate
        return false;
      }
    }

    return true;
  };
}

export {};
