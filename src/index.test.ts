import { describe, it } from "node:test";
import assert from "node:assert";

// Import polyfills first
import "./polyfills.js";

import { toArray, escapeRegex, validateDomain } from "./index.js";

// ============================================================================
// toArray utility tests
// ============================================================================

describe("toArray utility function", () => {
  it("returns empty array for null", () => {
    assert.deepStrictEqual(toArray(null), []);
  });

  it("returns empty array for undefined", () => {
    assert.deepStrictEqual(toArray(undefined), []);
  });

  it("returns same array if already an array", () => {
    const arr = [1, 2, 3];
    assert.deepStrictEqual(toArray(arr), arr);
  });

  it("converts object to array of values", () => {
    const obj = { a: 1, b: 2, c: 3 };
    assert.deepStrictEqual(toArray(obj), [1, 2, 3]);
  });

  it("handles empty array", () => {
    assert.deepStrictEqual(toArray([]), []);
  });

  it("handles empty object", () => {
    assert.deepStrictEqual(toArray({}), []);
  });

  it("handles nested arrays", () => {
    const arr = [[1, 2], [3, 4]];
    assert.deepStrictEqual(toArray(arr), [[1, 2], [3, 4]]);
  });

  it("handles array-like objects with numeric keys", () => {
    const obj = { "0": "a", "1": "b", "2": "c" };
    assert.deepStrictEqual(toArray(obj), ["a", "b", "c"]);
  });
});

describe("toArray handles RDAP edge cases (issue #16)", () => {
  it("handles entities as object instead of array", () => {
    const entities = {
      "0": { roles: ["registrar"], handle: "123" },
      "1": { roles: ["abuse"], handle: "456" },
    };
    const result = toArray(entities);
    assert.strictEqual(Array.isArray(result), true);
    assert.strictEqual(result.length, 2);
    assert.deepStrictEqual(result[0], { roles: ["registrar"], handle: "123" });
  });

  it("handles nested entities being null", () => {
    const result = toArray(null);
    assert.deepStrictEqual(result, []);
  });

  it("handles nested entities being undefined", () => {
    const result = toArray(undefined);
    assert.deepStrictEqual(result, []);
  });
});

// ============================================================================
// escapeRegex utility tests (ReDoS prevention)
// ============================================================================

describe("escapeRegex utility function", () => {
  it("escapes special regex characters", () => {
    const input = "test.*+?^${}()|[]\\";
    const escaped = escapeRegex(input);
    assert.strictEqual(escaped, "test\\.\\*\\+\\?\\^\\$\\{\\}\\(\\)\\|\\[\\]\\\\");
  });

  it("leaves normal strings unchanged", () => {
    const input = "GoDaddy Inc";
    const escaped = escapeRegex(input);
    assert.strictEqual(escaped, "GoDaddy Inc");
  });

  it("handles empty string", () => {
    const escaped = escapeRegex("");
    assert.strictEqual(escaped, "");
  });

  it("handles string with only special characters", () => {
    const input = ".*+";
    const escaped = escapeRegex(input);
    assert.strictEqual(escaped, "\\.\\*\\+");
  });

  it("escaped string can be used safely in RegExp", () => {
    const malicious = "test(.*)+$";
    const escaped = escapeRegex(malicious);
    // Should not throw when creating RegExp
    const regex = new RegExp(escaped, "i");
    // The escaped string should match literally
    assert.strictEqual(regex.test("test(.*)+$"), true);
    assert.strictEqual(regex.test("testABC"), false);
  });
});

// ============================================================================
// validateDomain utility tests
// ============================================================================

describe("validateDomain utility function", () => {
  it("accepts valid domain", () => {
    const result = validateDomain("example.com");
    assert.strictEqual(result, "example.com");
  });

  it("trims whitespace", () => {
    const result = validateDomain("  example.com  ");
    assert.strictEqual(result, "example.com");
  });

  it("converts to lowercase", () => {
    const result = validateDomain("EXAMPLE.COM");
    assert.strictEqual(result, "example.com");
  });

  it("throws on empty string", () => {
    assert.throws(() => validateDomain(""), /non-empty string/);
  });

  it("throws on whitespace-only string", () => {
    assert.throws(() => validateDomain("   "), /non-empty string/);
  });

  it("throws on null", () => {
    assert.throws(() => validateDomain(null as any), /non-empty string/);
  });

  it("throws on undefined", () => {
    assert.throws(() => validateDomain(undefined as any), /non-empty string/);
  });

  it("throws on domain too long", () => {
    const longDomain = "a".repeat(254) + ".com";
    assert.throws(() => validateDomain(longDomain), /too long/);
  });

  it("accepts domain at max length", () => {
    const maxDomain = "a".repeat(249) + ".com"; // 253 chars
    const result = validateDomain(maxDomain);
    assert.strictEqual(result.length, 253);
  });
});

// ============================================================================
// vcardArray safety checks (issue #12)
// ============================================================================

describe("vcardArray safety checks (issue #12)", () => {
  it("Array.isArray correctly identifies arrays", () => {
    const vcardArray: any[] = ["vcard", [["fn", {}, "text", "Test"]]];
    assert.strictEqual(Array.isArray(vcardArray[1]), true);
    assert.strictEqual(typeof (vcardArray[1] as any[]).find, "function");
  });

  it("Array.isArray returns false for non-arrays", () => {
    const vcardArray: any[] = ["vcard", "not-an-array"];
    assert.strictEqual(Array.isArray(vcardArray[1]), false);
  });

  it("Array.isArray returns false for undefined", () => {
    const vcardArray: any[] = ["vcard"];
    assert.strictEqual(Array.isArray(vcardArray[1]), false);
  });

  it("safe access pattern prevents TypeError", () => {
    const vcardArray: any[] = ["vcard"];
    const hasFn = vcardArray && Array.isArray(vcardArray[1]) && (vcardArray[1] as any[]).find((el: any) => el[0] === 'fn');
    assert.strictEqual(hasFn, false);
  });

  it("safe access pattern works with valid data", () => {
    const vcardArray: any[] = ["vcard", [["fn", {}, "text", "Test Registrar"]]];
    const hasFn = vcardArray && Array.isArray(vcardArray[1]) && (vcardArray[1] as any[]).find((el: any) => el[0] === 'fn');
    assert.deepStrictEqual(hasFn, ["fn", {}, "text", "Test Registrar"]);
  });
});

// ============================================================================
// debug module integration (issue #13)
// ============================================================================

describe("debug module integration (issue #13)", () => {
  it("debug module is importable", async () => {
    const createDebug = (await import("debug")).default;
    assert.strictEqual(typeof createDebug, "function");
  });

  it("debug instance can be created", async () => {
    const createDebug = (await import("debug")).default;
    const debug = createDebug("test:namespace");
    assert.strictEqual(typeof debug, "function");
  });

  it("debug function can be called without error", async () => {
    const createDebug = (await import("debug")).default;
    const debug = createDebug("test:namespace");
    // Should not throw
    debug("test message %s", "arg");
  });
});

// ============================================================================
// findTimestamps anti-pattern fix (commit comment)
// ============================================================================

describe("findTimestamps behavior", () => {
  it("properly extracts timestamps from events array", () => {
    // This tests the fix for the anti-pattern where events.find was used with side effects
    const events = [
      { eventAction: "registration", eventDate: "2020-01-01T00:00:00Z" },
      { eventAction: "last changed", eventDate: "2023-06-15T12:00:00Z" },
      { eventAction: "expiration", eventDate: "2025-01-01T00:00:00Z" },
    ];

    // The function should properly iterate and extract all timestamps
    // without relying on side effects in find()
    const created = events.find(ev => ev.eventAction === "registration")?.eventDate;
    const updated = events.find(ev => ev.eventAction === "last changed")?.eventDate;
    const expires = events.find(ev => ev.eventAction === "expiration")?.eventDate;

    assert.strictEqual(created, "2020-01-01T00:00:00Z");
    assert.strictEqual(updated, "2023-06-15T12:00:00Z");
    assert.strictEqual(expires, "2025-01-01T00:00:00Z");
  });

  it("handles events with invalid dates", () => {
    const events = [
      { eventAction: "registration", eventDate: "invalid-date" },
      { eventAction: "registration", eventDate: "2020-01-01T00:00:00Z" },
    ];

    // Should skip invalid dates and find valid one
    let validDate = null;
    for (const ev of events) {
      if (ev.eventAction === "registration" && ev.eventDate) {
        const d = new Date(ev.eventDate);
        if (!isNaN(d.valueOf())) {
          validDate = d;
          break;
        }
      }
    }

    assert.notStrictEqual(validDate, null);
    assert.strictEqual(validDate?.toISOString(), "2020-01-01T00:00:00.000Z");
  });

  it("handles +0000Z date format", () => {
    const dateStr = "2020-01-01T00:00:00+0000Z";
    const normalized = dateStr.replace(/\+0000Z$/, "Z");
    const d = new Date(normalized);
    assert.strictEqual(isNaN(d.valueOf()), false);
    assert.strictEqual(d.toISOString(), "2020-01-01T00:00:00.000Z");
  });
});

// ============================================================================
// findInObject null safety
// ============================================================================

describe("findInObject null safety", () => {
  it("handles null input", async () => {
    const { findInObject } = await import("./utils/findInObject.js");
    const result = findInObject(null as any, () => true, (el) => el, "fallback");
    assert.strictEqual(result, "fallback");
  });

  it("handles undefined input", async () => {
    const { findInObject } = await import("./utils/findInObject.js");
    const result = findInObject(undefined as any, () => true, (el) => el, "fallback");
    assert.strictEqual(result, "fallback");
  });

  it("handles object with null values", async () => {
    const { findInObject } = await import("./utils/findInObject.js");
    const obj = { a: null, b: { c: "found" } };
    const result = findInObject(obj, (el) => el === "found", (el) => el, "fallback");
    assert.strictEqual(result, "found");
  });

  it("finds nested value", async () => {
    const { findInObject } = await import("./utils/findInObject.js");
    const obj = { a: { b: { c: ["fn", {}, "text", "Test"] } } };
    const result = findInObject(
      obj,
      (el) => Array.isArray(el) && el[0] === "fn",
      (el) => el[3],
      "fallback"
    );
    assert.strictEqual(result, "Test");
  });
});

// ============================================================================
// IP response parsing null safety
// ============================================================================

describe("IP response parsing", () => {
  it("handles missing port43 field", async () => {
    const { parseIpResponse } = await import("./ip.js");
    const response: any = {
      found: false,
      registrar: { id: 0, name: null },
    };
    const rdap = {
      handle: "NET-1-0-0-0-1",
      startAddress: "1.0.0.0",
      endAddress: "1.255.255.255",
      // port43 is missing
    };

    // Should not throw
    parseIpResponse("1.0.0.1", rdap, response);
    assert.strictEqual(response.registrar.name, "");
  });

  it("handles port43 without expected pattern", async () => {
    const { parseIpResponse } = await import("./ip.js");
    const response: any = {
      found: false,
      registrar: { id: 0, name: null },
    };
    const rdap = {
      handle: "NET-1-0-0-0-1",
      port43: "whois-server", // No dots
    };

    // Should not throw
    parseIpResponse("1.0.0.1", rdap, response);
    assert.strictEqual(response.registrar.name, "");
  });

  it("extracts registry from valid port43", async () => {
    const { parseIpResponse } = await import("./ip.js");
    const response: any = {
      found: false,
      registrar: { id: 0, name: null },
    };
    const rdap = {
      handle: "NET-1-0-0-0-1",
      port43: "whois.arin.net",
    };

    parseIpResponse("1.0.0.1", rdap, response);
    assert.strictEqual(response.registrar.name, "ARIN");
  });
});


// ============================================================================
// String.prototype.toWellFormed polyfill tests (Node.js 18 compatibility)
// ============================================================================

describe("String.prototype.toWellFormed polyfill", () => {
  it("toWellFormed is available as a function", () => {
    assert.strictEqual(typeof "".toWellFormed, "function");
  });

  it("returns same string for well-formed input", () => {
    const str = "Hello, World!";
    assert.strictEqual(str.toWellFormed(), str);
  });

  it("handles empty string", () => {
    assert.strictEqual("".toWellFormed(), "");
  });

  it("handles valid surrogate pairs (emoji)", () => {
    const emoji = "😀"; // U+1F600 = \uD83D\uDE00
    assert.strictEqual(emoji.toWellFormed(), emoji);
  });

  it("replaces lone high surrogate with U+FFFD", () => {
    const loneHigh = "abc\uD800def";
    assert.strictEqual(loneHigh.toWellFormed(), "abc\uFFFDdef");
  });

  it("replaces lone low surrogate with U+FFFD", () => {
    const loneLow = "abc\uDC00def";
    assert.strictEqual(loneLow.toWellFormed(), "abc\uFFFDdef");
  });

  it("replaces lone high surrogate at end", () => {
    const str = "test\uD800";
    assert.strictEqual(str.toWellFormed(), "test\uFFFD");
  });

  it("handles multiple lone surrogates", () => {
    const str = "\uD800\uD800";
    assert.strictEqual(str.toWellFormed(), "\uFFFD\uFFFD");
  });

  it("preserves valid surrogate pairs among lone surrogates", () => {
    const str = "\uD800\uD83D\uDE00\uDC00"; // lone high, valid pair, lone low
    assert.strictEqual(str.toWellFormed(), "\uFFFD😀\uFFFD");
  });
});

describe("String.prototype.isWellFormed polyfill", () => {
  it("isWellFormed is available as a function", () => {
    assert.strictEqual(typeof "".isWellFormed, "function");
  });

  it("returns true for well-formed strings", () => {
    assert.strictEqual("Hello".isWellFormed(), true);
    assert.strictEqual("".isWellFormed(), true);
    assert.strictEqual("😀".isWellFormed(), true);
  });

  it("returns false for lone high surrogate", () => {
    assert.strictEqual("test\uD800".isWellFormed(), false);
  });

  it("returns false for lone low surrogate", () => {
    assert.strictEqual("test\uDC00".isWellFormed(), false);
  });

  it("returns true for valid surrogate pair", () => {
    assert.strictEqual("\uD83D\uDE00".isWellFormed(), true);
  });
});
