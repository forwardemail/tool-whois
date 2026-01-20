export function findInObject(
  obj: Object,
  condition: (el: any) => boolean,
  extractor: (el: any) => any,
  fallback: any
): any {
  const found = _findInObject(obj, condition);
  return found === undefined ? fallback : extractor(found);
}

function _findInObject(obj: any, condition: (el: any) => boolean): any {
  // Handle null/undefined
  if (obj === null || obj === undefined) {
    return undefined;
  }

  for (const key in obj) {
    // Skip inherited properties
    if (!Object.prototype.hasOwnProperty.call(obj, key)) {
      continue;
    }

    const value = obj[key];

    if (condition(value)) {
      return value;
    }

    if (value !== null && typeof value === "object") {
      const result = _findInObject(value, condition);
      if (result !== undefined) {
        return result;
      }
    }
  }

  return undefined;
}
