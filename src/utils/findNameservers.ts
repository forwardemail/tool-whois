export function findNameservers(values: any[]): string[] {
  let nameservers: any[] = [];
  if (Array.isArray(values)) {
    nameservers = values;
  } else if (typeof values === "object") {
    nameservers = Object.values(values);
  }

  return nameservers
    .map((ns) => ns.ldhName || ns.ldnName || ns.ipAddresses?.v4)
    .flat()
    .filter((ns) => ns)
    .map((ns) => (ns.stringValue || ns).toLocaleLowerCase())
    .sort();
}
