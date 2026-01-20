import { WhoisResponse } from "../whois.js";

export function parseIpResponse(ip: string, rdap: any, response: WhoisResponse) {
  response.found = Boolean(rdap.handle);

  // Safely extract registry from port43 with null check
  let registry = '';
  if (rdap.port43) {
    const match = rdap.port43.match(/\.(\w+)\./);
    if (match) {
      registry = match[1].toUpperCase();
    }
  }

  const realRdapServer = rdap.links?.find(({ rel }: { rel: string }) => rel === 'self')?.value?.replace(/\/ip\/.*/, '/ip/');

  response.server = realRdapServer || 'https://rdap.org/ip/';

  response.identity = {
    handle: rdap.handle,
    ipRange: {
      start: rdap.startAddress,
      endAddress: rdap.endAddress
    },
    cidr: (rdap.cidr0_cidrs || []).map((cidr: any) => cidr.v4prefix + '/' + cidr.length),
    name: rdap.name,
    type: rdap.type,
    parent: rdap.parentHandle,
    ip,
  };

  response.registrar = {
    id: 0,
    name: registry,
  };
}
