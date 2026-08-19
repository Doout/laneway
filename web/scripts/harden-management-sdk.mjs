import { readFile, unlink, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import process from 'node:process';

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error('generated output path is required');
}

const sdkPath = resolve(outputPath, 'sdk.gen.ts');
const indexPath = resolve(outputPath, 'index.ts');
const typesPath = resolve(outputPath, 'types.gen.ts');
const zodPath = resolve(outputPath, 'zod.gen.ts');
const generatedClientPath = resolve(outputPath, 'client.gen.ts');
const rootOnlyOperations = [
  'beginRootAdministratorTokenRotation',
  'completeRootAdministratorTokenRotation',
  'issueAdministratorBootstrapGrant',
  'issueAdministratorRecoveryGrant',
  'probeRootAdministratorCredential',
];

const rootOnlyTypeNames = [
  'BeginRootAdministratorTokenRotation',
  'CompleteRootAdministratorTokenRotation',
  'IssueAdministratorBootstrapGrant',
  'IssueAdministratorRecoveryGrant',
  'ProbeRootAdministratorCredential',
  'AdministratorCsrfCookie',
  'AdministratorCsrfHeader',
  'AdministratorSession2',
  'ClientOptions',
  'RecoveryGrant',
  'RootBearer',
  'RotationId',
  'ServiceAccessToken2',
];
const rootOnlyLowerPrefixes = rootOnlyTypeNames.map((name) => name.toLowerCase());
const rootOnlyZodNames = [
  'zBeginRootAdministratorTokenRotation',
  'zCompleteRootAdministratorTokenRotation',
  'zIssueAdministratorBootstrapGrant',
  'zIssueAdministratorRecoveryGrant',
  'zProbeRootAdministratorCredential',
  'zServiceAccessToken2',
];

const pruneNamedImports = (source) => source.replace(
  /import (type )?\{([^}]*)\} from ('\.\/types\.gen'|'\.\/zod\.gen');/gu,
  (statement, typeOnly, names, moduleName) => {
    const kept = names.split(',').map((name) => name.trim()).filter((name) =>
      !rootOnlyLowerPrefixes.some((prefix) => name.toLowerCase().startsWith(prefix)) &&
      !rootOnlyZodNames.some((prefix) => name.startsWith(prefix)),
    );
    return `import ${typeOnly ?? ''}{ ${kept.join(', ')} } from ${moduleName};`;
  },
);

const removeFunction = (source, name) => {
  const marker = `export const ${name} =`;
  const start = source.indexOf(marker);
  if (start < 0) throw new Error(`generated SDK is missing ${name}`);

  const commentStart = source.lastIndexOf('/**', start);
  if (commentStart < 0) throw new Error(`generated SDK is missing docs for ${name}`);

  const end = source.indexOf('\n});', start);
  if (end < 0) throw new Error(`generated SDK has an unexpected ${name} shape`);
  return source.slice(0, commentStart) + source.slice(end + 4);
};

const replaceRequired = (source, before, after, label) => {
  if (!source.includes(before)) throw new Error(`generated artifact is missing ${label}`);
  return source.replace(before, after);
};

const removeDeclarations = (source, kind, prefixes) => {
  for (const prefix of prefixes) {
    const declaration = new RegExp(`export ${kind} ${prefix}[A-Za-z0-9]* =[\\s\\S]*?;\\n\\n`, 'gu');
    source = source.replace(declaration, '');
  }
  return source;
};

const validationHelpers = `
const utf8ByteLength = (value: string): number => new TextEncoder().encode(value).byteLength;
const byteLengthBetween = (value: string, minimum: number, maximum: number): boolean => {
    const length = utf8ByteLength(value);
    return length >= minimum && length <= maximum;
};
const goSpace = /^[\\u0009-\\u000d\\u0020\\u0085\\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]+|[\\u0009-\\u000d\\u0020\\u0085\\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]+$/g;
const goTrimSpace = (value: string): string => value.replace(goSpace, '');
const trimmedBytes = (value: string, maximum: number, allowEmpty = false): boolean =>
    (allowEmpty || value.length > 0) && value === goTrimSpace(value) && utf8ByteLength(value) <= maximum && !value.includes('\\0');
const uniqueStrings = (values: ReadonlyArray<string>): boolean => new Set(values).size === values.length;
const globalAutomationPermissions = new Set([
    'network.create',
    'bootstrap_bundle.create',
    'audit.read_global',
]);
const validServicePrincipalScope = (value: {
    all_networks: boolean;
    network_ids: ReadonlyArray<string>;
    permissions: ReadonlyArray<string>;
}): boolean => {
    if (!uniqueStrings(value.network_ids) || !uniqueStrings(value.permissions)) return false;
    if (value.all_networks && value.network_ids.length > 0) return false;
    const requiresNetworkScope = value.permissions.some((permission) => !globalAutomationPermissions.has(permission));
    return requiresNetworkScope === (value.all_networks || value.network_ids.length > 0);
};

const decodeBase64 = (value: string): Uint8Array | undefined => {
    try {
        const standard = value.replace(/-/g, '+').replace(/_/g, '/');
        const padded = standard + '='.repeat((4 - standard.length % 4) % 4);
        const decoded = atob(padded);
        return Uint8Array.from(decoded, (character) => character.charCodeAt(0));
    } catch {
        return undefined;
    }
};

const protoUint32 = (value: unknown): number | undefined => {
    if (typeof value === 'number') {
        return Number.isInteger(value) && value >= 0 && value <= 4294967295 ? value : undefined;
    }
    if (typeof value !== 'string' || !/^[0-9]+$/.test(value)) return undefined;
    const canonical = value.replace(/^0+(?=[0-9])/, '');
    if (canonical.length > 10) return undefined;
    const parsed = BigInt(canonical);
    return parsed <= 4294967295n ? Number(parsed) : undefined;
};

const parseIpv4 = (value: string): Uint8Array | undefined => {
    const parts = value.split('.');
    if (parts.length !== 4) return undefined;
    const bytes = parts.map((part) => /^(?:0|[1-9][0-9]{0,2})$/.test(part) ? Number(part) : -1);
    return bytes.every((part) => part >= 0 && part <= 255) ? Uint8Array.from(bytes) : undefined;
};

const parseIpv6 = (value: string): Uint8Array | undefined => {
    if (!value || value.includes('%')) return undefined;
    let normalized = value;
    if (value.includes('.')) {
        const separator = value.lastIndexOf(':');
        const tail = separator >= 0 ? parseIpv4(value.slice(separator + 1)) : undefined;
        if (!tail) return undefined;
        normalized = value.slice(0, separator) + ':' + ((tail[0] << 8) | tail[1]).toString(16) + ':' + ((tail[2] << 8) | tail[3]).toString(16);
    }
    const halves = normalized.split('::');
    if (halves.length > 2) return undefined;
    const parseHalf = (half: string): Array<number> | undefined => {
        if (!half) return [];
        const parts = half.split(':');
        if (parts.some((part) => !/^[0-9a-fA-F]{1,4}$/.test(part))) return undefined;
        return parts.map((part) => Number.parseInt(part, 16));
    };
    const left = parseHalf(halves[0] ?? '');
    const right = parseHalf(halves[1] ?? '');
    if (!left || !right) return undefined;
    const omitted = 8 - left.length - right.length;
    if (halves.length === 1 ? omitted !== 0 : omitted < 1) return undefined;
    const words = [...left, ...Array.from({ length: omitted }, () => 0), ...right];
    const bytes = new Uint8Array(16);
    words.forEach((word, index) => {
        bytes[index * 2] = word >>> 8;
        bytes[index * 2 + 1] = word & 0xff;
    });
    return bytes;
};

const parseIp = (value: string): Uint8Array | undefined => parseIpv4(value) ?? parseIpv6(value);
const isIpv4Mapped = (bytes: Uint8Array): boolean => bytes.length === 16 &&
    bytes.slice(0, 10).every((byte) => byte === 0) && bytes[10] === 0xff && bytes[11] === 0xff;
const formatIpv6 = (bytes: Uint8Array): string => {
    const words = Array.from({ length: 8 }, (_, index) => (bytes[index * 2] << 8) | bytes[index * 2 + 1]);
    let bestStart = -1;
    let bestLength = 0;
    for (let index = 0; index < words.length;) {
        if (words[index] !== 0) {
            index += 1;
            continue;
        }
        let end = index;
        while (end < words.length && words[end] === 0) end += 1;
        if (end - index > bestLength && end - index >= 2) {
            bestStart = index;
            bestLength = end - index;
        }
        index = end;
    }
    if (bestStart < 0) return words.map((word) => word.toString(16)).join(':');
    const left = words.slice(0, bestStart).map((word) => word.toString(16)).join(':');
    const right = words.slice(bestStart + bestLength).map((word) => word.toString(16)).join(':');
    return \`${'${left}'}::${'${right}'}\`;
};
const formatIp = (bytes: Uint8Array): string => bytes.length === 4 ? Array.from(bytes).join('.') : formatIpv6(bytes);

const hostBitsAreZero = (bytes: Uint8Array, prefixLength: number): boolean => {
    const wholeBytes = Math.floor(prefixLength / 8);
    const remainingBits = prefixLength % 8;
    if (remainingBits > 0 && (bytes[wholeBytes] & (0xff >>> remainingBits)) !== 0) return false;
    const firstHostByte = wholeBytes + (remainingBits > 0 ? 1 : 0);
    return bytes.slice(firstHostByte).every((byte) => byte === 0);
};
const prefixesOverlap = (left: Uint8Array, leftBits: number, right: Uint8Array, rightBits: number): boolean => {
    if (left.length !== right.length) return false;
    const bits = Math.min(leftBits, rightBits);
    const wholeBytes = Math.floor(bits / 8);
    for (let index = 0; index < wholeBytes; index += 1) {
        if (left[index] !== right[index]) return false;
    }
    const remainingBits = bits % 8;
    if (remainingBits === 0) return true;
    const mask = (0xff << (8 - remainingBits)) & 0xff;
    return (left[wholeBytes] & mask) === (right[wholeBytes] & mask);
};

type ParsedCidr = { address: Uint8Array; bits: number; canonical: string };
const parseCidr = (value: string): ParsedCidr | undefined => {
    const separator = value.lastIndexOf('/');
    if (separator < 1) return undefined;
    const address = parseIp(value.slice(0, separator));
    const rawBits = value.slice(separator + 1);
    if (!address || !/^(?:0|[1-9][0-9]*)$/.test(rawBits)) return undefined;
    const bits = Number(rawBits);
    if (bits > address.length * 8 || !hostBitsAreZero(address, bits)) return undefined;
    return { address, bits, canonical: \`${'${formatIp(address)}'}/${'${bits}'}\` };
};
const forbiddenV4 = [
    [Uint8Array.of(0, 0, 0, 0), 32],
    [Uint8Array.of(127, 0, 0, 0), 8],
    [Uint8Array.of(169, 254, 0, 0), 16],
    [Uint8Array.of(224, 0, 0, 0), 4],
] as const;
const forbiddenV6 = [
    [new Uint8Array(16), 128],
    [Uint8Array.of(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1), 128],
    [Uint8Array.of(0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0), 10],
    [Uint8Array.of(0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0), 8],
] as const;
const routableCidr = (value: string, family?: 4 | 6, minimum = 1, maximum = 128, exactSpelling = false): boolean => {
    const parsed = parseCidr(value);
    if (!parsed || isIpv4Mapped(parsed.address) || parsed.bits < minimum || parsed.bits > maximum) return false;
    if (family === 4 && parsed.address.length !== 4 || family === 6 && parsed.address.length !== 16) return false;
    if (exactSpelling && parsed.canonical !== value) return false;
    const forbidden = parsed.address.length === 4 ? forbiddenV4 : forbiddenV6;
    return !forbidden.some(([address, bits]) => prefixesOverlap(parsed.address, parsed.bits, address, bits));
};

const validProtoPrefix = (value: { address: string; prefix_length?: number }): boolean => {
    const address = decodeBase64(value.address);
    const bits = value.prefix_length ?? 0;
    return !!address && (address.length === 4 || address.length === 16) && bits <= address.length * 8 && hostBitsAreZero(address, bits);
};
const validRelayEndpoint = (value: string): boolean => {
    if (!value || value !== goTrimSpace(value)) return false;
    let host: string;
    let port: string;
    if (value.startsWith('[')) {
        const closing = value.indexOf(']');
        if (closing < 0 || value[closing + 1] !== ':') return false;
        host = value.slice(1, closing);
        port = value.slice(closing + 2);
        if (value.indexOf(']', closing + 1) >= 0) return false;
    } else {
        const separator = value.lastIndexOf(':');
        if (separator < 1 || value.indexOf(':') !== separator) return false;
        host = value.slice(0, separator);
        port = value.slice(separator + 1);
    }
    const address = parseIp(host);
    if (address && (isIpv4Mapped(address) || address.every((byte) => byte === 0) ||
        address.length === 4 && address.every((byte) => byte === 255) ||
        address.length === 4 && address[0] >= 224 && address[0] <= 239 ||
        address.length === 16 && address[0] === 0xff)) return false;
    if (!address) {
        const canonicalHost = host.toLowerCase().replace(/\\.$/, '');
        if (!canonicalHost || utf8ByteLength(canonicalHost) > 253 || canonicalHost.split('.').some((label) =>
            !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) return false;
    }
    return /^[0-9]+$/.test(port) && Number(port) >= 1 && Number(port) <= 65535;
};
const validAdministratorAccess = (value: { role: string; all_networks: boolean; network_ids: ReadonlyArray<string> }): boolean =>
    uniqueStrings(value.network_ids) && (value.role !== 'owner' || value.all_networks) && (!value.all_networks || value.network_ids.length === 0);
const validEndpointStatus = (value: {
    freshness: string;
    last_reported_at_unix_seconds?: number;
    expires_at_unix_seconds?: number;
    report?: { valid_for_seconds: number };
}): boolean => {
    const hasLast = value.last_reported_at_unix_seconds !== undefined;
    const hasExpiry = value.expires_at_unix_seconds !== undefined;
    if (hasLast !== hasExpiry || hasLast && value.last_reported_at_unix_seconds! >= value.expires_at_unix_seconds!) return false;
    if (value.freshness === 'current') return hasLast && value.report !== undefined &&
        value.expires_at_unix_seconds! - value.last_reported_at_unix_seconds! === value.report.valid_for_seconds;
    if (value.freshness === 'expired') return hasLast && value.report === undefined;
    if (value.freshness === 'never_reported') return !hasLast && value.report === undefined;
    return value.freshness === 'node_inactive' && value.report === undefined;
};
const validRoute = (value: { prefix: string; kind: string; mode: string }): boolean => {
    const parsed = parseCidr(value.prefix);
    if (!parsed || isIpv4Mapped(parsed.address) || parsed.canonical !== value.prefix) return false;
    if (parsed.bits > 0) {
        const forbidden = parsed.address.length === 4 ? forbiddenV4 : forbiddenV6;
        if (forbidden.some(([address, bits]) => prefixesOverlap(parsed.address, parsed.bits, address, bits))) return false;
    }
    if (value.kind === 'overlay') return parsed.bits === parsed.address.length * 8 && value.mode === 'none';
    if (value.kind === 'subnet') return parsed.bits > 0 && (value.mode === 'nat' || value.mode === 'routed');
    return value.kind === 'exit' && parsed.bits === 0 && (value.mode === 'nat' || value.mode === 'routed');
};
`;

let types = await readFile(typesPath, 'utf8');
types = replaceRequired(types, `export type ClientOptions = {
    baseUrl: \`${'${string}'}://${'${string}'}\` | (string & {});
};

`, '', 'configurable ClientOptions');
types = replaceRequired(types, `        /**
         * Root-only exact canonical username filter.
         */
        username?: Username;
`, '', 'root-only administrator username query');
types = removeDeclarations(types, 'type', rootOnlyTypeNames.filter((name) => name !== 'ClientOptions'));
await writeFile(typesPath, types);

let zod = await readFile(zodPath, 'utf8');
zod = replaceRequired(zod, "import * as z from 'zod';\n", `import * as z from 'zod';\n${validationHelpers}`, 'Zod import');
const zodReplacements = [
  ["export const zAssignRouteRequest = z.object({\n    network_id: zIdentifier,\n    node_id: zIdentifier,\n    prefix: z.string(),", "export const zAssignRouteRequest = z.object({\n    network_id: zIdentifier,\n    node_id: zIdentifier,\n    prefix: z.string().refine((value) => routableCidr(value), 'prefix must be a masked non-default routable CIDR'),"],
  ["export const zPassword = z.string();", "export const zPassword = z.string().refine((value) => byteLengthBetween(value, 15, 1024), 'password must occupy 15..1024 UTF-8 bytes');"],
  ["export const zAccessServicePortRange = z.object({\n    first: z.int().gte(1).lte(65535),\n    last: z.int().gte(1).lte(65535)\n}).strict();", "export const zAccessServicePortRange = z.object({\n    first: z.int().gte(1).lte(65535),\n    last: z.int().gte(1).lte(65535)\n}).strict().refine((value) => value.first <= value.last, 'first must not exceed last');"],
  ["        route_id: zIdentifier,\n        prefix: z.string()\n    }).strict()\n]);\n\nexport const zCreateAccessServiceRequest", "        route_id: zIdentifier,\n        prefix: z.string().refine((value) => routableCidr(value, undefined, 1, 128, true), 'prefix must be a canonical masked non-default routable CIDR')\n    }).strict()\n]);\n\nexport const zCreateAccessServiceRequest"],
  ["        route_id: zIdentifier,\n        prefix: z.string(),\n        enabled: z.boolean(),", "        route_id: zIdentifier,\n        prefix: z.string().refine((value) => routableCidr(value, undefined, 1, 128, true), 'prefix must be a canonical masked non-default routable CIDR'),\n        enabled: z.boolean(),"],
  ["    ports: z.array(zAccessServicePortRange),\n    enabled: z.boolean(),\n    created_at_unix_seconds: zUnixSeconds,\n    updated_at_unix_seconds: zUnixSeconds\n}).strict();", "    ports: z.array(zAccessServicePortRange),\n    enabled: z.boolean(),\n    created_at_unix_seconds: zUnixSeconds,\n    updated_at_unix_seconds: zUnixSeconds\n}).strict().refine((value) => value.protocol === 'tcp' || value.protocol === 'udp' ? value.ports.length > 0 : value.ports.length === 0, 'TCP and UDP require ports; other protocols forbid them');"],
  ["}).strict();\n\n/**\n * Canonical padded base64 encoding of exactly 16 bytes.\n */\nexport const zProtoBytes16", "}).strict().refine((value) => value.first <= value.last, 'first must not exceed last');\n\n/**\n * Canonical padded base64 encoding of exactly 16 bytes.\n */\nexport const zProtoBytes16"],
  ["export const zProtoBytes16 = z.string().regex(/^[A-Za-z0-9+\\/]{22}==$/);", "export const zProtoBytes16 = z.string().regex(/^[A-Za-z0-9+\\/]{22}==$/).refine((value) => {\n    const bytes = decodeBase64(value);\n    return !!bytes && bytes.length === 16 && bytes.some((byte) => byte !== 0);\n}, 'identifier must decode to 16 nonzero bytes');"],
  ["export const zProtoBytes16Input = z.string().regex(/^[A-Za-z0-9+\\/]{22}==$/);", "export const zProtoBytes16Input = z.string().regex(/^[A-Za-z0-9+\\/]{22}==$/).refine((value) => {\n    const bytes = decodeBase64(value);\n    return !!bytes && bytes.length === 16 && bytes.some((byte) => byte !== 0);\n}, 'identifier must decode to 16 nonzero bytes');"],
  ["export const zProtoUint32Input = z.union([\n    z.int().gte(0).lte(4294967295),\n    z.string().regex(/^[0-9]+$/)\n]);", "export const zProtoUint32Input = z.union([\n    z.int().gte(0).lte(4294967295),\n    z.string().regex(/^[0-9]+$/)\n]).transform((value, context) => {\n    const normalized = protoUint32(value);\n    if (normalized !== undefined) return normalized;\n    context.addIssue({ code: 'custom', message: 'value must be a uint32 integer or quoted decimal digits' });\n    return z.NEVER;\n});"],
  ["export const zPortRangeInput = z.object({\n    first: zProtoUint32Input,\n    last: zProtoUint32Input\n}).strict();", "export const zPortRangeInput = z.object({\n    first: zProtoUint32Input,\n    last: zProtoUint32Input\n}).strict().refine((value) => value.first >= 1 && value.last <= 65535 && value.first <= value.last, 'port range must be ordered within 1..65535');"],
  ["export const zProtoIpPrefixInput = z.object({\n    address: zProtoIpAddressInput,\n    prefix_length: zProtoUint32Input.optional()\n}).strict();", "export const zProtoIpPrefixInput = z.object({\n    address: zProtoIpAddressInput,\n    prefix_length: zProtoUint32Input.optional()\n}).strict().refine(validProtoPrefix, 'IP prefix must match its address family and contain no host bits');"],
  ["export const zProtoIpPrefix = z.object({\n    address: zProtoIpAddress,\n    prefix_length: z.int().gte(0).lte(128).optional()\n}).strict();", "export const zProtoIpPrefix = z.object({\n    address: zProtoIpAddress,\n    prefix_length: z.int().gte(0).lte(128).optional()\n}).strict().refine(validProtoPrefix, 'IP prefix must match its address family and contain no host bits');"],
  ["export const zRelayEndpoint = z.string();", "export const zRelayEndpoint = z.string().refine(validRelayEndpoint, 'relay endpoint must be an accepted host and nonzero port');"],
  ["export const zResourceName = z.string();", "export const zResourceName = z.string().refine((value) => trimmedBytes(value, 253), 'name must be 1..253 trimmed UTF-8 bytes without NUL');"],
  ["    ipv4_pool: z.string(),\n    ipv6_pool: z.string().nullish()", "    ipv4_pool: z.string().refine((value) => routableCidr(value, 4, 8, 30, true), 'IPv4 pool must be a canonical routable /8../30'),\n    ipv6_pool: z.string().nullish().refine((value) => value == null || value === '' || routableCidr(value, 6, 64, 120, true), 'IPv6 pool must be a canonical routable /64../120')"],
  ["export const zRevocationRequest = z.object({\n    reason: z.string()\n}).strict();", "export const zRevocationRequest = z.object({\n    reason: z.string().refine((value) => value.length > 0 && value === goTrimSpace(value) && utf8ByteLength(value) <= 1024, 'reason must be 1..1024 trimmed UTF-8 bytes')\n}).strict();"],
  ["export const zAdministratorAccessPatch = z.intersection(z.unknown(), z.object({\n    role: zRole,\n    all_networks: z.boolean(),\n    network_ids: z.array(zIdentifier)\n}).strict());", "export const zAdministratorAccessPatch = z.object({\n    role: zRole,\n    all_networks: z.boolean(),\n    network_ids: z.array(zIdentifier)\n}).strict().refine(validAdministratorAccess, 'administrator scope is inconsistent with role or contains duplicate networks');"],
  ["export const zAdministratorUpdateRequest = z.intersection(z.union([\n    z.object({\n        access: z.unknown()\n    }).strict(),\n    z.object({\n        enabled: z.unknown()\n    }).strict()\n]), z.object({\n    access: zAdministratorAccessPatch.nullish(),\n    enabled: z.boolean().nullish()\n}).strict());", "export const zAdministratorUpdateRequest = z.object({\n    access: zAdministratorAccessPatch.nullish(),\n    enabled: z.boolean().nullish()\n}).strict().refine((value) => value.access != null || value.enabled != null, 'at least one non-null update member is required');"],
  ["export const zSessionRevocationRequest = z.object({\n    reason: z.string()\n}).strict();", "export const zSessionRevocationRequest = z.object({\n    reason: z.string().refine((value) => byteLengthBetween(value, 1, 256), 'reason must occupy 1..256 UTF-8 bytes')\n}).strict();"],
  ["export const zServiceAccessTokenRevocationRequest = z.object({\n    reason: z.string().min(1).max(256)\n}).strict();", "export const zServiceAccessTokenRevocationRequest = z.object({\n    reason: z.string().refine((value) => trimmedBytes(value, 256), 'reason must be 1..256 trimmed UTF-8 bytes without NUL')\n}).strict();"],
  ["export const zCreateServicePrincipalRequest = z.object({\n    name: zServicePrincipalName,\n    all_networks: z.boolean(),\n    network_ids: z.array(zIdentifier),\n    permissions: z.array(zAutomationPermission).min(1)\n}).strict();", "export const zCreateServicePrincipalRequest = z.object({\n    name: zServicePrincipalName,\n    all_networks: z.boolean(),\n    network_ids: z.array(zIdentifier),\n    permissions: z.array(zAutomationPermission).min(1)\n}).strict().refine(validServicePrincipalScope, 'service principal scope and permissions must be unique and consistent');"],
  ["export const zTrafficSelector = z.intersection(z.unknown(), z.object({", "export const zTrafficSelector = z.object({"],
  ["    destination_ports: z.array(zPortRange).optional()\n}).strict());", "    destination_ports: z.array(zPortRange).optional()\n}).strict().refine((value) => !value.destination_ports?.length || value.ip_protocol === 'IP_PROTOCOL_TCP' || value.ip_protocol === 'IP_PROTOCOL_UDP', 'destination ports require TCP or UDP');"],
  ["export const zTrafficSelectorInput = z.intersection(z.unknown(), z.object({", "export const zTrafficSelectorInput = z.object({"],
  ["    destination_ports: z.array(zPortRangeInput).optional()\n}).strict());\n\nexport const zUint32", "    destination_ports: z.array(zPortRangeInput).optional()\n}).strict().refine((value) => !value.destination_ports?.length || value.ip_protocol === 'IP_PROTOCOL_TCP' || value.ip_protocol === 'IP_PROTOCOL_UDP', 'destination ports require TCP or UDP');\n\nexport const zUint32"],
  ["    description: z.string().nullish()\n}).strict();", "    description: z.string().nullish().refine((value) => value == null || utf8ByteLength(value) <= 1024 && !value.includes('\\0'), 'description must occupy at most 1024 UTF-8 bytes without NUL')\n}).strict();"],
  ["    description: z.string(),\n    enabled: z.boolean(),", "    description: z.string().refine((value) => utf8ByteLength(value) <= 1024 && !value.includes('\\0'), 'description must occupy at most 1024 UTF-8 bytes without NUL'),\n    enabled: z.boolean(),"],
  ["export const zAuditEvent = z.intersection(z.unknown(), z.object({\n    event_id: zIdentifier,\n    network_id: zIdentifier.optional(),\n    actor_kind: zActorKind,\n    actor_id: zIdentifier.optional(),\n    actor_node_id: zIdentifier.optional(),\n    action: z.string(),\n    target_type: z.string(),\n    target_id: zIdentifier.optional(),\n    details: z.unknown(),\n    created_at_unix_seconds: zUnixSeconds\n}).strict());", "export const zAuditEvent = z.object({\n    event_id: zIdentifier,\n    network_id: zIdentifier.optional(),\n    actor_kind: zActorKind,\n    actor_id: zIdentifier.optional(),\n    actor_node_id: zIdentifier.optional(),\n    action: z.string(),\n    target_type: z.string(),\n    target_id: zIdentifier.optional(),\n    details: z.unknown(),\n    created_at_unix_seconds: zUnixSeconds\n}).strict().refine((value) => {\n    const identified = ['node', 'administrator', 'service_principal', 'recovery_grant'].includes(value.actor_kind);\n    return identified ? value.actor_id !== undefined : value.actor_id === undefined;\n}, 'actor_id presence must match actor_kind');"],
  ["    payload: z.string().regex(/^#!\\/bin\\/bash\\n/),", "    payload: z.string().regex(/^#!\\/bin\\/bash\\n/).refine((value) => utf8ByteLength(value) <= 98304 && !value.includes('\\0'), 'payload must occupy at most 98304 UTF-8 bytes without NUL'),"],
  ["    revocation_reason: z.string().optional()\n}).strict();\n\nexport const zCertificates", "    revocation_reason: z.string().optional().refine((value) => value === undefined || utf8ByteLength(value) <= 1024, 'reason must occupy at most 1024 UTF-8 bytes')\n}).strict();\n\nexport const zCertificates"],
  ["export const zEnrollmentTokenRequest = z.intersection(z.unknown(), z.object({\n    network_id: zIdentifier,\n    user_id: zIdentifier.nullish(),\n    label: z.string().nullish().default(''),\n    expires_at_unix_seconds: zUnixSeconds,\n    enrollment_class: zEnrollmentClass.nullish(),\n    session_lifetime_seconds: z.int().nullish(),\n    requested_name: z.string().nullish(),", "export const zEnrollmentTokenRequest = z.object({\n    network_id: zIdentifier,\n    user_id: zIdentifier.nullish(),\n    label: z.string().nullish().default('').refine((value) => value == null || trimmedBytes(value, 256, true), 'label must be trimmed and at most 256 UTF-8 bytes without NUL'),\n    expires_at_unix_seconds: zUnixSeconds,\n    enrollment_class: zEnrollmentClass.nullish(),\n    session_lifetime_seconds: z.int().nullish(),\n    requested_name: z.string().nullish().refine((value) => value == null || value === '' || trimmedBytes(value, 253), 'requested name must be empty or a valid resource name'),"],
  ["    ]).nullish()\n}).strict());", "    ]).nullish()\n}).strict().refine((value) => {\n    const enrollmentClass = value.enrollment_class ?? 'durable';\n    return enrollmentClass === 'ephemeral'\n        ? value.session_lifetime_seconds != null && value.session_lifetime_seconds >= 300 && value.session_lifetime_seconds <= 86400\n        : value.session_lifetime_seconds == null || value.session_lifetime_seconds === 0;\n}, 'session lifetime must match enrollment class');"],
  ["    revocation_reason: z.string().optional()\n}).strict();\n\nexport const zAdministratorSessions", "    revocation_reason: z.string().optional().refine((value) => value === undefined || utf8ByteLength(value) <= 256, 'reason must occupy at most 256 UTF-8 bytes')\n}).strict();\n\nexport const zAdministratorSessions"],
  ["    description: z.string().nullish().default(''),", "    description: z.string().nullish().default('').refine((value) => value == null || utf8ByteLength(value) <= 1024 && !value.includes('\\0'), 'description must occupy at most 1024 UTF-8 bytes without NUL'),"],
  ["export const zCreateAdministratorRequest = z.intersection(z.unknown(), z.object({\n    username: zUsername,\n    password: zPassword,\n    role: zRole,\n    all_networks: z.boolean().nullish().default(false),\n    network_ids: z.array(zIdentifier).nullish()\n}).strict());", "export const zCreateAdministratorRequest = z.object({\n    username: zUsername,\n    password: zPassword,\n    role: zRole,\n    all_networks: z.boolean().nullish().default(false),\n    network_ids: z.array(zIdentifier).nullish()\n}).strict().refine((value) => validAdministratorAccess({\n    role: value.role,\n    all_networks: value.all_networks ?? false,\n    network_ids: value.network_ids ?? [],\n}), 'administrator scope is inconsistent with role or contains duplicate networks');"],
  ["export const zListAdministratorsQuery = z.object({\n    limit: z.int().gte(1).lte(1000).optional().default(100),\n    username: zUsername.optional()\n}).strict();", "export const zListAdministratorsQuery = z.object({\n    limit: z.int().gte(1).lte(1000).optional().default(100)\n}).strict();"],
  ["    withdrawn_at_unix_seconds: zUnixSeconds.optional()\n}).strict();\n\nexport const zRoutes", "    withdrawn_at_unix_seconds: zUnixSeconds.optional()\n}).strict().refine(validRoute, 'route kind, mode, and prefix must be consistent');\n\nexport const zRoutes"],
  ["export const zEnrollmentToken = z.object({\n    token_id: zIdentifier,\n    enrollment_token: zSecret,\n    user_id: zIdentifier.optional(),\n    expires_at_unix_seconds: zUnixSeconds,\n    enrollment_class: zEnrollmentClass,\n    session_lifetime_seconds: z.int().gte(300).lte(86400).optional(),\n    requested_name: z.string().optional(),", "export const zEnrollmentToken = z.object({\n    token_id: zIdentifier,\n    enrollment_token: zSecret,\n    user_id: zIdentifier.optional(),\n    expires_at_unix_seconds: zUnixSeconds,\n    enrollment_class: zEnrollmentClass,\n    session_lifetime_seconds: z.int().gte(300).lte(86400).optional(),\n    requested_name: zResourceName.optional(),"],
  ["export const zIssueServiceAccessTokenRequest = z.object({\n    label: z.string().min(1).max(64),\n    expires_at_unix_seconds: zUnixSeconds\n}).strict();", "export const zIssueServiceAccessTokenRequest = z.object({\n    label: z.string().refine((value) => trimmedBytes(value, 64), 'label must be 1..64 trimmed UTF-8 bytes without NUL'),\n    expires_at_unix_seconds: zUnixSeconds\n}).strict();"],
  ["    ]).optional()\n}).strict();\n\nexport const zEnrollmentTokenRequest", "    ]).optional()\n}).strict().refine((value) => value.enrollment_class === 'ephemeral'\n    ? value.session_lifetime_seconds !== undefined\n    : value.session_lifetime_seconds === undefined, 'session lifetime must match enrollment class');\n\nexport const zEnrollmentTokenRequest"],
  ["export const zNetwork = z.object({\n    network_id: zIdentifier,\n    name: zResourceName,\n    ipv4_pool: z.string(),\n    ipv6_pool: z.string().optional(),", "export const zNetwork = z.object({\n    network_id: zIdentifier,\n    name: zResourceName,\n    ipv4_pool: z.string().refine((value) => routableCidr(value, 4, 8, 30, true), 'IPv4 pool must be a canonical routable /8../30'),\n    ipv6_pool: z.string().optional().refine((value) => value === undefined || routableCidr(value, 6, 64, 120, true), 'IPv6 pool must be a canonical routable /64../120'),"],
  ["    password_updated_at_unix_seconds: zUnixSeconds\n}).strict();\n\nexport const zAdministratorBootstrapRequest", "    password_updated_at_unix_seconds: zUnixSeconds\n}).strict().refine((value) => validAdministratorAccess(value), 'administrator scope is inconsistent with role or contains duplicate networks');\n\nexport const zAdministratorBootstrapRequest"],
  ["    report: zEndpointRuntimeReport.optional()\n}).strict();\n\nexport const zEndpointStatuses", "    report: zEndpointRuntimeReport.optional()\n}).strict().refine(validEndpointStatus, 'endpoint status freshness, evidence timestamps, and report must be consistent');\n\nexport const zEndpointStatuses"],
  ["    csrf_token: zSecret\n}).strict();\n\nexport const zAdministrators", "    csrf_token: zSecret\n}).strict().refine((value) => validAdministratorAccess(value), 'administrator scope is inconsistent with role or contains duplicate networks');\n\nexport const zAdministrators"],
  ["export const zServiceAccessToken = z.object({\n    token_id: zIdentifier,\n    principal_id: zIdentifier,\n    label: z.string().min(1).max(64),\n    state: zServiceAccessTokenState,\n    created_at_unix_seconds: zUnixSeconds,\n    expires_at_unix_seconds: zUnixSeconds,\n    revoked_at_unix_seconds: zUnixSeconds.optional(),\n    revocation_reason: z.string().min(1).max(256).optional()\n}).strict();", "export const zServiceAccessToken = z.object({\n    token_id: zIdentifier,\n    principal_id: zIdentifier,\n    label: z.string().refine((value) => trimmedBytes(value, 64), 'label must be 1..64 trimmed UTF-8 bytes without NUL'),\n    state: zServiceAccessTokenState,\n    created_at_unix_seconds: zUnixSeconds,\n    expires_at_unix_seconds: zUnixSeconds,\n    revoked_at_unix_seconds: zUnixSeconds.optional(),\n    revocation_reason: z.string().optional().refine((value) => value === undefined || trimmedBytes(value, 256), 'reason must be 1..256 trimmed UTF-8 bytes without NUL')\n}).strict().refine((value) => value.state === 'revoked'\n    ? value.revoked_at_unix_seconds !== undefined && value.revocation_reason !== undefined\n    : value.revoked_at_unix_seconds === undefined && value.revocation_reason === undefined, 'revocation metadata must match token state');"],
  ["export const zServicePrincipal = z.object({\n    principal_id: zIdentifier,\n    name: zServicePrincipalName,\n    enabled: z.boolean(),\n    all_networks: z.boolean(),\n    network_ids: z.array(zIdentifier),\n    permissions: z.array(zAutomationPermission).min(1),\n    created_at_unix_seconds: zUnixSeconds,\n    updated_at_unix_seconds: zUnixSeconds\n}).strict();", "export const zServicePrincipal = z.object({\n    principal_id: zIdentifier,\n    name: zServicePrincipalName,\n    enabled: z.boolean(),\n    all_networks: z.boolean(),\n    network_ids: z.array(zIdentifier),\n    permissions: z.array(zAutomationPermission).min(1),\n    created_at_unix_seconds: zUnixSeconds,\n    updated_at_unix_seconds: zUnixSeconds\n}).strict().refine(validServicePrincipalScope, 'service principal scope and permissions must be unique and consistent');"],
];
for (const [before, after] of zodReplacements) zod = replaceRequired(zod, before, after, before.slice(0, 80));
zod = removeDeclarations(zod, 'const', [
  ...rootOnlyOperations.map((name) => `z${name[0].toUpperCase()}${name.slice(1)}`),
  'zAdministratorCsrfCookie',
  'zAdministratorCsrfHeader',
  'zAdministratorSession2',
  'zRecoveryGrant',
  'zRootBearer',
  'zRotationId',
  'zServiceAccessToken2',
]);
await writeFile(zodPath, zod);

let sdk = await readFile(sdkPath, 'utf8');
for (const operation of rootOnlyOperations) sdk = removeFunction(sdk, operation);
sdk = pruneNamedImports(sdk);
sdk = sdk.replace(/^ {4}\.\.\.options,?\n/gmu, '');
sdk = sdk.replace(/=> options\.client\.(?:delete|get|patch|post|put)<[^\n]+>\(\{\n/gu, (match) => `${match}    ...options,\n`);
sdk = sdk.replaceAll("        ...options.headers\n", '');
sdk = replaceRequired(sdk, 'Client, ClientMeta, Options as Options2', 'InternalTransport as Client, Options as Options2', 'ClientMeta import');
sdk = sdk.replaceAll('returned by `createClient()`', 'injected by `createManagementApi()`');
sdk = replaceRequired(sdk, `    /**
     * You can pass arbitrary values through the \`meta\` object. This can be
     * used to access values that aren't defined as part of the SDK function.
     */
    meta?: keyof ClientMeta extends never ? Record<string, unknown> : ClientMeta;
`, '', 'public SDK metadata escape hatch');
sdk = sdk.replace(
  ' * Owner session or root automation. An exact username filter is accepted only with root automation and cannot be combined with limit.',
  ' * Owner browser session. Automation-only filtering is intentionally absent.',
);
await writeFile(sdkPath, sdk);

const generatedIndex = await readFile(indexPath, 'utf8');
if (!generatedIndex.includes("from './sdk.gen';") || !generatedIndex.includes("from './types.gen';")) {
  throw new Error('generated index has an unexpected shape');
}
await writeFile(indexPath, `// This file is auto-generated by @hey-api/openapi-ts\n\nexport * from './types.gen';\nexport * from './zod.gen';\n`);
await unlink(generatedClientPath);
