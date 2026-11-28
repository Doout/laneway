import { readFile } from 'node:fs/promises';
import console from 'node:console';
import { URL } from 'node:url';

const controller = new URL('../../rust/laneway-controller/src/', import.meta.url);
const contractPath = new URL('../../api/openapi/management-v1.yaml', import.meta.url);
const componentsPath = new URL('../../api/openapi/components.yaml', import.meta.url);
const guidePath = new URL('../../spec/management-api-v1.md', import.meta.url);

// Only the request dispatcher and its route parsers register paths.
const handlers = [
  'http',
  'http/access_admin',
  'http/administrators',
  'http/applications',
  'http/applications/authorization',
  'http/audit',
  'http/automation',
  'http/recovery',
  'http/twingate',
];
const [contractSource, componentsSource, guideSource, accessSource, automationSource, ...routerSources] = await Promise.all([
  readFile(contractPath, 'utf8'),
  readFile(componentsPath, 'utf8'),
  readFile(guidePath, 'utf8'),
  readFile(new URL('access_admin.rs', controller), 'utf8'),
  readFile(new URL('automation.rs', controller), 'utf8'),
  ...handlers.map((handler) => readFile(new URL(`${handler}.rs`, controller), 'utf8')),
]);

const duplicateYamlKeys = [];
const checkDuplicateYamlKeys = (name, source) => {
  const frames = [{ indent: -1, keys: new Set() }];
  let blockScalarIndent;
  source.split(/\r?\n/u).forEach((line, index) => {
    const indentation = /^ */u.exec(line)?.[0].length ?? 0;
    if (blockScalarIndent !== undefined) {
      if (!line.trim() || indentation > blockScalarIndent) return;
      blockScalarIndent = undefined;
    }
    if (!line.trim() || line.trimStart().startsWith('#')) return;

    const match = /^( *)(- )?((?:"[^"]+"|'[^']+'|[^:#][^:]*?)):\s*(.*)$/u.exec(line);
    if (!match) return;
    const sequenceItem = match[2] !== undefined;
    const baseIndent = match[1].length;
    const keyIndent = baseIndent + (sequenceItem ? 2 : 0);
    const key = match[3].trim();
    const value = match[4];

    if (sequenceItem) {
      while (frames.at(-1).indent >= baseIndent) frames.pop();
      frames.push({ indent: baseIndent, keys: new Set() });
    } else {
      while (frames.at(-1).indent >= keyIndent) frames.pop();
    }
    const parent = frames.at(-1);
    if (parent.keys.has(key)) duplicateYamlKeys.push(`${name}:${index + 1} duplicate key ${key}`);
    parent.keys.add(key);
    frames.push({ indent: keyIndent, keys: new Set() });
    if (/^[>|][+-]?$/u.test(value.trim())) blockScalarIndent = keyIndent;
  });
};

checkDuplicateYamlKeys('management-v1.yaml', contractSource);
checkDuplicateYamlKeys('components.yaml', componentsSource);

const canonical = (path) => path.replace(/\{[^}]+\}/gu, '{}');
const documentedExtensions = new Map(
  [...guideSource.matchAll(/^\| `(\/v1\/admin\/[^`]+)` \| ([A-Z, ]+) \|/gmu)]
    .map(([, path, methods]) => [canonical(path), new Set(methods.split(', '))]),
);

const registeredPaths = new Map();
const registeredMethods = new Map();
const missingAccessMethods = [];
const duplicateRegistrations = [];

// The handlers with an Allow table use it to describe supported methods.
function allowedMethods(source) {
  const methods = new Map();
  for (const [, patterns, allowed] of source.matchAll(
    /((?:(?:Self|Route)::\w+(?:\([^()]*\))?(?:\s*\|\s*)?\s*)+) => "([A-Z, ]+)",/gu,
  )) {
    for (const [, route] of patterns.matchAll(/(?:Self|Route)::(\w+)/gu)) {
      methods.set(route, allowed.split(', ').filter((method) => method !== 'HEAD'));
    }
  }
  return methods;
}

function register(path, handler, methods) {
  // The main dispatcher checks the networks path both as a string and as
  // path components to handle GET and POST. Count the same handler once.
  const previous = registeredPaths.get(path);
  const sharedNetworkDispatch = path === '/v1/admin/networks' && handler === 'http' && previous === handler;
  if (previous !== undefined && !sharedNetworkDispatch) {
    duplicateRegistrations.push(path);
  }
  registeredPaths.set(path, handler);
  if (methods?.length) registeredMethods.set(path, methods);
}

for (const [index, source] of routerSources.entries()) {
  const handler = handlers[index];
  const methods = allowedMethods(source);
  for (const [, pattern, arm] of source.matchAll(
    /\[\s*""\s*,\s*"v1"\s*,\s*"admin"((?:\s*,\s*(?:"[^"\n]+"|\w+))+)\s*,?\s*\]\s*=>\s*(?:\{\s*)?(?:Some\()?((?:Self::)?\w+)?/gu,
  )) {
    const segments = pattern.split(',').slice(1).map((segment) => segment.trim());
    const path = `/v1/admin/${segments.map((segment) => (
      segment.startsWith('"') ? segment.slice(1, -1) : '{}'
    )).join('/')}`;
    const methodSet = methods.get(arm?.replace(/^Self::/u, ''));
    register(path, handler, methodSet);
    if (handler === 'http/access_admin' && !methodSet) missingAccessMethods.push(path);
  }
  for (const [, path] of source.matchAll(/path == "(\/v1\/admin(?:\/[^" ]*)?)"/gu)) {
    register(path, handler);
  }
}

const documented = new Set();
const serviceAccessTokenAlternatives = new Map();
const duplicateOperations = [];
let currentPath;
let currentOperation;
let inOperationSecurity = false;
for (const line of contractSource.split(/\r?\n/u)) {
  const pathMatch = /^ {2}(\/v1\/admin[^:]*):\s*$/u.exec(line);
  if (pathMatch) {
    currentPath = pathMatch[1];
    currentOperation = undefined;
    inOperationSecurity = false;
    continue;
  }
  if (/^(?: {2}\S|\S)/u.test(line)) {
    currentPath = undefined;
    currentOperation = undefined;
    inOperationSecurity = false;
  }
  const methodMatch = /^ {4}(get|post|put|patch|delete):\s*$/u.exec(line);
  if (currentPath && methodMatch) {
    const key = `${methodMatch[1].toUpperCase()} ${currentPath}`;
    if (documented.has(key)) duplicateOperations.push(key);
    documented.add(key);
    currentOperation = key;
    inOperationSecurity = false;
    continue;
  }
  if (!currentOperation) continue;
  if (/^ {6}security:\s*$/u.test(line)) {
    inOperationSecurity = true;
    continue;
  }
  if (/^ {6}\S/u.test(line)) inOperationSecurity = false;
  if (inOperationSecurity && /^ {8}- serviceAccessToken:\s*\[\]\s*$/u.test(line)) {
    serviceAccessTokenAlternatives.set(
      currentOperation,
      (serviceAccessTokenAlternatives.get(currentOperation) ?? 0) + 1,
    );
  }
}

// Service tokens can enter the access-action and audit handlers. The main
// dispatcher delegates only these inventory and enrollment operations to
// the service-token-aware store; its other endpoints are session/root only.
const dispatcherAutomation = new Map([
  ['GET /v1/admin/networks', 'network.list'],
  ['GET /v1/admin/networks/{}', 'network.read'],
  ['GET /v1/admin/networks/{}/nodes', 'node.read'],
  ['POST /v1/admin/networks', 'network.create'],
  ['POST /v1/admin/enrollment-tokens', 'enrollment.issue'],
  ['POST /v1/admin/bootstrap-bundles', 'bootstrap_bundle.create'],
  ['POST /v1/admin/networks/{}/node-installers', 'enrollment.issue'],
]);
const permissionNames = (body) => new Set(
  [...(body ?? '').matchAll(/"([a-z_]+\.[a-z_]+)"/gu)].map(([, permission]) => permission),
);
const accessPermissions = permissionNames(
  /fn permission\(&self\) -> &'static str \{([\s\S]*?)\n {4}\}/u.exec(accessSource)?.[1],
);
const delegablePermissions = permissionNames(
  /fn authority\(op: &str\) -> Option<bool> \{([\s\S]*?)\n\}/u.exec(automationSource)?.[1],
);
const expectedPermissions = new Set([
  ...accessPermissions,
  ...dispatcherAutomation.values(),
  'audit.read',
  'audit.read_global',
]);
const difference = (left, right) => [...left].filter((key) => !right.has(key)).sort();
const documentedPaths = new Set();
const documentedMethods = new Map();
const automationRoutes = new Set();
for (const route of documented) {
  const [method, rawPath] = route.split(' ');
  const path = canonical(rawPath);
  documentedPaths.add(path);
  if (!documentedMethods.has(path)) documentedMethods.set(path, new Set());
  documentedMethods.get(path).add(method);
  const handler = registeredPaths.get(path);
  if (handler === 'http/access_admin' || handler === 'http/audit'
    || dispatcherAutomation.has(`${method} ${path}`)) {
    automationRoutes.add(route);
  }
}

const missing = difference(registeredPaths.keys(), new Set([...documentedPaths, ...documentedExtensions.keys()]));
const missingPermissions = difference(expectedPermissions, delegablePermissions);
const extra = difference(documentedPaths, new Set(registeredPaths.keys()));
const staleExtensions = difference(documentedExtensions.keys(), new Set(registeredPaths.keys()));
const overlappingExtensions = [...documentedExtensions.keys()].filter((path) => documentedPaths.has(path));
const methodDrift = [];
for (const [path, expected] of registeredMethods) {
  const actual = documentedMethods.get(path) ?? documentedExtensions.get(path);
  if (actual && (expected.length !== actual.size || expected.some((method) => !actual.has(method)))) {
    methodDrift.push(`${path} (controller: ${expected.join(', ')}, documented: ${[...actual].join(', ')})`);
  }
}
const documentedAutomationRoutes = new Set(serviceAccessTokenAlternatives.keys());
const missingAutomationSecurity = difference(automationRoutes, documentedAutomationRoutes);
const extraAutomationSecurity = difference(documentedAutomationRoutes, automationRoutes);
const duplicateAutomationSecurity = [...serviceAccessTokenAlternatives]
  .filter(([, count]) => count !== 1)
  .map(([route, count]) => `${route} (${count})`)
  .sort();
const problems = [];
if (duplicateYamlKeys.length) problems.push(`duplicate YAML mapping keys: ${duplicateYamlKeys.join(', ')}`);
if (duplicateRegistrations.length) problems.push(`duplicate controller registrations: ${duplicateRegistrations.join(', ')}`);
if (duplicateOperations.length) problems.push(`duplicate OpenAPI operations: ${duplicateOperations.join(', ')}`);
if (missing.length) problems.push(`missing from OpenAPI or extension inventory: ${missing.join(', ')}`);
if (extra.length) problems.push(`not registered by controller: ${extra.join(', ')}`);
if (staleExtensions.length) problems.push(`extensions no longer served: ${staleExtensions.join(', ')}`);
if (overlappingExtensions.length) problems.push(`extensions already in OpenAPI: ${overlappingExtensions.join(', ')}`);
if (methodDrift.length) problems.push(`controller method drift: ${methodDrift.join(', ')}`);
if (missingAccessMethods.length) {
  problems.push(`missing controller access methods: ${missingAccessMethods.join(', ')}`);
}
if (!accessPermissions.size || missingPermissions.length) {
  problems.push(`service-token permissions no longer match the controller: ${missingPermissions.join(', ')}`);
}
if (missingAutomationSecurity.length) {
  problems.push(`grantable service-token routes missing the OpenAPI security alternative: ${missingAutomationSecurity.join(', ')}`);
}
if (extraAutomationSecurity.length) {
  problems.push(`OpenAPI exposes service tokens on non-grantable routes: ${extraAutomationSecurity.join(', ')}`);
}
if (duplicateAutomationSecurity.length) {
  problems.push(`duplicate OpenAPI service-token security alternatives: ${duplicateAutomationSecurity.join(', ')}`);
}

if (problems.length) {
  throw new Error(`management contract route drift:\n- ${problems.join('\n- ')}`);
}

console.log(`Management contract has unique YAML keys and documents ${documented.size} administrator operations on ${documentedPaths.size} controller paths. ${documentedExtensions.size} extension paths are tracked separately.`);
