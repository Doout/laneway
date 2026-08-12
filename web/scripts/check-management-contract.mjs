import { readFile } from 'node:fs/promises';
import console from 'node:console';
import { URL } from 'node:url';

const servicePath = new URL('../../go/internal/controllerservice/service.go', import.meta.url);
const contractPath = new URL('../../api/openapi/management-v1.yaml', import.meta.url);
const componentsPath = new URL('../../api/openapi/components.yaml', import.meta.url);

const [serviceSource, contractSource, componentsSource] = await Promise.all([
  readFile(servicePath, 'utf8'),
  readFile(contractPath, 'utf8'),
  readFile(componentsPath, 'utf8'),
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

const registered = new Set();
const duplicateRegistrations = [];
const addRegistration = (method, path) => {
  const key = `${method} ${path}`;
  if (registered.has(key)) duplicateRegistrations.push(key);
  registered.add(key);
};

for (const match of serviceSource.matchAll(
  /mux\.HandleFunc\("(GET|POST|PUT|PATCH|DELETE) (\/v1\/admin(?:\/[^" ]*)?)"/g,
)) {
  addRegistration(match[1], match[2]);
}

const goMethods = {
  Delete: 'DELETE',
  Get: 'GET',
  Patch: 'PATCH',
  Post: 'POST',
  Put: 'PUT',
};
for (const match of serviceSource.matchAll(
  /s\.registerManagementRoute\(mux, http\.Method(Get|Post|Put|Patch|Delete), "(\/v1\/admin(?:\/[^" ]*)?)"/g,
)) {
  addRegistration(goMethods[match[1]], match[2]);
}

const documented = new Set();
const duplicateOperations = [];
let currentPath;
for (const line of contractSource.split(/\r?\n/u)) {
  const pathMatch = /^ {2}(\/v1\/admin[^:]*):\s*$/u.exec(line);
  if (pathMatch) {
    currentPath = pathMatch[1];
    continue;
  }
  if (/^ {2}\S/u.test(line)) currentPath = undefined;
  const methodMatch = /^ {4}(get|post|put|patch|delete):\s*$/u.exec(line);
  if (!currentPath || !methodMatch) continue;
  const key = `${methodMatch[1].toUpperCase()} ${currentPath}`;
  if (documented.has(key)) duplicateOperations.push(key);
  documented.add(key);
}

const difference = (left, right) => [...left].filter((key) => !right.has(key)).sort();
const missing = difference(registered, documented);
const extra = difference(documented, registered);
const problems = [];
if (duplicateYamlKeys.length) problems.push(`duplicate YAML mapping keys: ${duplicateYamlKeys.join(', ')}`);
if (registered.size !== 43) problems.push(`controller registration count is ${registered.size}, expected 43`);
if (documented.size !== 43) problems.push(`OpenAPI operation count is ${documented.size}, expected 43`);
if (duplicateRegistrations.length) problems.push(`duplicate controller registrations: ${duplicateRegistrations.join(', ')}`);
if (duplicateOperations.length) problems.push(`duplicate OpenAPI operations: ${duplicateOperations.join(', ')}`);
if (missing.length) problems.push(`missing from OpenAPI: ${missing.join(', ')}`);
if (extra.length) problems.push(`not registered by controller: ${extra.join(', ')}`);

if (problems.length) {
  throw new Error(`management contract route drift:\n- ${problems.join('\n- ')}`);
}

console.log('Management contract has unique YAML keys and matches all 43 registered administrator routes.');
