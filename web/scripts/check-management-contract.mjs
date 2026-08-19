import { readFile } from 'node:fs/promises';
import console from 'node:console';
import { URL } from 'node:url';

const servicePath = new URL('../../go/internal/controllerservice/service.go', import.meta.url);
const routePoliciesPath = new URL('../../go/internal/adminauth/routes.go', import.meta.url);
const operationPoliciesPath = new URL('../../go/internal/adminauth/model.go', import.meta.url);
const contractPath = new URL('../../api/openapi/management-v1.yaml', import.meta.url);
const componentsPath = new URL('../../api/openapi/components.yaml', import.meta.url);

const [serviceSource, routePoliciesSource, operationPoliciesSource, contractSource, componentsSource] = await Promise.all([
  readFile(servicePath, 'utf8'),
  readFile(routePoliciesPath, 'utf8'),
  readFile(operationPoliciesPath, 'utf8'),
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
const protectedRegistrations = new Set();
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
  const key = `${goMethods[match[1]]} ${match[2]}`;
  addRegistration(goMethods[match[1]], match[2]);
  protectedRegistrations.add(key);
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

const policyRoutes = new Map();
for (const match of routePoliciesSource.matchAll(
  /\{http\.Method(Get|Post|Put|Patch|Delete), "(\/v1\/admin(?:\/[^" ]*)?)", (Operation[A-Za-z0-9]+), Scope[A-Za-z0-9]+, (?:true|false)\}/g,
)) {
  policyRoutes.set(`${goMethods[match[1]]} ${match[2]}`, match[3]);
}

const automationGrantableMatch = /func AutomationGrantable\(operation Operation\) bool \{[\s\S]*?switch operation \{\s*case ([\s\S]*?):\s*return false\s*default:/u.exec(operationPoliciesSource);
const automationExcludedOperations = new Set(
  [...(automationGrantableMatch?.[1] ?? '').matchAll(/\bOperation[A-Za-z0-9]+\b/gu)].map((match) => match[0]),
);
const automationRoutes = new Set(
  [...policyRoutes]
    .filter(([, operation]) => !automationExcludedOperations.has(operation))
    .map(([route]) => route),
);
const documentedAutomationRoutes = new Set(serviceAccessTokenAlternatives.keys());

const difference = (left, right) => [...left].filter((key) => !right.has(key)).sort();
const missing = difference(registered, documented);
const extra = difference(documented, registered);
const missingPolicies = difference(protectedRegistrations, new Set(policyRoutes.keys()));
const extraPolicies = difference(new Set(policyRoutes.keys()), protectedRegistrations);
const missingAutomationSecurity = difference(automationRoutes, documentedAutomationRoutes);
const extraAutomationSecurity = difference(documentedAutomationRoutes, automationRoutes);
const duplicateAutomationSecurity = [...serviceAccessTokenAlternatives]
  .filter(([, count]) => count !== 1)
  .map(([route, count]) => `${route} (${count})`)
  .sort();
const problems = [];
if (duplicateYamlKeys.length) problems.push(`duplicate YAML mapping keys: ${duplicateYamlKeys.join(', ')}`);
if (registered.size !== 66) problems.push(`controller registration count is ${registered.size}, expected 66`);
if (documented.size !== 66) problems.push(`OpenAPI operation count is ${documented.size}, expected 66`);
if (duplicateRegistrations.length) problems.push(`duplicate controller registrations: ${duplicateRegistrations.join(', ')}`);
if (duplicateOperations.length) problems.push(`duplicate OpenAPI operations: ${duplicateOperations.join(', ')}`);
if (missing.length) problems.push(`missing from OpenAPI: ${missing.join(', ')}`);
if (extra.length) problems.push(`not registered by controller: ${extra.join(', ')}`);
if (!automationGrantableMatch || automationExcludedOperations.size === 0) {
  problems.push('could not resolve the controller automation grant boundary');
}
if (missingPolicies.length) problems.push(`registered protected routes without policies: ${missingPolicies.join(', ')}`);
if (extraPolicies.length) problems.push(`policies without registered protected routes: ${extraPolicies.join(', ')}`);
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

console.log(`Management contract has unique YAML keys, matches all 66 registered administrator routes, and documents all ${automationRoutes.size} grantable service-token routes.`);
