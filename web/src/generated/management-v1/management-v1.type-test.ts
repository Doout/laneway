import { createManagementApi } from './index';
import * as browserEntry from './index';

type AssertFalse<Value extends false> = Value;
type BrowserEntry = typeof browserEntry;

const api = createManagementApi();

api.listAdministrators({ query: { limit: 10 } });
api.createNetwork({
  body: { name: 'example-network', ipv4_pool: '192.0.2.0/24' },
});

api.listAdministrators({
  query: {
    // @ts-expect-error Browser callers cannot select the root-only username query.
    username: 'owner.example',
  },
});

api.createNetwork({
  body: { name: 'example-network', ipv4_pool: '192.0.2.0/24' },
  // @ts-expect-error Per-call origins are not part of the browser API.
  baseUrl: 'https://example.invalid',
});

api.createNetwork({
  body: { name: 'example-network', ipv4_pool: '192.0.2.0/24' },
  // @ts-expect-error Per-call URLs are fixed by the generated operation.
  url: '/v1/admin/networks',
});

api.createNetwork({
  body: { name: 'example-network', ipv4_pool: '192.0.2.0/24' },
  // @ts-expect-error Per-call headers cannot inject credentials or CSRF.
  headers: { Authorization: 'unavailable' },
});

api.createNetwork({
  body: { name: 'example-network', ipv4_pool: '192.0.2.0/24' },
  // @ts-expect-error Generated validation cannot be replaced by a caller.
  requestValidator: async (value: unknown) => value,
});

api.createNetwork({
  body: { name: 'example-network', ipv4_pool: '192.0.2.0/24' },
  // @ts-expect-error Generated serialization cannot be replaced by a caller.
  bodySerializer: () => 'unvalidated',
});

api.createNetwork({
  // @ts-expect-error Arbitrary request bodies cannot bypass the generated DTO.
  body: { arbitrary: true },
});

// @ts-expect-error The public API has no generic raw request methods.
api.post({ url: '/v1/admin/networks', body: { arbitrary: true } });

type NoRawClientFactory = AssertFalse<'createManagementClient' extends keyof BrowserEntry ? true : false>;
type NoRootProbe = AssertFalse<'probeRootAdministratorCredential' extends keyof typeof api ? true : false>;
type NoBootstrapGrant = AssertFalse<'issueAdministratorBootstrapGrant' extends keyof typeof api ? true : false>;
type NoRecoveryGrant = AssertFalse<'issueAdministratorRecoveryGrant' extends keyof typeof api ? true : false>;
type NoBeginRotation = AssertFalse<'beginRootAdministratorTokenRotation' extends keyof typeof api ? true : false>;
type NoCompleteRotation = AssertFalse<'completeRootAdministratorTokenRotation' extends keyof typeof api ? true : false>;
// @ts-expect-error Root automation credentials are absent from browser types.
type NoRootBearerType = import('./index').RootBearer;
// @ts-expect-error Service access-token credentials are absent from browser types.
type NoServiceAccessTokenCredentialType = import('./index').ServiceAccessToken2;
// @ts-expect-error Configurable origins are absent from browser types.
type NoClientOptionsType = import('./index').ClientOptions;
// @ts-expect-error The generic transport is internal and absent from the browser entry.
type NoInternalTransportType = import('./index').InternalTransport;

export type BrowserSurfaceAssertions =
  | NoRawClientFactory
  | NoRootProbe
  | NoBootstrapGrant
  | NoRecoveryGrant
  | NoBeginRotation
  | NoCompleteRotation
  | NoRootBearerType
  | NoServiceAccessTokenCredentialType
  | NoClientOptionsType
  | NoInternalTransportType;
