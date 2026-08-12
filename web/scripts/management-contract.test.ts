import { readFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import { describe, expect, it, vi } from 'vitest'

import { createInternalTransport } from '../src/generated/management-v1/transport'
import { createManagementApi } from '../src/generated/management-v1/client'
import {
  createNetwork,
  getAdministratorAuthState,
} from '../src/generated/management-v1/generated/sdk.gen'
import {
  zAdministratorAccessPatch,
  zAdministratorUpdateRequest,
  zAssignRouteRequest,
  zAuditEvent,
  zBootstrapBundleRequest,
  zCreateAclRuleRequest,
  zCreateAdministratorRequest,
  zEnrollmentTokenRequest,
  zErrorEnvelope,
  zListAdministratorsQuery,
  zNetwork,
  zNetworkRequest,
  zNodeCapabilitiesRequest,
  zPassword,
  zPortRange,
  zProtoBytes16,
  zProtoIpPrefix,
  zRelayEndpoint,
  zRequestId,
  zResourceName,
  zRevocationRequest,
  zSessionRevocationRequest,
  zTrafficSelector,
  zTrafficSelectorInput,
  zUint64,
  zUnixSeconds,
  zUpdateAclRuleRequest,
  zUpdateRelayRequest,
} from '../src/generated/management-v1/generated/zod.gen'

type Parsable = {
  safeParse: (value: unknown) => { success: boolean }
}

const accepted = (schema: Parsable, value: unknown) => {
  expect(schema.safeParse(value).success).toBe(true)
}

const rejected = (schema: Parsable, value: unknown) => {
  expect(schema.safeParse(value).success).toBe(false)
}

const networkId = '1'.repeat(32)
const nodeId = '2'.repeat(32)
const principalId = '3'.repeat(32)
const eventId = '4'.repeat(32)
const validPassword = 'correct horse battery staple'

const validNetworkRequest = {
  name: 'example-network',
  ipv4_pool: '192.0.2.0/24',
}

const validNetwork = {
  network_id: networkId,
  ...validNetworkRequest,
  configuration_epoch: 1,
  created_at_unix_seconds: 1,
}

describe('generated strict DTOs and scalar boundaries', () => {
  it('rejects unknown request and response members', () => {
    accepted(zNetworkRequest, validNetworkRequest)
    rejected(zNetworkRequest, { ...validNetworkRequest, unexpected: true })

    accepted(zNetwork, validNetwork)
    rejected(zNetwork, { ...validNetwork, unexpected: true })
  })

  it('accepts only opaque lowercase 32-hex request IDs', () => {
    accepted(zRequestId, '0123456789abcdef0123456789abcdef')
    rejected(zRequestId, '0123456789ABCDEF0123456789ABCDEF')
    rejected(zRequestId, '0'.repeat(31))
    rejected(zRequestId, '0'.repeat(33))

    accepted(zErrorEnvelope, {
      request_id: 'a'.repeat(32),
      code: 'ERROR_CODE_MALFORMED',
      detail: 'invalid request',
      retryable: false,
    })
    rejected(zErrorEnvelope, {
      request_id: 'request-1',
      code: 'ERROR_CODE_MALFORMED',
      detail: 'invalid request',
      retryable: false,
    })
  })

  it('keeps integer wire values as safe JavaScript numbers', () => {
    accepted(zUint64, Number.MAX_SAFE_INTEGER)
    rejected(zUint64, Number.MAX_SAFE_INTEGER + 1)
    rejected(zUint64, 1n)

    accepted(zUnixSeconds, Number.MIN_SAFE_INTEGER)
    accepted(zUnixSeconds, Number.MAX_SAFE_INTEGER)
    rejected(zUnixSeconds, Number.MIN_SAFE_INTEGER - 1)
    rejected(zUnixSeconds, Number.MAX_SAFE_INTEGER + 1)
    rejected(zUnixSeconds, 1n)
  })
})

describe('UTF-8 byte limits', () => {
  it('enforces password and resource-name byte limits', () => {
    accepted(zPassword, 'a'.repeat(15))
    accepted(zPassword, 'é'.repeat(8))
    accepted(zPassword, 'é'.repeat(512))
    rejected(zPassword, 'é'.repeat(7))
    rejected(zPassword, 'é'.repeat(513))

    accepted(zResourceName, 'é'.repeat(126))
    rejected(zResourceName, 'é'.repeat(127))
    rejected(zResourceName, '')
    rejected(zResourceName, ' padded')
    rejected(zResourceName, 'padded ')
    rejected(zResourceName, '\u0085padded')
    accepted(zResourceName, '\ufeffnot-go-whitespace')
    rejected(zResourceName, 'embedded\0nul')
  })

  it('enforces enrollment label and requested-name rules by byte length', () => {
    const base = {
      network_id: networkId,
      expires_at_unix_seconds: 2_000_000_000,
    }

    accepted(zEnrollmentTokenRequest, base)
    accepted(zEnrollmentTokenRequest, { ...base, label: '' })
    accepted(zEnrollmentTokenRequest, { ...base, label: 'é'.repeat(128) })
    rejected(zEnrollmentTokenRequest, { ...base, label: 'é'.repeat(129) })
    rejected(zEnrollmentTokenRequest, { ...base, label: ' padded' })
    rejected(zEnrollmentTokenRequest, { ...base, label: 'nul\0label' })
    accepted(zEnrollmentTokenRequest, { ...base, requested_name: 'é'.repeat(126) })
    rejected(zEnrollmentTokenRequest, { ...base, requested_name: 'é'.repeat(127) })
  })

  it('enforces revocation-reason byte limits without character-count drift', () => {
    accepted(zRevocationRequest, { reason: 'é'.repeat(512) })
    rejected(zRevocationRequest, { reason: 'é'.repeat(513) })
    rejected(zRevocationRequest, { reason: '' })
    rejected(zRevocationRequest, { reason: ' padded' })

    accepted(zSessionRevocationRequest, { reason: 'é'.repeat(128) })
    rejected(zSessionRevocationRequest, { reason: 'é'.repeat(129) })
    rejected(zSessionRevocationRequest, { reason: '' })
  })

  it('enforces bootstrap payload and ACL-description byte limits', () => {
    const prefix = '#!/bin/bash\n'
    const remainingBytes = 98_304 - new TextEncoder().encode(prefix).byteLength
    const maximumPayload = prefix + 'é'.repeat(remainingBytes / 2)
    const selector = { ip_protocol: 'IP_PROTOCOL_ANY' }

    accepted(zBootstrapBundleRequest, {
      payload: maximumPayload,
      expires_at_unix_seconds: 2_000_000_000,
    })
    rejected(zBootstrapBundleRequest, {
      payload: `${maximumPayload}é`,
      expires_at_unix_seconds: 2_000_000_000,
    })
    rejected(zBootstrapBundleRequest, {
      payload: `${prefix}echo bad\0value`,
      expires_at_unix_seconds: 2_000_000_000,
    })

    for (const schema of [zCreateAclRuleRequest, zUpdateAclRuleRequest]) {
      accepted(schema, {
        action: 'accept',
        selector,
        description: 'é'.repeat(512),
      })
      rejected(schema, {
        action: 'accept',
        selector,
        description: 'é'.repeat(513),
      })
      rejected(schema, {
        action: 'accept',
        selector,
        description: 'bad\0description',
      })
    }
  })
})

describe('network and protobuf-shaped refinements', () => {
  it('requires nonzero canonical 16-byte protobuf IDs', () => {
    accepted(zProtoBytes16, 'AAAAAAAAAAAAAAAAAAAAAQ==')
    rejected(zProtoBytes16, 'AAAAAAAAAAAAAAAAAAAAAA==')
    rejected(zProtoBytes16, 'AAAAAAAAAAAAAAAAAAAAAB==')
    rejected(zProtoBytes16, 'AAAAAAAAAAAAAAAAAAAA')
  })

  it('checks protobuf IP-prefix family bounds and masked network bits', () => {
    accepted(zProtoIpPrefix, { address: 'wAACAA==', prefix_length: 24 })
    rejected(zProtoIpPrefix, { address: 'wAACAQ==', prefix_length: 24 })
    rejected(zProtoIpPrefix, { address: 'wAACAA==', prefix_length: 33 })

    accepted(zProtoIpPrefix, {
      address: 'IAENuAAAAAAAAAAAAAAAAA==',
      prefix_length: 64,
    })
    rejected(zProtoIpPrefix, {
      address: 'IAENuAAAAAAAAAAAAAAAAQ==',
      prefix_length: 64,
    })
    rejected(zProtoIpPrefix, {
      address: 'IAENuAAAAAAAAAAAAAAAAA==',
      prefix_length: 129,
    })
  })

  it('checks ordered port ranges and restricts ports to TCP or UDP', () => {
    accepted(zPortRange, { first: 443, last: 443 })
    accepted(zPortRange, { first: 80, last: 443 })
    rejected(zPortRange, { first: 443, last: 80 })

    accepted(zTrafficSelector, {
      ip_protocol: 'IP_PROTOCOL_TCP',
      destination_ports: [{ first: 443, last: 443 }],
    })
    accepted(zTrafficSelector, {
      ip_protocol: 'IP_PROTOCOL_UDP',
      destination_ports: [{ first: 53, last: 53 }],
    })
    rejected(zTrafficSelector, {
      ip_protocol: 'IP_PROTOCOL_ICMP',
      destination_ports: [{ first: 8, last: 8 }],
    })
  })

  it('round-trips canonical selector responses and normalizes quoted decimal uint32 input', () => {
    const canonical = {
      source_node_ids: ['AAAAAAAAAAAAAAAAAAAAAQ=='],
      source_prefixes: [{ address: 'wAACAA==', prefix_length: 24 }],
      destination_node_ids: ['AAAAAAAAAAAAAAAAAAAAAg=='],
      destination_prefixes: [{
        address: 'IAENuAAAAAAAAAAAAAAAAA==',
        prefix_length: 64,
      }],
      ip_protocol: 'IP_PROTOCOL_TCP' as const,
      destination_ports: [{ first: 80, last: 443 }],
    }

    expect(zTrafficSelector.parse(canonical)).toEqual(canonical)
    expect(zTrafficSelectorInput.parse(canonical)).toEqual(canonical)
    expect(zTrafficSelectorInput.parse({
      ip_protocol: 'IP_PROTOCOL_TCP',
      source_prefixes: [{ address: 'wAACAA==', prefix_length: '024' }],
      destination_ports: [{ first: '080', last: '443' }],
    })).toEqual({
      ip_protocol: 'IP_PROTOCOL_TCP',
      source_prefixes: [{ address: 'wAACAA==', prefix_length: 24 }],
      destination_ports: [{ first: 80, last: 443 }],
    })
  })

  it('keeps permissive protobuf JSON aliases outside the browser selector subset', () => {
    for (const selector of [
      { ipProtocol: 'IP_PROTOCOL_ANY' },
      { ip_protocol: 256 },
      { ip_protocol: 'IP_PROTOCOL_ANY', source_node_ids: null },
      { ip_protocol: 'IP_PROTOCOL_ANY', source_node_ids: ['AAAAAAAAAAAAAAAAAAAAAQ'] },
      { ip_protocol: 'IP_PROTOCOL_ANY', source_node_ids: ['_____________________w=='] },
      {
        ip_protocol: 'IP_PROTOCOL_UDP',
        source_prefixes: [{ address: 'wAACAA==', prefix_length: '1e-1000' }],
      },
    ]) {
      rejected(zTrafficSelectorInput, selector)
    }
  })

  it('accepts only canonical routable network pools in their allowed ranges', () => {
    accepted(zNetworkRequest, {
      name: 'dual-stack-network',
      ipv4_pool: '198.51.100.0/24',
      ipv6_pool: '2001:db8::/64',
    })
    accepted(zNetworkRequest, {
      name: 'small-network',
      ipv4_pool: '192.0.2.0/30',
      ipv6_pool: '2001:db8:1::/120',
    })

    for (const ipv4_pool of [
      '192.0.2.1/24',
      '192.0.0.0/7',
      '192.0.2.0/31',
      '127.0.0.0/8',
      '169.254.0.0/16',
      '224.0.0.0/4',
      '2001:db8::/64',
    ]) {
      rejected(zNetworkRequest, { name: 'invalid-network', ipv4_pool })
    }

    for (const ipv6_pool of [
      '2001:db8::1/64',
      '2001:db8::/63',
      '2001:db8::/121',
      'fe80::/64',
      'ff00::/64',
      '192.0.2.0/24',
    ]) {
      rejected(zNetworkRequest, {
        name: 'invalid-network',
        ipv4_pool: '192.0.2.0/24',
        ipv6_pool,
      })
    }
  })

  it('requires masked non-default assignment prefixes and accepts normalized IPv6 spelling', () => {
    const base = {
      network_id: networkId,
      node_id: nodeId,
      mode: 'nat',
    }
    accepted(zAssignRouteRequest, { ...base, prefix: '192.0.2.0/24' })
    accepted(zAssignRouteRequest, { ...base, prefix: '2001:db8::/64' })
    accepted(zAssignRouteRequest, { ...base, prefix: '2001:0db8::/64' })
    rejected(zAssignRouteRequest, { ...base, prefix: '192.0.2.1/24' })
    rejected(zAssignRouteRequest, { ...base, prefix: '0.0.0.0/0' })
    rejected(zAssignRouteRequest, { ...base, prefix: '::/0' })
  })

  it('accepts only canonical usable relay host-and-port values', () => {
    for (const endpoint of [
      'relay.example.test:4433',
      'relay.example.test:0443',
      '192.0.2.4:8443',
      '[2001:db8::1]:4433',
      '[2001:db8::192.0.2.1]:4433',
      '[192.0.2.4]:8443',
      '[Relay.Example.Test.]:0443',
    ]) {
      accepted(zRelayEndpoint, endpoint)
    }

    for (const endpoint of [
      'https://relay.example.test:4433',
      'relay.example.test',
      'relay.example.test:0',
      'relay.example.test:+443',
      'bad host:4433',
      '0.0.0.0:4433',
      '224.0.0.1:4433',
      '[::]:4433',
      '[ff02::1]:4433',
      '[::ffff:192.0.2.1]:4433',
      'İ:4433',
    ]) {
      rejected(zRelayEndpoint, endpoint)
    }
  })
})

describe('administrator, enrollment, and audit invariants', () => {
  const scopedAccess = {
    role: 'operator',
    all_networks: false,
    network_ids: [networkId],
  }
  const ownerAccess = {
    role: 'owner',
    all_networks: true,
    network_ids: [],
  }

  it('enforces owner and all-network scope rules on create and access DTOs', () => {
    accepted(zCreateAdministratorRequest, {
      username: 'operator.example',
      password: validPassword,
      role: 'operator',
      network_ids: [networkId],
    })
    accepted(zCreateAdministratorRequest, {
      username: 'owner.example',
      password: validPassword,
      ...ownerAccess,
    })
    rejected(zCreateAdministratorRequest, {
      username: 'owner.example',
      password: validPassword,
      role: 'owner',
      all_networks: false,
    })
    rejected(zCreateAdministratorRequest, {
      username: 'operator.example',
      password: validPassword,
      role: 'operator',
      all_networks: true,
      network_ids: [networkId],
    })

    accepted(zAdministratorAccessPatch, scopedAccess)
    accepted(zAdministratorAccessPatch, ownerAccess)
    rejected(zAdministratorAccessPatch, { ...ownerAccess, all_networks: false })
    rejected(zAdministratorAccessPatch, {
      ...scopedAccess,
      all_networks: true,
    })
  })

  it('requires at least one non-null administrator update member', () => {
    accepted(zAdministratorUpdateRequest, { enabled: false })
    accepted(zAdministratorUpdateRequest, { access: scopedAccess })
    accepted(zAdministratorUpdateRequest, { access: scopedAccess, enabled: null })
    rejected(zAdministratorUpdateRequest, {})
    rejected(zAdministratorUpdateRequest, { access: null })
    rejected(zAdministratorUpdateRequest, { enabled: null })
    rejected(zAdministratorUpdateRequest, { access: null, enabled: null })
  })

  it('requires ephemeral enrollment lifetimes and forbids them otherwise', () => {
    const base = {
      network_id: networkId,
      expires_at_unix_seconds: 2_000_000_000,
    }
    accepted(zEnrollmentTokenRequest, base)
    accepted(zEnrollmentTokenRequest, {
      ...base,
      enrollment_class: 'ephemeral',
      session_lifetime_seconds: 300,
    })
    rejected(zEnrollmentTokenRequest, {
      ...base,
      enrollment_class: 'ephemeral',
    })
    rejected(zEnrollmentTokenRequest, {
      ...base,
      enrollment_class: 'durable',
      session_lifetime_seconds: 300,
    })
    rejected(zEnrollmentTokenRequest, {
      ...base,
      enrollment_class: 'remembered',
      session_lifetime_seconds: 300,
    })
    rejected(zEnrollmentTokenRequest, {
      ...base,
      session_lifetime_seconds: 300,
    })
  })

  it('accepts explicit null where Go JSON decoding applies scalar zero values', () => {
    const enrollment = {
      network_id: networkId,
      expires_at_unix_seconds: 2_000_000_000,
    }
    accepted(zEnrollmentTokenRequest, {
      ...enrollment,
      enabled_capabilities: null,
      enrollment_class: null,
      label: null,
      requested_name: null,
      session_lifetime_seconds: null,
    })
    accepted(zEnrollmentTokenRequest, { ...enrollment, session_lifetime_seconds: 0 })
    accepted(zAssignRouteRequest, {
      network_id: networkId,
      node_id: nodeId,
      prefix: '192.0.2.0/24',
      mode: 'nat',
      metric: null,
    })
    accepted(zNodeCapabilitiesRequest, { enabled_capabilities: null })
    accepted(zNetworkRequest, { ...validNetworkRequest, network_id: null, ipv6_pool: null })
    accepted(zCreateAdministratorRequest, {
      username: 'operator.example',
      password: validPassword,
      role: 'operator',
      all_networks: null,
    })
    accepted(zUpdateRelayRequest, {
      name: 'relay',
      endpoint: 'relay.example.test:4433',
      enabled: null,
    })
    for (const schema of [zCreateAclRuleRequest, zUpdateAclRuleRequest]) {
      accepted(schema, {
        action: 'accept',
        selector: { ip_protocol: 'IP_PROTOCOL_ANY' },
        priority: null,
        description: null,
        ...(schema === zUpdateAclRuleRequest ? { enabled: null } : {}),
      })
    }
  })

  it('requires actor IDs only for durable identified actor kinds', () => {
    const base = {
      event_id: eventId,
      action: 'network.create',
      target_type: 'network',
      details: {},
      created_at_unix_seconds: 1,
    }

    for (const actor_kind of [
      'node',
      'administrator',
      'service_principal',
      'recovery_grant',
    ]) {
      accepted(zAuditEvent, { ...base, actor_kind, actor_id: principalId })
      rejected(zAuditEvent, { ...base, actor_kind })
    }

    for (const actor_kind of ['system', 'unauthenticated', 'legacy_unknown']) {
      accepted(zAuditEvent, { ...base, actor_kind })
      rejected(zAuditEvent, { ...base, actor_kind, actor_id: principalId })
    }
  })
})

describe('browser management transport', () => {
  it('ignores caller transport overrides and sends one fixed same-origin request', async () => {
    const responseValidatorOverride = vi.fn(async () => undefined)
    const requestValidatorOverride = vi.fn(async () => undefined)
    const bodySerializerOverride = vi.fn(() => 'compromised')
    const querySerializerOverride = vi.fn(() => '?compromised=true')
    const optionFetchOverride = vi.fn(async () => {
      throw new Error('caller fetch override was used')
    })
    const csrfToken = vi.fn(() => 'csrf-from-callback')
    const configuredFetch = vi.fn(async () => new Response(JSON.stringify(validNetwork), {
      status: 201,
      headers: { 'Content-Type': 'application/json' },
    }))
    const client = createInternalTransport({
      csrfToken,
      fetch: configuredFetch as unknown as typeof fetch,
    })

    const options = {
      client,
      body: validNetworkRequest,
      url: 'https://attacker.invalid/unsafe',
      baseUrl: 'https://attacker.invalid',
      method: 'DELETE',
      bodySerializer: bodySerializerOverride,
      querySerializer: querySerializerOverride,
      requestValidator: requestValidatorOverride,
      responseValidator: responseValidatorOverride,
      fetch: optionFetchOverride,
      credentials: 'omit',
      redirect: 'follow',
      parseAs: 'text',
      headers: {
        Authorization: 'Bearer caller-controlled',
        'X-Laneway-CSRF': 'caller-controlled',
      },
    } as unknown as Parameters<typeof createNetwork>[0]

    await createNetwork(options)

    expect(configuredFetch).toHaveBeenCalledTimes(1)
    expect(optionFetchOverride).not.toHaveBeenCalled()
    expect(bodySerializerOverride).not.toHaveBeenCalled()
    expect(querySerializerOverride).not.toHaveBeenCalled()
    expect(requestValidatorOverride).not.toHaveBeenCalled()
    expect(responseValidatorOverride).not.toHaveBeenCalled()
    expect(csrfToken).toHaveBeenCalledTimes(1)

    const input = configuredFetch.mock.calls[0]?.[0]
    expect(input).toBeInstanceOf(Request)
    const request = input as Request
    const requestUrl = new URL(request.url)
    expect(requestUrl.origin).toBe(window.location.origin)
    expect(requestUrl.pathname).toBe('/v1/admin/networks')
    expect(requestUrl.search).toBe('')
    expect(request.method).toBe('POST')
    expect(request.credentials).toBe('same-origin')
    expect(request.redirect).toBe('error')
    expect(request.headers.get('Authorization')).toBeNull()
    expect(request.headers.get('X-Laneway-CSRF')).toBe('csrf-from-callback')
    expect(request.headers.get('Content-Type')).toBe('application/json')
    await expect(request.clone().json()).resolves.toEqual(validNetworkRequest)
  })

  it('retains generated response validation when a caller supplies a replacement', async () => {
    const replacement = vi.fn(async () => undefined)
    const configuredFetch = vi.fn(async () => new Response(JSON.stringify({ state: 'compromised' }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }))
    const client = createInternalTransport({
      fetch: configuredFetch as unknown as typeof fetch,
    })

    await expect(getAdministratorAuthState({
      client,
      responseValidator: replacement,
    } as unknown as Parameters<typeof getAdministratorAuthState>[0])).rejects.toBeDefined()
    expect(replacement).not.toHaveBeenCalled()
  })

  it('retains generated request validation when a caller supplies a replacement', async () => {
    const replacement = vi.fn(async () => undefined)
    const configuredFetch = vi.fn()
    const client = createInternalTransport({
      fetch: configuredFetch as unknown as typeof fetch,
    })

    await expect(createNetwork({
      client,
      body: { ...validNetworkRequest, unexpected: true },
      requestValidator: replacement,
    } as unknown as Parameters<typeof createNetwork>[0])).rejects.toBeDefined()
    expect(replacement).not.toHaveBeenCalled()
    expect(configuredFetch).not.toHaveBeenCalled()
  })

  it('does not consult the CSRF callback for safe requests', async () => {
    const csrfToken = vi.fn(() => 'csrf-from-callback')
    const configuredFetch = vi.fn(async () => new Response(JSON.stringify({ state: 'sign_in' }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }))
    const client = createInternalTransport({
      csrfToken,
      fetch: configuredFetch as unknown as typeof fetch,
    })

    await getAdministratorAuthState({ client })
    expect(csrfToken).not.toHaveBeenCalled()
    const request = configuredFetch.mock.calls[0]?.[0] as Request
    expect(request.headers.get('X-Laneway-CSRF')).toBeNull()
  })

  it('rejects caller-controlled credential, context, and CSRF headers', async () => {
    const client = createInternalTransport({
      fetch: vi.fn() as unknown as typeof fetch,
    })
    for (const headers of [
      { Authorization: 'Bearer caller-controlled' },
      { Cookie: 'session=caller-controlled' },
      { Origin: 'https://attacker.invalid' },
      { 'Sec-Fetch-Site': 'cross-site' },
      { 'X-Laneway-CSRF': 'caller-controlled' },
    ]) {
      await expect(getAdministratorAuthState({
        client,
        headers,
      } as unknown as Parameters<typeof getAdministratorAuthState>[0])).rejects.toThrow(/controlled|unavailable/iu)
    }
  })

  it('rejects every root-only operation, recovery grant, and username filter', async () => {
    const configuredFetch = vi.fn()
    const client = createInternalTransport({
      fetch: configuredFetch as unknown as typeof fetch,
    })
    const unavailable = [
      client.get({ url: '/v1/admin/auth/root' }),
      client.get({ url: '/v1/admin/auth/%72oot' }),
      client.get({ url: '/v1/admin/placeholder/../auth/root' }),
      client.get({ url: '/v1/admin/auth\\root' }),
      client.post({ url: '/v1/admin/auth/bootstrap-grants' }),
      client.post({ url: `/v1/admin/auth/root-token-rotations/${eventId}/begin` }),
      client.post({ url: `/v1/admin/auth/root-token-rotations/${eventId}/complete` }),
      client.post({ url: `/v1/admin/administrators/${principalId}/recovery-grants` }),
      client.get({
        query: { username: 'owner.example' },
        url: '/v1/admin/administrators',
      }),
    ]

    await Promise.all(unavailable.map(async (result) => {
      await expect(result).rejects.toThrow(/unavailable/iu)
    }))
    expect(configuredFetch).not.toHaveBeenCalled()
    rejected(zListAdministratorsQuery, { username: 'owner.example' })
  })
})

describe('public browser artifact', () => {
  it('exposes operation-bound calls without generic request methods', async () => {
    const configuredFetch = vi.fn(async () => new Response(JSON.stringify({ state: 'sign_in' }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }))
    const api = createManagementApi({ fetch: configuredFetch as unknown as typeof fetch })

    expect('get' in api).toBe(false)
    expect('post' in api).toBe(false)
    expect('request' in api).toBe(false)
    await api.getAdministratorAuthState({})
    expect(configuredFetch).toHaveBeenCalledTimes(1)
  })

  it('does not export automation credentials, root operations, or origin configuration', async () => {
    const publicIndex = await readFile(resolve('src/generated/management-v1/index.ts'), 'utf8')
    const publicClient = await readFile(resolve('src/generated/management-v1/client.ts'), 'utf8')
    const generatedIndex = await readFile(resolve('src/generated/management-v1/generated/index.ts'), 'utf8')
    const sdk = await readFile(resolve('src/generated/management-v1/generated/sdk.gen.ts'), 'utf8')
    const publicSource = `${publicIndex}\n${publicClient}\n${generatedIndex}`

    expect(publicSource).not.toMatch(/\bAuthorization\b/u)
    expect(publicSource).not.toMatch(/\bBearer\b/u)
    expect(publicSource).not.toMatch(/\bbaseUrl\b/u)
    expect(publicSource).not.toMatch(/\bClientOptions\b/u)
    expect(publicSource).not.toMatch(/\bRootBearer\b/u)
    expect(publicSource).not.toMatch(/\b(?:probeRootAdministratorCredential|issueAdministratorBootstrapGrant|issueAdministratorRecoveryGrant|beginRootAdministratorTokenRotation|completeRootAdministratorTokenRotation)\b/u)
    expect(publicSource).not.toMatch(/\/v1\/admin\/(?:auth\/root(?:$|[/'`])|auth\/bootstrap-grants|auth\/root-token-rotations|administrators\/\{principal_id\}\/recovery-grants)/u)
    expect(generatedIndex).not.toMatch(/from '\.\/sdk\.gen'/u)
    expect(sdk).not.toMatch(/\b(?:probeRootAdministratorCredential|issueAdministratorBootstrapGrant|issueAdministratorRecoveryGrant|beginRootAdministratorTokenRotation|completeRootAdministratorTokenRotation)\b/u)
  })

  it('removes the root-only administrator username query from public types and validators', async () => {
    const sdk = await readFile(resolve('src/generated/management-v1/generated/sdk.gen.ts'), 'utf8')
    const types = await readFile(resolve('src/generated/management-v1/generated/types.gen.ts'), 'utf8')
    const start = types.indexOf('export type ListAdministratorsData')
    const end = types.indexOf('export type ListAdministratorsErrors', start)

    expect(start).toBeGreaterThanOrEqual(0)
    expect(end).toBeGreaterThan(start)
    expect(types.slice(start, end)).not.toMatch(/\busername\b/iu)
    expect(sdk).not.toMatch(/username filter/iu)
    rejected(zListAdministratorsQuery, { username: 'owner.example' })
  })
})
