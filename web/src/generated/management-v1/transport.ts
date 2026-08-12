import { zErrorEnvelope } from './generated/zod.gen';

/** @internal Generated SDK transport shape. Not exported by the browser entry point. */
export interface TDataShape {
  body?: unknown;
  headers?: unknown;
  path?: unknown;
  query?: unknown;
  url: string;
}

interface RequestOptions<ThrowOnError extends boolean = boolean> {
  body?: unknown;
  headers?: HeadersInit;
  method?: 'DELETE' | 'GET' | 'PATCH' | 'POST' | 'PUT';
  path?: Record<string, unknown>;
  query?: Record<string, unknown>;
  requestValidator?: (data: unknown) => Promise<unknown>;
  responseValidator?: (data: unknown) => Promise<unknown>;
  throwOnError?: ThrowOnError;
  url: string;
}

/** @internal */
export type RequestResult<
  TData = unknown,
  TError = unknown,
  ThrowOnError extends boolean = boolean,
> = ThrowOnError extends true
  ? Promise<{
      data: TData extends Record<string, unknown> ? TData[keyof TData] : TData;
      request: Request;
      response: Response;
    }>
  : Promise<
      | {
          data: TData extends Record<string, unknown> ? TData[keyof TData] : TData;
          error: undefined;
          request: Request;
          response: Response;
        }
      | {
          data: undefined;
          error: TError extends Record<string, unknown> ? TError[keyof TError] : TError;
          request?: Request;
          response?: Response;
        }
    >;

/** @internal */
export type Options<
  TData extends TDataShape = TDataShape,
  ThrowOnError extends boolean = boolean,
  TResponse = unknown,
> = Pick<RequestOptions<ThrowOnError>, 'throwOnError'> & Omit<TData, 'url'> & {
  readonly __responseType?: TResponse;
};

type Method = <TData = unknown, TError = unknown, ThrowOnError extends boolean = false>(
  options: Omit<RequestOptions<ThrowOnError>, 'method'>,
) => RequestResult<TData, TError, ThrowOnError>;

/** @internal */
export interface InternalTransport {
  delete: Method;
  get: Method;
  patch: Method;
  post: Method;
  put: Method;
}

export interface InternalTransportOptions {
  csrfToken?: () => string | undefined;
  fetch?: typeof fetch;
}

const mutationMethods = new Set(['DELETE', 'PATCH', 'POST', 'PUT']);
const csrfExemptPaths = new Set([
  '/v1/admin/auth/bootstrap',
  '/v1/admin/auth/login',
  '/v1/admin/auth/recover',
]);
const rootOnlyPaths = new Set([
  'GET /v1/admin/auth/root',
  'POST /v1/admin/auth/bootstrap-grants',
]);
const serializeQuery = (query: Record<string, unknown> | undefined): string => {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(query ?? {})) {
    if (value !== undefined && value !== null) search.append(key, String(value));
  }
  const encoded = search.toString();
  return encoded ? `?${encoded}` : '';
};

const interpolatePath = (url: string, path: Record<string, unknown> | undefined): string =>
  url.replace(/\{([^}]+)\}/gu, (_match, key: string) => {
    const value = path?.[key];
    if (value === undefined) throw new Error(`missing path parameter: ${key}`);
    return encodeURIComponent(String(value));
  });

const responseBody = async (response: Response): Promise<unknown> => {
  if (response.status === 204) return undefined;
  if (response.headers.get('Content-Type')?.includes('json')) {
    const text = await response.text();
    return text ? JSON.parse(text) : undefined;
  }
  return response.text();
};

/** @internal Constructed only by the operation-bound browser API factory. */
export const createInternalTransport = (
  config: InternalTransportOptions = {},
): InternalTransport => {
  const request = async <ThrowOnError extends boolean>(
    options: RequestOptions<ThrowOnError>,
  ): Promise<unknown> => {
    const method = options.method ?? 'GET';
    if (options.query?.username !== undefined) {
      throw new Error('operation is unavailable to the browser management client');
    }
    const validated = await options.requestValidator?.({
      body: options.body,
      path: options.path,
      query: options.query,
    });
    const requestData = validated && typeof validated === 'object'
      ? validated as { body?: unknown; path?: Record<string, unknown>; query?: Record<string, unknown> }
      : { body: options.body, path: options.path, query: options.query };
    const path = interpolatePath(options.url, requestData.path);
    const canonicalPath = new URL(path, globalThis.location.origin);
    if (!path.startsWith('/v1/admin/') || path.startsWith('//') || rootOnlyPaths.has(`${method} ${path}`) ||
        path.includes('/root-token-rotations/') || path.endsWith('/recovery-grants') ||
        requestData.query?.username !== undefined || canonicalPath.origin !== globalThis.location.origin ||
        canonicalPath.pathname !== path || path.includes('%') || path.includes('\\') ||
        canonicalPath.search || canonicalPath.hash) {
      throw new Error('operation is unavailable to the browser management client');
    }

    const headers = new Headers(options.headers);
    for (const [name, value] of headers) {
      if (name.toLowerCase() !== 'content-type' || value.toLowerCase() !== 'application/json') {
        throw new Error('request headers are controlled by the browser management client');
      }
    }
    if (mutationMethods.has(method) && !csrfExemptPaths.has(path)) {
      const csrf = config.csrfToken?.();
      if (csrf) headers.set('X-Laneway-CSRF', csrf);
    }

    const body = requestData.body === undefined
      ? undefined
      : JSON.stringify(requestData.body);
    const query = serializeQuery(requestData.query);
    const requestUrl = new URL(`${path}${query}`, globalThis.location.origin);
    if (requestUrl.origin !== globalThis.location.origin) {
      throw new Error('operation is unavailable to the browser management client');
    }
    const requestObject = new Request(requestUrl, {
      body,
      credentials: 'same-origin',
      headers,
      method,
      redirect: 'error',
    });

    let response: Response | undefined;
    try {
      response = await (config.fetch ?? globalThis.fetch)(requestObject);
      let data = await responseBody(response);
      if (!response.ok) throw zErrorEnvelope.parse(data);
      if (options.responseValidator) data = await options.responseValidator(data);
      return { data, request: requestObject, response };
    } catch (error) {
      if (options.throwOnError ?? true) throw error;
      return { data: undefined, error, request: requestObject, response };
    }
  };

  const method = (verb: NonNullable<RequestOptions['method']>): Method =>
    ((options: Omit<RequestOptions<boolean>, 'method'>) =>
      request({ ...options, method: verb })) as Method;
  return {
    delete: method('DELETE'),
    get: method('GET'),
    patch: method('PATCH'),
    post: method('POST'),
    put: method('PUT'),
  };
};
