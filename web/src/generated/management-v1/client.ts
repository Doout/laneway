import * as operations from './generated/sdk.gen';
import { createInternalTransport } from './transport';

export interface ManagementApiOptions {
  csrfToken?: () => string | undefined;
  fetch?: typeof fetch;
}

type BoundOperation<Operation> = Operation extends (
  options: infer OperationOptions,
) => infer Result
  ? (options: Omit<OperationOptions, 'client'>) => Result
  : never;

export type ManagementApi = {
  [Name in keyof typeof operations]: BoundOperation<(typeof operations)[Name]>;
};

/**
 * Create the operation-bound browser API. The returned object has no generic
 * request methods, URL override, arbitrary headers, or validator hooks.
 */
export const createManagementApi = (config: ManagementApiOptions = {}): ManagementApi => {
  const transport = createInternalTransport(config);
  const entries = Object.entries(operations).map(([name, operation]) => [
    name,
    (options: Record<string, unknown> = {}) =>
      (operation as (value: Record<string, unknown>) => unknown)({ ...options, client: transport }),
  ]);
  return Object.fromEntries(entries) as ManagementApi;
};
