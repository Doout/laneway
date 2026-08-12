import { defineConfig } from '@hey-api/openapi-ts';

export default defineConfig({
  input: '../api/openapi/management-v1.yaml',
  output: {
    path: 'src/generated/management-v1/generated',
    module: {
      resolve: (path) => (path === '@hey-api/client-fetch' ? '../transport' : path),
    },
    postProcess: [
      {
        name: 'harden generated management browser SDK',
        command: 'node',
        args: ['scripts/harden-management-sdk.mjs', '{{path}}'],
      },
    ],
  },
  plugins: [
    {
      name: '@hey-api/typescript',
      enums: 'javascript',
    },
    {
      name: '@hey-api/client-fetch',
      baseUrl: false,
      bundle: false,
      throwOnError: true,
    },
    {
      name: '@hey-api/sdk',
      // Browser code must never gain an Authorization/root-token input path.
      // Session and CSRF credentials are supplied by the hardened same-origin
      // transport when this generated SDK is adopted by the live console.
      auth: false,
      client: false,
      paramsStructure: 'grouped',
      responseStyle: 'fields',
      validator: {
        request: 'zod',
        response: 'zod',
      },
    },
    {
      name: 'zod',
      compatibilityVersion: 4,
      definitions: true,
      requests: true,
      responses: true,
      $resolvers: {
        object: (context) => {
          const base = context.nodes.base(context);
          return base.attr('strict').call();
        },
      },
    },
  ],
});
