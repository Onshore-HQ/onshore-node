# @onshorehq/sdk

The Onshore server SDK for Node.js and TypeScript. It stores sensitive values in your in-country vault and gives you tokens back, reveals them as your access rules allow, and covers records, lookups, data subject requests, resident checks, detection, flow checks, client tokens, cloaking for AI and webhook signatures.

- No runtime dependencies. Node.js 20 or later.
- Signs its own credentials (Ed25519), refreshes its access token, batches large requests and retries safely.
- Reveals fail closed.

```sh
npm install @onshorehq/sdk
```

```ts
import { VaultClient } from "@onshorehq/sdk";

const vault = new VaultClient({
  baseUrl: process.env.ONSHORE_URL!,
  serviceAccountId: process.env.ONSHORE_SA_ID!,
  keyId: process.env.ONSHORE_KEY_ID!,
  privateKey: process.env.ONSHORE_PRIVATE_KEY!,
});

const [{ token }] = await vault.tokenize("v_live_1", [{ field: "national_id", value: "AB123456C" }]);
```

Full reference: https://docs.onshorevault.com/developers/sdks/node/

## Licence

Apache-2.0. Copyright 2026 Flowsplus Services. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Contributions need the [Contributor Licence Agreement](CLA.md).
