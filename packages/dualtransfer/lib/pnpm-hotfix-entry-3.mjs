// Local maintenance entry: resolve the currently installed generation explicitly.
// No service actions, native proof caching, or changes to the implementation.
import { realpathSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
const implementation = await import(pathToFileURL(realpathSync(fileURLToPath(new URL('./index.js', import.meta.url)))).href);
export const { name, inject, Config, RPC_CHANNEL, resolveLocalContext, createRpcHandler, createAgentOperationManager, apply } = implementation;
