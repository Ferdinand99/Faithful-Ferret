// The part of the worker client (bindings/wasm/js/client.mjs of the published
// WASM package) that the web vault's sources use. The build copies this file
// next to the unpacked client as js/client.d.mts, so the type check reads these
// declarations instead of checking the published file.
export type Method = (...args: any[]) => Promise<any>;

export interface WorkerLike {
  postMessage(message: unknown, transfer?: Transferable[]): void;
  terminate(): void;
  onmessage: ((event: MessageEvent) => void) | null;
  onerror: ((event: ErrorEvent) => void) | null;
}

export interface Client {
  /** Every method of the vault worker. */
  vault: Record<string, Method>;
  /** One call per short-lived job worker. */
  job: Record<string, Method>;
  lock(): Promise<void>;
}

export function createClient(options?: {
  createVaultWorker?: () => WorkerLike;
  createJobWorker?: () => WorkerLike;
}): Client;

export class FerretError extends Error {
  code: string;
}
