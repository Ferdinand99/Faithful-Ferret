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

/** A wrap as the core gives it (bytes, not the wire's base64url). */
export interface CoreWrap {
  method_id: Uint8Array;
  kek_generation: number;
  method: { type: "password" | "recovery" | "prf"; [field: string]: unknown };
  wrap: Uint8Array;
}

/**
 * What `vault.renew_recovery` gives: the new recovery wrap, `pk_r` of the new key, the manifest row
 * with the new generation, and the pinned record to store once the server has accepted them. The new
 * key itself stays in the worker (`reveal_recovery_code`, `verify_recovery_setup`,
 * `clear_setup_secrets`).
 */
export interface RenewedRecovery {
  wrap: CoreWrap;
  pk_r: Uint8Array;
  manifest: { rev: number; envelope: Uint8Array; tag: Uint8Array };
  pinned: Record<string, any>;
}
