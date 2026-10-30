import { unhex } from '../util.mjs';

// Draws from the fixed RNG list of a case, in order.
export class Rng {
  constructor(list) {
    this.list = list.map(unhex);
    this.i = 0;
  }
  draw(n) {
    if (this.i >= this.list.length) throw new Error('rng exhausted');
    const v = this.list[this.i++];
    if (n !== undefined && v.length !== n) throw new Error(`rng draw ${this.i - 1}: wanted ${n} bytes, vector has ${v.length}`);
    return v;
  }
  get left() {
    return this.list.length - this.i;
  }
}

// Vault fields common to many inputs.
export function vaultFields(input) {
  return {
    accountId: unhex(input.account_id),
    vaultId: unhex(input.vault_id),
    vkEpoch: BigInt(input.vk_epoch),
    vk: unhex(input.vk),
  };
}
