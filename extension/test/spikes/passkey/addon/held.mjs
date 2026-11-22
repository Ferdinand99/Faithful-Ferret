// The held (conditional) requests of the passkey spike, scoped per port. Test-only.
//
// A request id is only unique inside one document: every page counts from 1. So a
// held request is kept under (port, id), a cancel is accepted only from the port that
// made the request, and one port may hold only a few requests at a time (design
// document 9.2: one pending request per tab, with a little room for the spike).

export class HeldRequests {
  /** @param {number} maxPerPort */
  constructor(maxPerPort) {
    this.maxPerPort = maxPerPort;
    /** @type {Map<object, Map<number, any>>} port -> (id -> request) */
    this.byPort = new Map();
  }

  get size() {
    let n = 0;
    for (const held of this.byPort.values()) n += held.size;
    return n;
  }

  /** @param {object} port */
  sizeOf(port) {
    return this.byPort.get(port)?.size ?? 0;
  }

  /**
   * @param {object} port
   * @param {number} id
   * @param {any} request
   * @returns {boolean} false when the port is at its limit or already holds that id
   */
  add(port, id, request) {
    let held = this.byPort.get(port);
    if (!held) {
      held = new Map();
      this.byPort.set(port, held);
    }
    if (held.has(id) || held.size >= this.maxPerPort) return false;
    held.set(id, request);
    return true;
  }

  /**
   * A cancel from `port` for `id`: only that port's own request can go.
   * @param {object} port
   * @param {number} id
   * @returns {boolean}
   */
  cancel(port, id) {
    const held = this.byPort.get(port);
    if (!held || !held.delete(id)) return false;
    if (held.size === 0) this.byPort.delete(port);
    return true;
  }

  /** The document went away. @param {object} port */
  dropPort(port) {
    this.byPort.delete(port);
  }

  /**
   * Takes the n-th held request in the order they were made.
   * @param {number} [n]
   * @returns {{ port: object, id: number, request: any } | null}
   */
  take(n = 0) {
    const all = [...this.byPort].flatMap(([port, held]) => [...held].map(([id, request]) => ({ port, id, request })));
    const found = all[n];
    if (!found) return null;
    this.cancel(found.port, found.id);
    return found;
  }
}
