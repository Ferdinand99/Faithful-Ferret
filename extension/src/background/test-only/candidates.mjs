// The test build only: a stand-in for the page matching, so the popup's "Fill"
// can be driven end to end in a real Firefox before the page matching of the
// release is there. It knows the top frame of a tab only (from `tabs.get`
// under activeTab) and asks the core for everything else: the origin
// (`page_origin`), the host (`display_host`) and which items match
// (`match_page`, over handles that are closed again at once). It has no rule
// of its own and no frame rules, which is why a release never has it.

/**
 * @param {{
 *   tabs: { get(tabId: number): Promise<{ url?: string }> },
 *   engine: () => any,
 *   client: () => { vault: any },
 * }} deps
 * @returns {import("../fillFlow.mjs").CandidateSource}
 */
export function createTestCandidates({ tabs, engine, client }) {
  return {
    async candidates(tabId) {
      const tab = await tabs.get(tabId).catch(() => null);
      const url = tab?.url;
      if (typeof url !== "string" || !/^https?:\/\//.test(url)) return { frames: [] };
      const core = client();
      const origin = await core.vault.page_origin(url).catch(() => null);
      const running = engine();
      if (typeof origin !== "string" || running === null) return { frames: [] };
      const host = await core.vault.display_host(url).catch(() => null);
      /** @type {Array<{ id: string, handle: number, close(): Promise<void> }>} */
      const opened = [];
      try {
        for (const summary of running.list()) {
          try {
            const item = await running.open(summary.id);
            opened.push({ id: summary.id, handle: item.handle, close: item.close });
          } catch {
            // An item that does not open is not offered.
          }
        }
        /** @type {Array<{ handle: number }>} */
        const matched = opened.length === 0 ? [] : await core.vault.match_page(url, opened.map((o) => o.handle));
        const ids = [...new Set(matched.map((m) => opened.find((o) => o.handle === m.handle)?.id).filter((id) => typeof id === "string"))];
        return {
          ...(host && typeof host.unicode === "string" ? { host } : {}),
          frames: [{ frameId: 0, url, origin, insecure: origin.startsWith("http:"), itemIds: /** @type {string[]} */ (ids) }],
        };
      } finally {
        for (const o of opened) await o.close().catch(() => {});
      }
    },
  };
}
