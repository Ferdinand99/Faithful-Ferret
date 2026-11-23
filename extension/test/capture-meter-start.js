// Test build only (never in a release). Run just before the capture script, in the content script's world: it wraps the
// window's addEventListener and setTimeout so that every listener and timer the capture script registers is timed, and
// it starts a clock. capture-meter-end.js, run just after the capture script, stops the clock for the script's own
// start; what the listeners and timers cost afterwards adds up in the meter. The meter is read with a function that
// names globalThis.__ferretMeter. The page cannot see any of it: it lives in the extension's own world.
(() => {
  const meter = { ms: 0, calls: 0, listeners: 0, timers: 0, startedAt: performance.now(), startMs: null };
  const timed = (fn) => function timedCallback(...args) {
    const began = performance.now();
    try {
      return fn.apply(this, args);
    } finally {
      meter.ms += performance.now() - began;
      meter.calls += 1;
    }
  };
  const add = window.addEventListener.bind(window);
  window.addEventListener = (type, fn, options) => {
    meter.listeners += 1;
    return add(type, timed(fn), options);
  };
  const later = window.setTimeout.bind(window);
  window.setTimeout = (fn, ms, ...rest) => {
    meter.timers += 1;
    return later(timed(fn), ms, ...rest);
  };
  globalThis.__ferretMeter = meter;
})();
