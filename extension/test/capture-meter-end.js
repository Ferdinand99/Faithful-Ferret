// Test build only (never in a release). Run just after the capture script (see capture-meter-start.js): the time from
// the start file to here is what the capture script cost to start, with the listeners and the first look at the page.
globalThis.__ferretMeter.startMs = performance.now() - globalThis.__ferretMeter.startedAt;
