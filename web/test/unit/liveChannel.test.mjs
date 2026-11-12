// The live channel (ruling K1): hello and sync make hints, a stream with no hello
// or no bytes is cut and tried again, three failures in a row fall back to a read
// every five minutes, and the end of the session ends the channel.
import assert from "node:assert/strict";
import { test } from "node:test";
import { ApiError, createApi } from "../../src/api.mjs";
import { createLiveChannel, EVENTS_PATH } from "../../src/sync/events.mjs";
import { fakeStreamApi, fakePageEvents } from "./liveHelpers.mjs";
import { fakeClock, settle } from "./vaultHelpers.mjs";

/** A channel over a fake stream api, a fake clock and a fake page. */
function rig(options = {}) {
  const clock = fakeClock();
  const api = options.api ?? fakeStreamApi();
  const page = fakePageEvents();
  const hints = [];
  const states = [];
  const channel = createLiveChannel({
    api,
    timers: { set: (fn, ms) => clock.setTimeout(fn, ms), clear: (id) => clock.clearTimeout(id) },
    now: clock.now,
    onHint: (seq) => hints.push(seq),
    onState: (state) => states.push(state),
    win: page,
    random: () => 0.5, // no jitter, unless a test asks for it
    ...options.channel,
  });
  /** Moves the clock and lets what the timers started finish. */
  const tick = async (ms) => {
    clock.advance(ms);
    await settle();
  };
  return { clock, api, page, hints, states, channel, tick };
}

const network = () => new ApiError(0, "network");

test("hello_makes_the_channel_live_and_hints_the_engine", async () => {
  const { api, hints, states, channel } = rig();
  assert.equal(channel.state(), "offline", "nothing before the start");
  channel.start();
  assert.equal(channel.state(), "connecting");
  await settle();
  assert.equal(api.calls.length, 1);
  assert.equal(api.calls[0].path, EVENTS_PATH);
  assert.equal(channel.state(), "connecting", "no hello yet");

  api.last.hello(7);
  await settle();
  assert.equal(channel.state(), "live");
  assert.deepEqual(hints, [7], "the engine reads the feed");
  assert.deepEqual(states, ["connecting", "live"]);

  // A second start of a started channel changes nothing.
  channel.start();
  await settle();
  assert.equal(api.calls.length, 1);
});

test("sync_event_hints_with_its_seq", async () => {
  const { api, hints, channel } = rig();
  channel.start();
  await settle();
  // Events before the hello are not heard: the hello is what makes a stream a stream.
  api.last.sync(3);
  await settle();
  assert.deepEqual(hints, []);

  api.last.hello(5);
  api.last.sync(6);
  api.last.sync(9);
  await settle();
  assert.deepEqual(hints, [5, 6, 9]);

  // A comment is no hint, an unknown event is ignored, and a sync without a usable seq still wakes the engine
  // (it reads the feed itself and trusts nothing in the event).
  api.last.comment();
  api.last.push("event: whatever\ndata: {\"seq\":99}\n\n");
  api.last.push("event: sync\ndata: not json\n\n");
  api.last.push("event: sync\ndata: {\"seq\":-1}\n\n");
  api.last.push("event: sync\ndata: {\"seq\":1.5}\n\n");
  api.last.push("event: sync\ndata: {\"seq\":\"7\",\"rows\":[1]}\n\n");
  await settle();
  assert.deepEqual(hints, [5, 6, 9, null, null, null, null]);
  assert.equal(channel.state(), "live");
});

test("a_hello_that_is_not_a_hello_counts_as_a_failure", async () => {
  const { api, hints, channel, tick } = rig();
  channel.start();
  await settle();
  api.last.push("event: hello\ndata: {\"seq\":\"x\"}\n\n");
  await settle();
  assert.equal(channel.state(), "connecting");
  assert.deepEqual(hints, []);
  assert.equal(api.last.signal.aborted, true);
  await tick(1000);
  assert.equal(api.calls.length, 2);
});

test("a_stream_that_breaks_the_line_limit_is_dropped_and_tried_again", async () => {
  const { api, hints, channel, tick } = rig();
  channel.start();
  await settle();
  api.last.hello(1);
  await settle();
  api.last.push(`data: ${"a".repeat(70_000)}\n`);
  await settle();
  assert.equal(api.connections[0].signal.aborted, true);
  await tick(1000);
  assert.equal(api.calls.length, 2);
  assert.deepEqual(hints, [1]);
});

test("no_hello_within_ten_seconds_aborts_and_reconnects_with_backoff", async () => {
  const { api, channel, tick } = rig();
  channel.start();
  await settle();
  // Bytes are not enough: the first comment does not make the stream live.
  api.last.comment();
  await settle();
  await tick(9_999);
  assert.equal(api.connections[0].signal.aborted, false);
  await tick(1);
  assert.equal(api.connections[0].signal.aborted, true, "ten seconds without a hello");
  assert.equal(api.connections[0].cancelled, true);
  assert.equal(channel.state(), "connecting");

  // 1 s to the next try ...
  await tick(999);
  assert.equal(api.calls.length, 1);
  await tick(1);
  assert.equal(api.calls.length, 2);
  // ... then 2 s after the second failure.
  await tick(10_000);
  assert.equal(api.connections[1].signal.aborted, true);
  await tick(1_999);
  assert.equal(api.calls.length, 2);
  await tick(1);
  assert.equal(api.calls.length, 3);
});

test("the_backoff_doubles_up_to_a_minute", async () => {
  const api = fakeStreamApi();
  api.script.push(...Array.from({ length: 12 }, network));
  const { channel, tick } = rig({ api, channel: { maxFailures: 100 } });
  channel.start();
  await settle();
  const waits = [];
  for (let i = 0; i < 9; i += 1) {
    const before = api.calls.length;
    let waited = 0;
    while (api.calls.length === before && waited < 120_000) {
      await tick(500);
      waited += 500;
    }
    waits.push(waited);
  }
  // Each new try comes after 1, 2, 4, 8, 16, 32, 60, 60, 60 s.
  assert.deepEqual(waits, [1000, 2000, 4000, 8000, 16_000, 32_000, 60_000, 60_000, 60_000]);
});

test("sixty_seconds_of_silence_aborts", async () => {
  const { api, channel, tick } = rig();
  channel.start();
  await settle();
  api.last.hello(1);
  await settle();
  assert.equal(channel.state(), "live");

  await tick(59_999);
  assert.equal(api.last.signal.aborted, false);
  api.last.comment(); // a heartbeat moves the limit
  await settle();
  await tick(59_999);
  assert.equal(api.last.signal.aborted, false);
  await tick(1);
  assert.equal(api.connections[0].signal.aborted, true);
  assert.equal(channel.state(), "live", "a quick reconnect is not announced");
  await tick(1000);
  assert.equal(api.calls.length, 2, "tried again, not given up");
  await tick(4000);
  assert.equal(channel.state(), "connecting", "but five seconds without a new hello are");
});

test("a_stream_the_server_closes_after_a_hello_is_opened_again", async () => {
  const { api, hints, channel, tick } = rig();
  channel.start();
  await settle();
  api.last.hello(1);
  await settle();
  // The server ends the stream (its lifetime, a restart): no failure, a new stream after a second.
  api.connections[0].end();
  await settle();
  await tick(1000);
  assert.equal(api.calls.length, 2);
  api.last.hello(2);
  await settle();
  assert.equal(channel.state(), "live");
  assert.deepEqual(hints, [1, 2]);
});

test("a_stream_that_keeps_dropping_right_after_its_hello_is_not_reopened_every_second", async () => {
  const { api, channel, tick } = rig();
  channel.start();
  await settle();
  const gaps = [];
  for (let i = 0; i < 4; i += 1) {
    api.last.hello(i);
    await settle();
    api.last.end();
    await settle();
    let waited = 0;
    const before = api.calls.length;
    while (api.calls.length === before) {
      await tick(500);
      waited += 500;
    }
    gaps.push(waited);
  }
  assert.deepEqual(gaps, [1000, 2000, 4000, 8000]);
  // A stream that lived for a minute starts the wait over.
  api.last.hello(9);
  await settle();
  await tick(30_000);
  api.last.comment();
  await settle();
  await tick(30_000);
  api.last.end();
  await settle();
  await tick(1000);
  assert.equal(api.calls.length, 6);
});

test("three_failures_without_hello_fall_back_and_retry_every_five_minutes", async () => {
  const api = fakeStreamApi();
  api.script.push(network(), "hang", network(), network());
  const { hints, states, channel, tick } = rig({ api });
  channel.start();
  await settle();
  assert.equal(api.calls.length, 1, "refused");
  await tick(1000);
  assert.equal(api.calls.length, 2, "an answer that never comes: the hello time runs from the request");
  await tick(10_000);
  assert.equal(channel.state(), "connecting", "two failures");
  assert.deepEqual(hints, []);
  await tick(2000);
  assert.equal(api.calls.length, 3, "the third try");
  await settle();
  assert.equal(channel.state(), "fallback", "three failures in a row");
  assert.deepEqual(hints, [null], "the engine is asked once as the channel gives up");
  assert.deepEqual(states, ["connecting", "fallback"]);

  // Every five minutes: a read, and another try.
  await tick(299_999);
  assert.equal(api.calls.length, 3);
  await tick(1);
  assert.equal(api.calls.length, 4);
  assert.deepEqual(hints, [null, null]);
  assert.equal(channel.state(), "fallback", "a failed try does not leave the fallback");
  await tick(299_999);
  assert.equal(api.calls.length, 4);
  await tick(1);
  assert.equal(api.calls.length, 5, "and again");

  // A hello ends the fallback and clears the failures.
  api.last.hello(3);
  await settle();
  assert.equal(channel.state(), "live");
  assert.deepEqual(hints.at(-1), 3);
  api.last.end();
  await settle();
  await tick(1000);
  assert.equal(api.calls.length, 6);
});

test("the_fallback_uses_the_given_numbers", async () => {
  const api = fakeStreamApi();
  api.script.push(network(), network());
  const { hints, channel, tick } = rig({ api, channel: { maxFailures: 2, fallbackRetryMs: 1000 } });
  channel.start();
  await settle();
  await tick(1000);
  assert.equal(channel.state(), "fallback");
  await tick(1000);
  assert.equal(api.calls.length, 3);
  assert.deepEqual(hints, [null, null]);
});

test("focus_and_online_try_again_from_fallback", async () => {
  const api = fakeStreamApi();
  api.script.push(network(), network(), network(), network(), network());
  const { page, channel, clock, tick } = rig({ api });
  channel.start();
  await settle();
  await tick(1000);
  await tick(2000);
  assert.equal(channel.state(), "fallback");
  assert.equal(api.calls.length, 3);
  assert.equal(page.count(), 2, "focus and online");

  // Right after a try, a focus does not start another.
  page.fire("focus");
  await settle();
  assert.equal(api.calls.length, 3);

  await tick(6000);
  page.fire("focus");
  await settle();
  assert.equal(api.calls.length, 4);
  assert.equal(channel.state(), "fallback");
  assert.equal(clock.pending, 1, "the next try is five minutes away again");

  await tick(6000);
  page.fire("online");
  await settle();
  assert.equal(api.calls.length, 5);
  await tick(6000);
  page.fire("focus");
  await settle();
  assert.equal(api.calls.length, 6, "this one is answered");
  api.last.hello(4);
  await settle();
  assert.equal(channel.state(), "live");

  // A live channel is left alone, and a focus during a try does not start a second one.
  page.fire("focus");
  page.fire("online");
  await settle();
  assert.equal(api.calls.length, 6);
});

test("offline_waits_for_the_network_and_does_not_count_as_failures", async () => {
  const api = fakeStreamApi();
  api.script.push(network(), network(), network(), network());
  const { page, hints, channel, tick } = rig({ api });
  page.navigator.onLine = false;
  channel.start();
  await settle();
  assert.equal(channel.state(), "offline");
  // Four refusals with the network off: still not the fallback.
  await tick(1000);
  await tick(2000);
  await tick(4000);
  assert.equal(api.calls.length, 4);
  assert.equal(channel.state(), "offline");
  assert.deepEqual(hints, []);

  // The network is back: the `online` event does not wait for the timer.
  page.navigator.onLine = true;
  page.fire("online");
  await settle();
  assert.equal(api.calls.length, 5);
  api.last.hello(2);
  await settle();
  assert.equal(channel.state(), "live");
});

test("401_stops_without_retry_and_429_waits_retry_after", async () => {
  // 401: the session is over. No retry, no timer, and a focus does not bring it back.
  const over = rig();
  over.api.script.push(new ApiError(401, "unauthorized"));
  over.channel.start();
  await settle();
  assert.equal(over.channel.state(), "unauthorized");
  await over.tick(3_600_000);
  over.page.fire("focus");
  over.page.fire("online");
  await settle();
  assert.equal(over.api.calls.length, 1);
  assert.equal(over.clock.pending, 0);
  // A new start (a new sign-in) tries again.
  over.channel.stop();
  over.channel.start();
  await settle();
  assert.equal(over.api.calls.length, 2);
  over.api.last.hello(1);
  await settle();
  assert.equal(over.channel.state(), "live");

  // 429: wait as long as the server says (and not the backoff).
  const busy = rig();
  busy.api.script.push(new ApiError(429, "throttled", 45));
  busy.channel.start();
  await settle();
  assert.equal(busy.channel.state(), "connecting");
  await busy.tick(44_999);
  assert.equal(busy.api.calls.length, 1);
  await busy.tick(1);
  assert.equal(busy.api.calls.length, 2);

  // Without a Retry-After, 30 s; an absurd one is cut to five minutes; zero is a second.
  for (const [retryAfter, wait] of [[null, 30_000], [999_999, 300_000], [0, 1000]]) {
    const one = rig();
    one.api.script.push(new ApiError(429, "throttled", retryAfter));
    one.channel.start();
    await settle();
    await one.tick(wait - 1);
    assert.equal(one.api.calls.length, 1, `${retryAfter}`);
    await one.tick(1);
    assert.equal(one.api.calls.length, 2, `${retryAfter}`);
  }

  // A server that always says 429 ends in the fallback like any other that never says hello.
  const always = rig();
  always.api.script.push(...Array.from({ length: 3 }, () => new ApiError(429, "throttled", 30)));
  always.channel.start();
  await settle();
  await always.tick(30_000);
  await always.tick(30_000);
  assert.equal(always.channel.state(), "fallback");
});

test("stop_aborts_the_fetch_and_clears_every_timer", async () => {
  // A live stream.
  const live = rig();
  live.channel.start();
  await settle();
  live.api.last.hello(1);
  await settle();
  assert.equal(live.clock.pending > 0, true, "the silence timer runs");
  live.channel.stop();
  assert.equal(live.api.last.signal.aborted, true);
  assert.equal(live.api.last.cancelled, true);
  assert.equal(live.clock.pending, 0);
  assert.equal(live.page.count(), 0, "the page listeners are gone");
  assert.equal(live.channel.state(), "offline");
  await live.tick(3_600_000);
  assert.equal(live.api.calls.length, 1, "nothing comes back");

  // A request that has not been answered.
  const hanging = rig();
  hanging.api.script.push("hang");
  hanging.channel.start();
  await settle();
  const signal = hanging.api.calls[0].options.signal;
  assert.equal(signal.aborted, false);
  hanging.channel.stop();
  assert.equal(signal.aborted, true);
  assert.equal(hanging.clock.pending, 0);
  await settle();
  assert.equal(hanging.api.connections.length, 0);

  // A wait before a new try, and the fallback.
  const waiting = rig();
  waiting.api.script.push(network());
  waiting.channel.start();
  await settle();
  assert.equal(waiting.clock.pending, 1);
  waiting.channel.stop();
  assert.equal(waiting.clock.pending, 0);

  const fallen = rig({ channel: { maxFailures: 1 } });
  fallen.api.script.push(network());
  fallen.channel.start();
  await settle();
  assert.equal(fallen.channel.state(), "fallback");
  fallen.channel.stop();
  assert.equal(fallen.clock.pending, 0);

  // Stopped twice, and started again, are fine; a late answer from the old stream is not heard.
  fallen.channel.stop();
  const again = rig();
  again.api.script.push("hang");
  again.channel.start();
  await settle();
  again.channel.stop();
  again.channel.start();
  await settle();
  assert.equal(again.api.calls.length, 2);
  again.api.last.hello(2);
  await settle();
  assert.equal(again.channel.state(), "live");
  assert.deepEqual(again.hints, [2]);
});

test("a_throwing_hint_or_state_listener_does_not_break_the_channel", async () => {
  const clock = fakeClock();
  const api = fakeStreamApi();
  const channel = createLiveChannel({
    api,
    timers: { set: (fn, ms) => clock.setTimeout(fn, ms), clear: (id) => clock.clearTimeout(id) },
    now: clock.now,
    onHint: () => Promise.reject(new Error("a failed read")),
    onState: () => {
      throw new Error("a broken screen");
    },
    win: fakePageEvents(),
  });
  channel.start();
  await settle();
  api.last.hello(1);
  api.last.sync(2);
  await settle();
  assert.equal(channel.state(), "live");
  channel.stop();
});

test("the_request_carries_the_protocol_header_and_no_store", async () => {
  // The real client over a fake fetch: the channel's stream request is what the server expects.
  const calls = [];
  let controller;
  const fetchImpl = async (url, init) => {
    calls.push({ url, init });
    const body = new ReadableStream({
      start(c) {
        controller = c;
        c.enqueue(new TextEncoder().encode('event: hello\ndata: {"seq":4}\n\n'));
      },
    });
    return new Response(body, { status: 200, headers: { "content-type": "text/event-stream" } });
  };
  const hints = [];
  const channel = createLiveChannel({ api: createApi({ fetchImpl }), onHint: (seq) => hints.push(seq), win: fakePageEvents() });
  channel.start();
  await settle();
  assert.equal(channel.state(), "live");
  assert.deepEqual(hints, [4]);
  const [{ url, init }] = calls;
  assert.equal(url, "/api/sync/events");
  assert.equal(init.method, "GET");
  assert.equal(init.headers["Ferret-Protocol"], "1");
  assert.equal(init.headers.Accept, "text/event-stream");
  assert.equal(init.cache, "no-store");
  assert.equal(init.credentials, "same-origin");
  assert.equal(init.redirect, "error");
  assert.ok(init.signal instanceof AbortSignal);
  assert.equal(init.signal.aborted, false);
  // Stopping ends the real stream: the signal aborts.
  channel.stop();
  assert.equal(init.signal.aborted, true);
  void controller;
});

test("a_quick_reconnect_after_a_hello_is_not_announced", async () => {
  const { api, states, channel, tick } = rig();
  channel.start();
  await settle();
  api.last.hello(1);
  await settle();
  assert.deepEqual(states, ["connecting", "live"]);
  // The server closes the stream (the hour is up); the next one says hello within a second or two.
  api.last.end();
  await settle();
  await tick(1000);
  assert.equal(api.calls.length, 2);
  await tick(2000);
  api.last.hello(2);
  await settle();
  await tick(10_000);
  assert.deepEqual(states, ["connecting", "live"], "the screen was told nothing");

  // A reconnect that fails at once is told: there is no live stream any more.
  api.script.push(new ApiError(0, "network"));
  api.last.end();
  await settle();
  await tick(2000); // the second quick drop waits 2 s
  assert.equal(channel.state(), "connecting");
  assert.deepEqual(states, ["connecting", "live", "connecting"]);

  // Nor is a lost network kept quiet.
  const rigged = rig();
  rigged.channel.start();
  await settle();
  rigged.api.last.hello(1);
  await settle();
  rigged.page.navigator.onLine = false;
  rigged.api.last.end();
  await settle();
  assert.equal(rigged.channel.state(), "offline");

  // And a stop in the grace time leaves no timer.
  const quiet = rig();
  quiet.channel.start();
  await settle();
  quiet.api.last.hello(1);
  await settle();
  quiet.api.last.end();
  await settle();
  quiet.channel.stop();
  assert.equal(quiet.clock.pending, 0);
});

test("focus_and_online_do_not_cut_a_429_or_a_backoff_short", async () => {
  // 429 with Retry-After 45: a focus at 5 s sends nothing.
  const busy = rig();
  busy.api.script.push(new ApiError(429, "throttled", 45));
  busy.channel.start();
  await settle();
  await busy.tick(5000);
  busy.page.fire("focus");
  busy.page.fire("online");
  await settle();
  assert.equal(busy.api.calls.length, 1);
  await busy.tick(39_999);
  busy.page.fire("focus");
  await settle();
  assert.equal(busy.api.calls.length, 1);
  await busy.tick(1);
  assert.equal(busy.api.calls.length, 2, "the wait ran out on its own");

  // A backoff of 2 s binds as well.
  const failing = rig();
  failing.api.script.push(new ApiError(0, "network"), new ApiError(0, "network"));
  failing.channel.start();
  await settle();
  await failing.tick(1000);
  assert.equal(failing.api.calls.length, 2);
  await failing.tick(500);
  failing.page.fire("focus");
  await settle();
  assert.equal(failing.api.calls.length, 2);
  await failing.tick(1500);
  assert.equal(failing.api.calls.length, 3);

  // A 429 that ends in the fallback binds too, and then the fallback's own rule is back.
  const always = rig();
  always.api.script.push(...Array.from({ length: 3 }, () => new ApiError(429, "throttled", 30)));
  always.channel.start();
  await settle();
  await always.tick(30_000);
  await always.tick(30_000);
  assert.equal(always.channel.state(), "fallback");
  await always.tick(6000);
  always.page.fire("focus");
  await settle();
  assert.equal(always.api.calls.length, 3);
  await always.tick(24_000);
  always.page.fire("focus");
  await settle();
  assert.equal(always.api.calls.length, 4);
});

test("the_backoff_and_a_429_wait_vary_by_twenty_percent_either_way", async () => {
  for (const [random, backoffMs, throttledMs] of [[0, 800, 36_000], [0.5, 1000, 45_000], [1, 1200, 54_000]]) {
    const failing = rig({ channel: { random: () => random } });
    failing.api.script.push(new ApiError(0, "network"));
    failing.channel.start();
    await settle();
    await failing.tick(backoffMs - 1);
    assert.equal(failing.api.calls.length, 1, `backoff at ${random}`);
    await failing.tick(1);
    assert.equal(failing.api.calls.length, 2, `backoff at ${random}`);

    const busy = rig({ channel: { random: () => random } });
    busy.api.script.push(new ApiError(429, "throttled", 45));
    busy.channel.start();
    await settle();
    await busy.tick(throttledMs - 1);
    assert.equal(busy.api.calls.length, 1, `429 at ${random}`);
    await busy.tick(1);
    assert.equal(busy.api.calls.length, 2, `429 at ${random}`);
  }
  // The real source of numbers stays inside the same bounds.
  for (let i = 0; i < 20; i += 1) {
    const one = rig({ channel: { random: Math.random } });
    one.api.script.push(new ApiError(0, "network"));
    one.channel.start();
    await settle();
    await one.tick(799);
    assert.equal(one.api.calls.length, 1);
    await one.tick(401);
    assert.equal(one.api.calls.length, 2);
  }
});

test("a_seq_that_is_not_a_safe_whole_number_is_no_seq", async () => {
  const { api, hints, channel } = rig();
  channel.start();
  await settle();
  api.last.hello(2);
  await settle();
  const odd = ["9007199254740992", "9007199254740993", "18446744073709551616", "1e400", "null", "true", "[]", "{}", "-0.5"];
  for (const seq of odd) api.last.push(`event: sync\ndata: {"seq":${seq}}\n\n`);
  api.last.push("event: sync\ndata: null\n\n");
  api.last.push("event: sync\ndata: 7\n\n");
  await settle();
  assert.deepEqual(hints, [2, ...Array(odd.length + 2).fill(null)], "a hint with no seq, never a wrong one");
  // 2^53 - 1 is the largest the engine could be told.
  api.last.push('event: sync\ndata: {"seq":9007199254740991}\n\n');
  await settle();
  assert.equal(hints.at(-1), 9007199254740991);

  // A hello with any of them is no hello.
  for (const seq of ["9007199254740992", "null"]) {
    const bad = rig();
    bad.channel.start();
    await settle();
    bad.api.last.push(`event: hello\ndata: {"seq":${seq}}\n\n`);
    await settle();
    assert.equal(bad.channel.state(), "connecting", seq);
    assert.deepEqual(bad.hints, [], seq);
    assert.equal(bad.api.last.signal.aborted, true, seq);
    await bad.tick(1000);
    assert.equal(bad.api.calls.length, 2, seq);
  }
});
