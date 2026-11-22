// The side menu as a screen: the switch to the admin pages, folding to a rail, the pinned folders, the account
// menu, the drawer of a phone, the keyboard, and the names of the controls. A very small DOM, so the focus is
// recorded by the controls that are asked to take it.
import assert from "node:assert/strict";
import { test } from "node:test";
import { el } from "../../src/dom.mjs";
import { createWipeScope } from "../../src/views/common.mjs";
import { sidebarView } from "../../src/views/sidebar.mjs";
import { shellView } from "../../src/views/shell.mjs";
import { createUiPrefs } from "../../src/uiPrefs.mjs";
import favoritesRoute from "../../src/routes/favorites.route.mjs";
import listRoute from "../../src/routes/list.route.mjs";
import newRoute from "../../src/routes/new.route.mjs";
import trashRoute from "../../src/routes/trash.route.mjs";
import { FakeElement, all, click, fakeEngine, fakeSession, find, fire, settle, t, textOf, walk, withDom } from "./vaultHelpers.mjs";

const ROUTES = [listRoute, newRoute, favoritesRoute, trashRoute];
const FOLDERS = [{ id: "home", name: "Home", parentId: null }, { id: "net", name: "Network", parentId: "home" }, { id: "fin", name: "Finance", parentId: null }];

/** A storage that is a map. */
function memory() {
  const map = new Map();
  return { map, getItem: (k) => map.get(k) ?? null, setItem: (k, v) => void map.set(k, String(v)), removeItem: (k) => void map.delete(k) };
}

/** Makes the controls of the menu that may take the focus record it. */
function watchFocus(view) {
  const focused = [];
  for (const node of [...walk(view.top), ...walk(view.side)]) {
    if (node instanceof FakeElement) node.focus = () => focused.push(node.getAttribute("data-role") ?? node.tagName);
  }
  return focused;
}

function build(options = {}) {
  const calls = { lock: 0, signOut: 0, admin: 0, opened: [] };
  const status = el("span", { class: "pill sync-status", role: "status", "data-role": "sync-status" }, "Up to date");
  const view = sidebarView({
    t, routes: ROUTES, counts: { all: 248, favorites: 12 }, prefs: createUiPrefs(memory(), []), email: "ada.lovelace@example.com",
    status, liveStatus: null, onLock: async () => void (calls.lock += 1), onSignOut: async () => void (calls.signOut += 1),
    win: { open: (...args) => calls.opened.push(args) }, ...options,
  });
  const behind = [el("div", null), el("div", null)];
  view.setBehind(behind);
  const root = el("div", null, view.top, view.side, view.backdrop, ...behind);
  const focused = watchFocus(view);
  return { view, root, calls, behind, focused, status };
}

const adminWay = (answer, calls = { go: 0 }) => ({ check: async () => answer, go: () => void (calls.go += 1), calls });

test("the_switch_to_the_admin_pages_shows_only_for_an_administrator", async () => {
  await withDom(async () => {
    // No admin address, or no way to ask: never shown.
    const none = build();
    await settle();
    assert.equal(find(none.root, "switch-admin").hidden, true);

    const yes = build({ admin: adminWay(true) });
    assert.equal(find(yes.root, "switch-admin").hidden, true, "hidden until the server has said so");
    await settle();
    assert.equal(find(yes.root, "switch-admin").hidden, false);

    const no = build({ admin: adminWay(false) });
    await settle();
    assert.equal(find(no.root, "switch-admin").hidden, true);

    const failing = build({ admin: { check: async () => { throw new Error("offline"); }, go() {} } });
    await settle();
    assert.equal(find(failing.root, "switch-admin").hidden, true, "a failed check shows no switch");
  });
});

test("the_switch_goes_to_the_admin_pages_and_has_a_name_that_says_where", async () => {
  await withDom(async () => {
    const way = adminWay(true);
    const { root } = build({ admin: way });
    await settle();
    const button = find(root, "switch-admin");
    assert.equal(button.getAttribute("aria-label"), "shell.switch.label");
    await click(button);
    assert.equal(way.calls.go, 1);
  });
});

test("folding_the_menu_to_a_rail_is_remembered_and_the_button_says_what_it_does_next", async () => {
  await withDom(async () => {
    const storage = memory();
    const first = build({ prefs: createUiPrefs(storage) });
    const side = find(first.root, "side");
    const button = find(first.root, "collapse");
    assert.equal(side.getAttribute("data-collapsed"), "false");
    assert.equal(button.getAttribute("aria-label"), "shell.menu.collapse");
    await click(button);
    assert.equal(side.getAttribute("data-collapsed"), "true");
    assert.equal(button.getAttribute("aria-label"), "shell.menu.expand");
    assert.equal(createUiPrefs(storage).collapsed(), true);

    // Another page of the same device starts folded.
    const second = build({ prefs: createUiPrefs(storage) });
    assert.equal(find(second.root, "side").getAttribute("data-collapsed"), "true");
    assert.equal(find(second.root, "collapse").getAttribute("aria-label"), "shell.menu.expand");
    await click(find(second.root, "collapse"));
    assert.equal(createUiPrefs(storage).collapsed(), false);
  });
});

test("the_entries_show_their_counts_and_follow_the_items", async () => {
  await withDom(async () => {
    const { view, root } = build();
    const count = (role) => textOf(find(root, role).childNodes.find((c) => c.getAttribute?.("class") === "side-count")).trim();
    assert.equal(count("nav-items"), "248");
    assert.equal(count("nav-favorites"), "12");
    assert.equal(find(root, "nav-trash").childNodes.some((c) => c.getAttribute?.("class") === "side-count"), false);
    view.setCounts({ all: 249, favorites: 13 });
    assert.equal(count("nav-items"), "249");
    assert.equal(count("nav-favorites"), "13");
  });
});

test("pinned_folders_are_listed_with_their_sub_folders_and_can_be_unpinned_from_their_menu", async () => {
  await withDom(async () => {
    const storage = memory();
    const prefs = createUiPrefs(storage, []);
    prefs.pin("Home");
    const { root, view } = build({ prefs, folders: FOLDERS });
    const rows = () => all(root, "nav-folder").map((link) => textOf(link).trim());
    assert.deepEqual(rows(), ["Home", "Network"]);
    // Only the pinned one has a menu, and its name says which folder it is for.
    const buttons = all(root, "folder-menu-button");
    assert.equal(buttons.length, 1);
    assert.equal(buttons[0].getAttribute("aria-label"), 'shell.pinned.options {"name":"Home"}');
    assert.equal(buttons[0].getAttribute("aria-expanded"), "false");
    await click(buttons[0]);
    assert.equal(buttons[0].getAttribute("aria-expanded"), "true");
    assert.equal(find(root, "folder-menu").hidden, false);
    await click(find(root, "unpin"));
    assert.deepEqual(prefs.pinned(), []);
    assert.deepEqual(rows(), [], "the folders leave the menu");
    assert.equal(all(root, "folder-menu-button").length, 0);
    // The vault has folders later: the menu follows.
    view.setFolders([...FOLDERS, { id: "x", name: "X" }]);
    assert.deepEqual(rows(), []);
  });
});

test("the_account_menu_opens_from_the_foot_and_names_the_account", async () => {
  await withDom(async () => {
    const { root, calls } = build();
    const button = find(root, "account-menu-button");
    const menu = find(root, "account-menu");
    assert.equal(button.getAttribute("aria-haspopup"), "menu");
    assert.equal(button.getAttribute("aria-expanded"), "false");
    assert.equal(button.getAttribute("aria-controls"), menu.getAttribute("id"));
    assert.equal(button.getAttribute("aria-label"), 'shell.account.menu {"email":"ada.lovelace@example.com"}');
    assert.equal(find(root, "account-menu-button").childNodes.find((c) => c.getAttribute?.("class") === "side-email").getAttribute("title"), "ada.lovelace@example.com", "a cut-off address can be read in full");
    assert.equal(menu.hidden, true);
    assert.ok(textOf(button).includes("AL"), "the round mark has the initials");

    await click(button);
    assert.equal(button.getAttribute("aria-expanded"), "true");
    assert.equal(menu.hidden, false);
    assert.deepEqual(all(root, "account-menu").length, 1);
    const items = [...walk(menu)].filter((n) => n.getAttribute?.("role") === "menuitem").map((n) => n.getAttribute("data-role"));
    assert.deepEqual(items, ["nav-account", "help", "lock", "sign-out"]);
    assert.equal(find(root, "nav-account").getAttribute("href"), "#/account");

    // Lock now locks and the menu closes.
    await click(find(root, "lock"));
    assert.equal(calls.lock, 1);
    assert.equal(menu.hidden, true);
    assert.equal(button.getAttribute("aria-expanded"), "false");

    // Sign out does what it was given.
    await click(button);
    await click(find(root, "sign-out"));
    assert.equal(calls.signOut, 1);
    // Help is a link to the documentation, in a window of its own that has no way back to the vault.
    const help = find(root, "help");
    assert.equal(help.tagName, "a");
    assert.match(help.getAttribute("href"), /^https:\/\//);
    assert.equal(help.getAttribute("target"), "_blank");
    assert.match(help.getAttribute("rel"), /noopener/);
    assert.match(help.getAttribute("rel"), /noreferrer/);
  });
});

test("a_menu_without_a_sign_out_handler_has_no_sign_out_item", async () => {
  await withDom(async () => {
    const { root } = build({ onSignOut: undefined });
    const menu = find(root, "account-menu");
    assert.ok(![...walk(menu)].some((n) => n.getAttribute?.("data-role") === "sign-out"));
  });
});

test("escape_closes_the_account_menu_and_the_focus_goes_back_to_its_button", async () => {
  await withDom(async () => {
    const { view, root, focused } = build();
    const button = find(root, "account-menu-button");
    await click(button);
    assert.equal(focused.at(-1), "nav-account", "the first item takes the focus when the menu opens");
    focused.length = 0;
    assert.equal(view.escape(), true);
    assert.equal(button.getAttribute("aria-expanded"), "false");
    assert.deepEqual(focused, ["account-menu-button"]);
    assert.equal(view.escape(), false, "nothing is open any more");
  });
});

test("the_arrow_keys_move_through_the_account_menu_and_tab_leaves_it", async () => {
  await withDom(async () => {
    const { root, focused } = build();
    const button = find(root, "account-menu-button");
    const menu = find(root, "account-menu");
    // The arrow down on the closed button opens it; the arrow up opens it at the last item.
    await fire(button, "keydown", { key: "ArrowDown" });
    assert.equal(button.getAttribute("aria-expanded"), "true");
    assert.equal(focused.at(-1), "nav-account");
    const order = ["nav-account", "help", "lock", "sign-out"];
    const key = async (name, from) => {
      await fire(menu, "keydown", { key: name, target: find(root, from) });
      return focused.at(-1);
    };
    assert.equal(await key("ArrowDown", "nav-account"), "help");
    assert.equal(await key("ArrowDown", "sign-out"), "nav-account", "it wraps round");
    assert.equal(await key("ArrowUp", "nav-account"), "sign-out");
    assert.equal(await key("Home", "lock"), order[0]);
    assert.equal(await key("End", "help"), order[3]);
    await fire(menu, "keydown", { key: "Tab", target: find(root, "help") });
    assert.equal(menu.hidden, true, "tab leaves the menu and closes it");
    await fire(button, "keydown", { key: "ArrowUp" });
    assert.equal(focused.at(-1), "sign-out");
  });
});

test("a_press_outside_closes_a_menu_and_a_press_inside_does_not", async () => {
  await withDom(async () => {
    const { view, root } = build();
    const button = find(root, "account-menu-button");
    const menu = find(root, "account-menu");
    await click(button);
    view.press(find(root, "help"));
    assert.equal(menu.hidden, false, "inside the menu");
    view.press(button);
    assert.equal(menu.hidden, false, "on its own button (that one toggles it)");
    view.press(find(root, "nav-items"));
    assert.equal(menu.hidden, true);
    assert.equal(button.getAttribute("aria-expanded"), "false");
  });
});

test("one_menu_is_open_at_a_time", async () => {
  await withDom(async () => {
    const prefs = createUiPrefs(memory(), []);
    prefs.pin("Home");
    prefs.pin("Finance");
    const { root } = build({ prefs, folders: FOLDERS });
    const [home, fin] = all(root, "folder-menu-button");
    const account = find(root, "account-menu-button");
    await click(home);
    await click(fin);
    assert.equal(home.getAttribute("aria-expanded"), "false");
    assert.equal(fin.getAttribute("aria-expanded"), "true");
    await click(account);
    assert.equal(fin.getAttribute("aria-expanded"), "false");
    assert.equal(account.getAttribute("aria-expanded"), "true");
  });
});

test("the_drawer_of_a_phone_opens_from_the_menu_button_and_puts_the_rest_out_of_reach", async () => {
  await withDom(async () => {
    const { view, root, behind, focused } = build();
    const open = find(root, "menu-open");
    const side = find(root, "side");
    assert.equal(open.getAttribute("aria-label"), "shell.menu.open");
    assert.equal(open.getAttribute("aria-expanded"), "false");
    assert.equal(open.getAttribute("aria-controls"), side.getAttribute("id"));
    assert.equal(side.getAttribute("data-open"), "false");

    await click(open);
    assert.equal(side.getAttribute("data-open"), "true");
    assert.equal(find(root, "drawer-backdrop").getAttribute("data-open"), "true");
    assert.equal(open.getAttribute("aria-expanded"), "true");
    assert.deepEqual(behind.map((n) => n.inert), [true, true], "the screen cannot be reached while the drawer is open");
    assert.equal(view.top.inert, true);
    assert.equal(focused.at(-1), "menu-close", "the focus moves into the drawer");
    assert.equal(view.state().drawerOpen, true);

    // Escape closes it and the focus goes back to the button that opened it.
    focused.length = 0;
    assert.equal(view.escape(), true);
    assert.equal(side.getAttribute("data-open"), "false");
    assert.equal(open.getAttribute("aria-expanded"), "false");
    assert.deepEqual(behind.map((n) => n.inert), [false, false]);
    assert.equal(view.top.inert, false);
    assert.deepEqual(focused, ["menu-open"]);
  });
});

test("the_drawer_closes_from_its_own_button_the_backdrop_and_a_chosen_entry", async () => {
  await withDom(async () => {
    const { root, view } = build();
    const side = find(root, "side");
    const state = () => side.getAttribute("data-open");
    for (const close of [() => click(find(root, "menu-close")), () => click(find(root, "drawer-backdrop")), () => click(find(root, "nav-trash"))]) {
      await click(find(root, "menu-open"));
      assert.equal(state(), "true");
      await close();
      assert.equal(state(), "false");
    }
    // Opening the drawer closes an account menu that was open.
    await click(find(root, "account-menu-button"));
    view.openDrawer();
    assert.equal(find(root, "account-menu").hidden, true);
  });
});

test("an_open_menu_closes_before_the_drawer_when_escape_is_pressed", async () => {
  await withDom(async () => {
    const { view, root } = build();
    view.openDrawer();
    await click(find(root, "account-menu-button"));
    assert.equal(view.escape(), true);
    assert.equal(find(root, "account-menu").hidden, true);
    assert.equal(view.state().drawerOpen, true, "the first Escape closed the menu only");
    assert.equal(view.escape(), true);
    assert.equal(view.state().drawerOpen, false);
  });
});

test("every_control_with_no_text_has_a_name_and_every_link_says_where_it_goes", async () => {
  await withDom(async () => {
    const prefs = createUiPrefs(memory(), []);
    prefs.pin("Home");
    const { root } = build({ prefs, folders: FOLDERS, admin: adminWay(true) });
    await settle();
    const nodes = [...walk(root)].filter((n) => n instanceof FakeElement);
    const controls = nodes.filter((n) => ["button", "a"].includes(n.tagName) || n.getAttribute("role") === "menuitem");
    assert.ok(controls.length >= 12);
    for (const control of controls) {
      const name = (control.getAttribute("aria-label") ?? textOf(control)).trim();
      assert.ok(name !== "", `${control.tagName} ${control.getAttribute("data-role")} has no name`);
    }
    // The icon-only buttons are exactly the ones that carry an aria-label and no text.
    const iconOnly = controls.filter((n) => textOf(n).trim() === "").map((n) => n.getAttribute("data-role")).sort();
    assert.deepEqual(iconOnly, ["collapse", "folder-menu-button", "menu-close", "menu-open"]);
    // The pictures are hidden from a screen reader.
    for (const icon of nodes.filter((n) => n.getAttribute("class")?.split(" ").includes("icon"))) assert.equal(icon.getAttribute("aria-hidden"), "true");
    // Menus and landmarks have names.
    assert.equal(find(root, "account-menu").getAttribute("aria-label"), "security.nav.account");
    const nav = nodes.find((n) => n.tagName === "nav");
    assert.equal(nav.getAttribute("aria-label"), "shell.nav.label");
  });
});

test("the_planned_pages_are_not_in_the_tab_order_and_say_why", async () => {
  await withDom(async () => {
    const { root } = build();
    for (const role of ["nav-generator", "nav-health", "nav-folders"]) {
      const node = find(root, role);
      assert.equal(node.tagName, "span", "not a link and not a button");
      assert.equal(node.getAttribute("aria-disabled"), "true");
      assert.equal(node.getAttribute("href"), null);
      assert.ok(textOf(node).includes("shell.soon"), role);
    }
  });
});

test("the_tab_order_is_the_skip_link_the_top_bar_the_menu_and_then_the_screen", async () => {
  await withDom(async () => {
    const engine = fakeEngine();
    const root = shellView({
      t, engine, session: { onLock() {} }, content: el("p", { "data-role": "page" }, "x"), lock: async () => {}, touch: () => true,
      scope: createWipeScope(), onLocked: () => el("div"), routes: ROUTES, prefs: createUiPrefs(null), email: "ada@example.com", admin: adminWay(true),
      signOut: async () => {},
    });
    await settle();
    const order = [...walk(root)]
      .filter((n) => n instanceof FakeElement && n.getAttribute("data-role") !== null)
      .map((n) => n.getAttribute("data-role"));
    const at = (role) => order.indexOf(role);
    const chain = ["skip", "menu-open", "brand", "collapse", "menu-close", "switch-admin", "nav-items", "nav-favorites", "nav-trash", "account-menu-button", "content"];
    chain.forEach((role, i) => assert.ok(at(role) >= 0, role));
    assert.deepEqual([...chain].sort((a, b) => at(a) - at(b)), chain);
    // The screen is in the main landmark, which can take the focus from the skip link.
    const main = find(root, "content");
    assert.equal(main.tagName, "main");
    assert.equal(main.getAttribute("tabindex"), "-1");
    let focused = null;
    main.focus = () => {
      focused = "content";
    };
    await click(find(root, "skip"));
    assert.equal(focused, "content");
  });
});

test("escape_and_a_press_outside_work_from_the_frame", async () => {
  await withDom(async () => {
    const root = shellView({
      t, engine: fakeEngine(), session: { onLock() {} }, content: el("p"), lock: async () => {}, touch: () => true,
      scope: createWipeScope(), onLocked: () => el("div"), routes: ROUTES, prefs: createUiPrefs(null),
    });
    const button = find(root, "account-menu-button");
    const menu = find(root, "account-menu");
    await click(button);
    const event = await fire(root, "keydown", { key: "Escape" });
    assert.equal(menu.hidden, true);
    assert.equal(event.prevented, true);
    // An Escape with nothing open is left alone.
    const idle = await fire(root, "keydown", { key: "Escape" });
    assert.equal(idle.prevented, undefined);
    await click(button);
    await fire(root, "pointerdown", { target: find(root, "nav-items") });
    assert.equal(menu.hidden, true);
  });
});

test("lock_now_in_the_frame_locks_the_vault", async () => {
  await withDom(async () => {
    let locked = 0;
    const root = shellView({
      t, engine: fakeEngine(), session: { onLock() {} }, content: el("p"), lock: async () => void (locked += 1), touch: () => true,
      scope: createWipeScope(), onLocked: () => el("div"), routes: ROUTES, prefs: createUiPrefs(null),
    });
    await click(find(root, "lock"));
    assert.equal(locked, 1);
  });
});

test("the_frame_follows_the_items_in_its_counts", async () => {
  await withDom(async () => {
    const engine = fakeEngine({ items: [{ id: "a".repeat(32), favorite: true }, { id: "b".repeat(32) }] });
    const root = shellView({
      t, engine, session: { onLock() {} }, content: el("p"), lock: async () => {}, touch: () => true,
      scope: createWipeScope(), onLocked: () => el("div"), routes: ROUTES, prefs: createUiPrefs(null),
    });
    const count = (role) => textOf(find(root, role).childNodes.find((c) => c.getAttribute?.("class") === "side-count")).trim();
    assert.deepEqual([count("nav-items"), count("nav-favorites")], ["2", "1"]);
    engine.items = [...engine.items, { id: "c".repeat(32), favorite: true }];
    engine.emit("changed", {});
    assert.deepEqual([count("nav-items"), count("nav-favorites")], ["3", "2"]);
  });
});

test("a_new_count_changes_the_number_in_place_and_leaves_the_entries_and_the_focus_alone", async () => {
  await withDom(async () => {
    const { view, root, focused } = build();
    const link = find(root, "nav-items");
    const favourites = find(root, "nav-favorites");
    const lists = find(root, "side-sections");
    const before = [...lists.childNodes];
    const countNode = link.childNodes.find((c) => c.getAttribute?.("class") === "side-count");
    view.setCounts({ all: 249, favorites: 12 });
    // The same nodes: nothing was built again, so the keyboard focus on a link stays where it is.
    assert.equal(find(root, "nav-items"), link);
    assert.equal(find(root, "nav-favorites"), favourites);
    assert.deepEqual([...lists.childNodes], before);
    assert.equal(link.childNodes.find((c) => c.getAttribute?.("class") === "side-count"), countNode);
    assert.equal(textOf(countNode).trim(), "249");
    assert.equal(textOf(favourites.childNodes.find((c) => c.getAttribute?.("class") === "side-count")).trim(), "12");
    assert.deepEqual(focused, []);
    // The same count again does nothing at all.
    view.setCounts({ all: 249, favorites: 12 });
    assert.equal(find(root, "nav-items"), link);
  });
});

test("the_menu_lets_go_of_the_window_and_the_page_when_it_is_disposed", async () => {
  await withDom(async () => {
    const queries = new Set();
    const win = {
      matchMedia: () => ({ addEventListener: (_type, fn) => queries.add(fn), removeEventListener: (_type, fn) => queries.delete(fn) }),
    };
    const { view, behind } = build({ win });
    assert.equal(queries.size, 1);
    view.dispose();
    assert.equal(queries.size, 0);
    // It no longer holds the parts of the page it made inert: opening the drawer leaves them alone.
    view.openDrawer();
    assert.deepEqual(behind.map((node) => node.inert), [undefined, undefined]);
  });
});

test("after_a_lock_nothing_of_the_old_frame_is_left_listening_and_it_holds_no_screen", async () => {
  await withDom(async () => {
    const queries = new Set();
    const hash = new Set();
    const win = {
      location: { hash: "#/items" },
      addEventListener: (type, fn) => type === "hashchange" && hash.add(fn),
      removeEventListener: (type, fn) => type === "hashchange" && hash.delete(fn),
      matchMedia: () => ({ addEventListener: (_type, fn) => queries.add(fn), removeEventListener: (_type, fn) => queries.delete(fn) }),
    };
    const engine = fakeEngine();
    const session = fakeSession();
    const scope = createWipeScope();
    const content = el("p", { "data-role": "secret-screen" }, "Bank");
    const root = shellView({
      t, engine, session, content, lock: async () => {}, touch: () => true, scope, onLocked: () => el("div", { "data-role": "unlock" }),
      routes: ROUTES, prefs: createUiPrefs(null), win,
    });
    assert.equal(queries.size, 1);
    assert.equal(hash.size, 1);
    assert.ok(engine.listeners.changed.size + engine.listeners.state.size + engine.listeners.error.size + engine.listeners.copied.size >= 4);
    assert.ok(find(root, "secret-screen"));

    await session.lock();
    // The listeners that point into the frame are gone, on the window, on the media query and on the engine.
    assert.equal(queries.size, 0);
    assert.equal(hash.size, 0);
    for (const [event, set] of Object.entries(engine.listeners)) assert.equal(set.size, 0, event);
    // The frame holds only the unlock screen: not the menu, not the screen, not the e-mail.
    assert.equal(find(root, "secret-screen"), null);
    assert.equal(find(root, "side"), null);
    assert.equal(root.childNodes.length, 1);
    assert.ok(find(root, "unlock"));
  });
});

test("a_frame_that_leaves_the_page_lets_go_when_its_scope_runs", async () => {
  await withDom(async () => {
    const queries = new Set();
    const win = { matchMedia: () => ({ addEventListener: (_t, fn) => queries.add(fn), removeEventListener: (_t, fn) => queries.delete(fn) }), addEventListener() {}, removeEventListener() {}, location: { hash: "" } };
    const engine = fakeEngine();
    const scope = createWipeScope();
    shellView({ t, engine, session: { onLock() {} }, content: el("p"), lock: async () => {}, touch: () => true, scope, onLocked: () => el("div"), routes: ROUTES, prefs: createUiPrefs(null), win });
    assert.equal(queries.size, 1);
    scope.run();
    assert.equal(queries.size, 0);
    assert.equal(engine.listeners.changed.size, 0);
  });
});

test("a_lock_forgets_the_pins_and_nothing_of_a_folder_is_written_to_the_device", async () => {
  await withDom(async () => {
    const writes = [];
    const storage = { getItem: () => null, setItem: (k, v) => void writes.push([k, v]), removeItem() {} };
    const pins = [];
    const prefs = createUiPrefs(storage, pins);
    prefs.pin("Home");
    const session = fakeSession();
    const root = shellView({
      t, engine: fakeEngine(), session, content: el("p"), lock: async () => {}, touch: () => true,
      scope: createWipeScope(), onLocked: () => el("div"), routes: ROUTES, prefs, folders: FOLDERS,
    });
    assert.deepEqual(all(root, "nav-folder").map((link) => textOf(link).trim()), ["Home", "Network"]);
    // Pinning and unpinning in the menu writes nothing at all.
    await click(find(root, "folder-menu-button"));
    await click(find(root, "unpin"));
    assert.deepEqual(writes, []);
    prefs.pin("Finance");
    assert.deepEqual(pins, ["Finance"]);
    await session.lock();
    assert.deepEqual(pins, [], "the lock forgot them");
    assert.deepEqual(writes, [], "and no folder name was ever written");
  });
});

// ------------------------------------------------------------ the theme choice

/** A theme choice over a word in memory, like the real one over localStorage. */
function themeChoice(initial = "auto") {
  const state = { now: initial, sets: [] };
  return { state, current: () => state.now, set: (name) => { state.sets.push(name); state.now = name; } };
}

const themeRoles = (root) => [...walk(find(root, "account-menu"))].filter((n) => n.getAttribute?.("role") === "menuitemradio");

test("a_menu_without_a_theme_choice_has_none", async () => {
  await withDom(async () => {
    const { root } = build();
    assert.equal(find(root, "theme"), null);
    assert.deepEqual(themeRoles(root), []);
  });
});

test("the_account_menu_offers_light_dark_and_system_as_a_group_of_radio_entries", async () => {
  await withDom(async () => {
    const { root } = build({ theme: themeChoice("dark") });
    const group = find(root, "theme");
    assert.equal(group.getAttribute("role"), "group");
    const label = [...walk(group)].find((n) => n.getAttribute?.("class") === "side-menu-label");
    assert.equal(group.getAttribute("aria-labelledby"), label.getAttribute("id"), "the group is named by its heading");
    assert.ok(textOf(label).includes("shell.theme.label"));
    const radios = themeRoles(root);
    assert.deepEqual(radios.map((n) => n.getAttribute("data-theme-set")), ["light", "dark", "auto"], "Light, Dark, System in that order");
    assert.deepEqual(radios.map((n) => textOf(n).trim()), ["shell.theme.light", "shell.theme.dark", "shell.theme.system"]);
    assert.deepEqual(radios.map((n) => n.getAttribute("aria-checked")), ["false", "true", "false"], "the choice in force is the checked one");
    for (const radio of radios) assert.equal(radio.tagName, "button", "a real button: Enter and Space work");
  });
});

test("choosing_a_theme_applies_it_checks_it_and_leaves_the_menu_open", async () => {
  await withDom(async () => {
    const theme = themeChoice("auto");
    const { root } = build({ theme });
    const button = find(root, "account-menu-button");
    const menu = find(root, "account-menu");
    await click(button);
    const checked = () => themeRoles(root).filter((n) => n.getAttribute("aria-checked") === "true").map((n) => n.getAttribute("data-theme-set"));
    assert.deepEqual(checked(), ["auto"]);
    await click(themeRoles(root)[0]);
    assert.deepEqual(theme.state.sets, ["light"]);
    assert.deepEqual(checked(), ["light"]);
    assert.equal(menu.hidden, false, "the menu stays open, so the change can be seen and changed again");
    await click(themeRoles(root)[1]);
    assert.deepEqual(theme.state.sets, ["light", "dark"]);
    assert.deepEqual(checked(), ["dark"]);
    await click(themeRoles(root)[2]);
    assert.deepEqual(theme.state.sets, ["light", "dark", "auto"]);
    assert.deepEqual(checked(), ["auto"]);
  });
});

test("the_menu_reads_the_theme_again_when_it_opens_so_another_tabs_choice_shows", async () => {
  await withDom(async () => {
    const theme = themeChoice("light");
    const { root } = build({ theme });
    const button = find(root, "account-menu-button");
    await click(button);
    await click(button); // closed again
    theme.state.now = "dark"; // another tab chose
    await click(button);
    assert.deepEqual(themeRoles(root).map((n) => n.getAttribute("aria-checked")), ["false", "true", "false"]);
  });
});

test("the_theme_entries_are_in_the_arrow_key_order_between_help_and_lock", async () => {
  await withDom(async () => {
    const { root, focused } = build({ theme: themeChoice() });
    const menu = find(root, "account-menu");
    await click(find(root, "account-menu-button"));
    const radios = themeRoles(root).map((n) => n.getAttribute("data-theme-set"));
    const order = ["nav-account", "help", ...radios.map((r) => `theme-${r}`), "lock", "sign-out"];
    const role = (node) => (node.getAttribute("data-role") === "theme-choice" ? `theme-${node.getAttribute("data-theme-set")}` : node.getAttribute("data-role"));
    const nodes = [...walk(menu)].filter((n) => ["menuitem", "menuitemradio"].includes(n.getAttribute?.("role")));
    assert.deepEqual(nodes.map(role), order);
    // The arrow down from Help goes to Light, and from System to Lock.
    for (const node of nodes) node.focus = () => focused.push(role(node));
    await fire(menu, "keydown", { key: "ArrowDown", target: find(root, "help") });
    assert.equal(focused.at(-1), "theme-light");
    await fire(menu, "keydown", { key: "ArrowDown", target: themeRoles(root)[2] });
    assert.equal(focused.at(-1), "lock");
  });
});

test("lock_and_the_other_entries_still_close_the_menu_when_the_theme_choice_is_there", async () => {
  await withDom(async () => {
    const { root, calls } = build({ theme: themeChoice() });
    await click(find(root, "account-menu-button"));
    await click(find(root, "lock"));
    assert.equal(calls.lock, 1);
    assert.equal(find(root, "account-menu").hidden, true);
  });
});
