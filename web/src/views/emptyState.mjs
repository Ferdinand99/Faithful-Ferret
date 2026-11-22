// An empty page: a round icon, one short line and the one thing worth doing next. The pages of the shell (the list,
// the favourites, a search with no hit, the trash, the devices) all say "nothing here" the same way, so the user
// learns it once. Nothing here holds a secret; the text and the label are put in as text nodes.
import { el, mount } from "../dom.mjs";

/**
 * @typedef {object} EmptyAction
 * @property {string} label the button's text
 * @property {string} role its `data-role`
 * @property {string} [href] a link to a page of this app (`#/...`); without it the action is a button
 * @property {() => void} [onClick] what a button does
 * @property {boolean} [primary] the filled style (the action that makes the first thing)
 * @property {string} [icon] the class that gives the button a leading icon, for example `i-plus`
 */

/**
 * The parts of an empty state: the icon, the text and the actions, in one block that a page can fill again when what it
 * shows changes (the list does).
 * @param {{ role: string, icon: string, class?: string }} options `icon` is a `data-icon` name of the shell's icons
 */
export function emptyBlock({ role, icon, class: extra = "" }) {
  const text = el("p", { class: "empty-text", "data-role": "empty-text" });
  const actions = el("div", { class: "actions", "data-role": "empty-actions" });
  const picture = el("span", { class: "icon empty-icon", "data-icon": icon, "aria-hidden": "true" });
  const root = el("div", { class: `empty-state ${extra}`.trim(), "data-role": role }, picture, text, actions);
  return {
    root,
    /** @param {string} line @param {EmptyAction[]} [list] @param {string} [other] another icon for this reason */
    fill(line, list = [], other) {
      if (other) picture.setAttribute("data-icon", other);
      mount(text, document.createTextNode(line));
      mount(actions, ...list.map(actionNode));
    },
  };
}

/**
 * A finished empty state, for a page that is empty for one reason.
 * @param {{ role: string, icon: string, text: string, actions?: EmptyAction[], class?: string }} options
 * @returns {HTMLElement}
 */
export function emptyState({ role, icon, text, actions = [], class: extra }) {
  const block = emptyBlock({ role, icon, class: extra });
  block.fill(text, actions);
  return block.root;
}

/** @param {EmptyAction} action */
function actionNode(action) {
  const style = action.primary === true ? "btn btn-primary" : "btn btn-secondary";
  const klass = action.icon ? `${style} ${action.icon}` : style;
  if (typeof action.href === "string") return el("a", { class: klass, href: action.href, "data-role": action.role }, action.label);
  const button = el("button", { type: "button", class: klass, "data-role": action.role }, action.label);
  if (typeof action.onClick === "function") button.addEventListener("click", action.onClick);
  return button;
}
