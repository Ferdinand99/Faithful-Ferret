// A menu that opens from a button, shared by the side menu and the list: `aria-expanded` on the button, arrow keys,
// Home and End inside, and a way to close it that puts the focus back. Nothing here holds a secret.

/** @param {any} node */
export const focusNode = (node) => {
  if (typeof node?.focus === "function") node.focus();
};

/** Whether `node` is `ancestor` or stands below it. @param {any} node @param {any} ancestor */
export function within(node, ancestor) {
  for (let one = node; one; one = one.parentNode) if (one === ancestor) return true;
  return false;
}

/**
 * A menu that opens from a button: `aria-expanded` on the button, arrow keys,
 * Home and End inside, and a way to close it that puts the focus back.
 * @param {{
 *   trigger: HTMLElement, menu: HTMLElement, items: () => HTMLElement[], onOpen?: () => void, onClose?: () => void,
 *   escape?: boolean,
 * }} options `escape`: Escape inside the menu (or on its button, while it is open) closes it and puts the focus back on the button;
 *   the side menu leaves Escape to the frame, which closes the drawer as well
 */
export function popMenu({ trigger, menu, items, onOpen, onClose, escape = false }) {
  let open = false;
  /** @param {boolean} value */
  const set = (value) => {
    const was = open;
    open = value;
    menu.hidden = !value;
    trigger.setAttribute("aria-expanded", value ? "true" : "false");
    if (was && !value) onClose?.();
  };
  /** @param {"first" | "last" | null} focus */
  const show = (focus) => {
    onOpen?.();
    set(true);
    const list = items();
    focusNode(focus === "last" ? list[list.length - 1] : list[0]);
  };
  set(false);
  trigger.addEventListener("click", () => {
    if (open) {
      set(false);
      return;
    }
    show("first");
  });
  trigger.addEventListener("keydown", (/** @type {any} */ event) => {
    if (escape && open && event.key === "Escape") {
      event.preventDefault?.();
      set(false);
      return;
    }
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault?.();
      if (!open) show(event.key === "ArrowUp" ? "last" : "first");
    }
  });
  menu.addEventListener("keydown", (/** @type {any} */ event) => {
    const list = items();
    const at = list.findIndex((node) => node === event.target || within(event.target, node));
    /** @param {number} to */
    const move = (to) => {
      event.preventDefault?.();
      focusNode(list[(to + list.length) % list.length]);
    };
    if (event.key === "ArrowDown") move(at + 1);
    else if (event.key === "ArrowUp") move(at <= 0 ? list.length - 1 : at - 1);
    else if (event.key === "Home") move(0);
    else if (event.key === "End") move(list.length - 1);
    else if (escape && event.key === "Escape") {
      event.preventDefault?.();
      set(false);
      focusNode(trigger);
    } else if (event.key === "Tab") set(false); // the focus goes on to the next control by itself
  });
  return {
    trigger,
    menu,
    isOpen: () => open,
    /** @param {"first" | "last" | null} [focus] */
    open: (focus = "first") => show(focus),
    /** @param {boolean} [returnFocus] */
    close(returnFocus = false) {
      if (!open) return;
      set(false);
      if (returnFocus) focusNode(trigger);
    },
  };
}

