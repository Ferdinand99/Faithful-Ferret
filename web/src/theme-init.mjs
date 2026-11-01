// Runs before the first paint (a blocking script, not a module), so a chosen
// theme never flashes the other one. The only thing it reads is the word
// "light" or "dark" that the footer switch stored; no secret is ever kept here.
// theme.mjs holds the same key and does the rest.
(function () {
  try {
    var stored = localStorage.getItem("ferret-theme");
    if (stored === "light" || stored === "dark") document.documentElement.setAttribute("data-theme", stored);
  } catch (error) {
    // Storage is blocked: the system setting decides.
  }
})();
