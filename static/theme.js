// Sets the colour theme before the page paints, so there is no flash.
// Loaded as a file (not inline) so the page can keep a strict Content Security Policy.
(function () {
  var theme = null;
  try { theme = localStorage.getItem("securecheck-theme"); } catch (e) { /* storage unavailable */ }
  if (theme !== "light" && theme !== "dark") {
    theme = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }
  document.documentElement.setAttribute("data-theme", theme);
})();
