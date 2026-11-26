/* SOC AudiDashboard: theme toggle. Loaded with <script src defer>; no inline script anywhere (CSP). */
(function () {
  "use strict";
  var KEY = "audidash-theme";
  var root = document.documentElement;

  function readStored() {
    try {
      return window.localStorage.getItem(KEY);
    } catch (e) {
      return null;
    }
  }

  function store(value) {
    try {
      window.localStorage.setItem(KEY, value);
    } catch (e) {
      /* storage blocked: the choice simply lasts for this page view */
    }
  }

  function apply(theme, button) {
    root.setAttribute("data-theme", theme);
    if (button) {
      button.setAttribute("aria-pressed", theme === "light" ? "true" : "false");
      button.textContent = theme === "light" ? "Tema escuro" : "Tema claro";
    }
  }

  var current = readStored() === "light" ? "light" : "dark";
  apply(current, null);

  document.addEventListener("DOMContentLoaded", function () {
    var button = document.getElementById("theme-toggle");
    if (!button) {
      return;
    }
    apply(current, button);
    button.addEventListener("click", function () {
      current = current === "light" ? "dark" : "light";
      apply(current, button);
      store(current);
    });
  });
})();
