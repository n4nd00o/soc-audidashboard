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

  /* HTMX failures that are not swapped (403/404/5xx): show a short, generic status message. */
  var statusBox = null;
  var hideTimer = null;

  function ensureStatusBox() {
    if (statusBox) {
      return statusBox;
    }
    statusBox = document.createElement("div");
    statusBox.className = "toast-status";
    statusBox.setAttribute("role", "status");
    statusBox.setAttribute("aria-live", "polite");
    document.body.appendChild(statusBox);
    return statusBox;
  }

  function messageFor(code) {
    if (code === 403) {
      return "Ação não permitida ou sessão expirada. Recarregue a página.";
    }
    if (code === 404) {
      return "Item não encontrado.";
    }
    if (code >= 500) {
      return "Erro no servidor. Tente novamente em instantes.";
    }
    return "Não foi possível concluir a ação.";
  }

  document.addEventListener("htmx:responseError", function (evt) {
    var xhr = evt.detail && evt.detail.xhr;
    var code = xhr ? xhr.status : 0;
    var box = ensureStatusBox();
    box.textContent = messageFor(code);
    window.clearTimeout(hideTimer);
    hideTimer = window.setTimeout(function () {
      box.textContent = "";
    }, 8000);
  });
})();
