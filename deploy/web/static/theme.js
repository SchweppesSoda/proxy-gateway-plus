"use strict";

(() => {
  const COOKIE_NAME = "pdg_theme";
  const MODES = ["system", "light", "dark"];
  const media = window.matchMedia("(prefers-color-scheme: dark)");

  function readMode() {
    const match = document.cookie.split(";").map((item) => item.trim())
      .find((item) => item.startsWith(`${COOKIE_NAME}=`));
    const value = match ? decodeURIComponent(match.slice(COOKIE_NAME.length + 1)) : "system";
    return MODES.includes(value) ? value : "system";
  }

  function resolved(mode) {
    return mode === "system" ? (media.matches ? "dark" : "light") : mode;
  }

  function paint(mode) {
    const theme = resolved(mode);
    document.documentElement.dataset.themeMode = mode;
    document.documentElement.dataset.theme = theme;
    document.documentElement.style.colorScheme = theme;
    const meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.content = theme === "dark" ? "#101719" : "#f4f7f6";
    window.dispatchEvent(new CustomEvent("pdg-theme-change", {
      detail: { mode, theme }
    }));
  }

  function writeMode(mode) {
    const selected = MODES.includes(mode) ? mode : "system";
    const secure = location.protocol === "https:" ? "; Secure" : "";
    document.cookie = `${COOKIE_NAME}=${encodeURIComponent(selected)}; Path=/; Max-Age=31536000; SameSite=Strict${secure}`;
    paint(selected);
    return selected;
  }

  let mode = readMode();
  paint(mode);
  media.addEventListener("change", () => {
    if (mode === "system") paint(mode);
  });

  window.PDGTheme = Object.freeze({
    get mode() { return mode; },
    get resolved() { return resolved(mode); },
    set(next) { mode = writeMode(next); return mode; },
    cycle() {
      const next = MODES[(MODES.indexOf(mode) + 1) % MODES.length];
      mode = writeMode(next);
      return mode;
    }
  });
})();
