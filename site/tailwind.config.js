/** @type {import('tailwindcss').Config} */

// Every color is a CSS variable (an RGB triplet) defined per theme in index.css,
// so one class works in light and dark and opacity modifiers still apply.
const token = (name) => `rgb(var(--${name}) / <alpha-value>)`;

export default {
  darkMode: ["selector", '[data-theme="dark"]'],
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        paper: token("paper"),     // page
        panel: token("panel"),     // inset surfaces: code, tables, the lab
        rule: token("rule"),       // hairlines
        ink: token("ink"),         // headings, key figures
        body: token("body"),       // running text
        muted: token("muted"),     // captions, labels
        proof: token("proof"),     // LINE PROVEN -- the only green on the page
        warn: token("warn"),       // CLASS ONLY
        sev: token("sev"),         // failures, severity
      },
      fontFamily: {
        sans: ['"IBM Plex Sans"', "system-ui", "sans-serif"],
        mono: ['"IBM Plex Mono"', "ui-monospace", "monospace"],
      },
      maxWidth: { page: "1120px" },
    },
  },
  plugins: [],
};
