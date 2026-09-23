/** @type {import('tailwindcss').Config} */
export default {
  darkMode: "class",
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        // Inherited from the tool's own HTML report so the site and the artifact
        // it advertises read as one product.
        base:    "#0a0c11",
        surface: "#12161f",
        raised:  "#171d29",
        line:    "#232a38",
        ink:     "#f2f5fb",
        muted:   "#8a93a6",
        faint:   "#5f6b80",
        violet:  "#7c5cff",
        violets: "#a892ff",
        proof:   "#2fd47a",
        warn:    "#ff9f43",
        sev:     "#ff5c6c",
      },
      fontFamily: {
        display: ['"Space Grotesk"', "system-ui", "sans-serif"],
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ['"JetBrains Mono"', "ui-monospace", "monospace"],
      },
      animation: {
        "border-beam": "border-beam calc(var(--duration)*1s) infinite linear",
        marquee: "marquee var(--duration) linear infinite",
        shine: "shine var(--duration) infinite linear",
      },
      keyframes: {
        "border-beam": {
          "100%": { "offset-distance": "100%" },
        },
        marquee: {
          from: { transform: "translateX(0)" },
          to: { transform: "translateX(calc(-100% - var(--gap)))" },
        },
        shine: {
          "0%": { "background-position": "0% 0%" },
          "50%": { "background-position": "100% 100%" },
          to: { "background-position": "0% 0%" },
        },
      },
    },
  },
  plugins: [],
};
