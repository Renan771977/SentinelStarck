/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx,ts,tsx}"],
  theme: {
    extend: {
      colors: {
        app: "#090C12",
        panel: "#0F141D",
        raised: "#161D29",
        line: "#222C3C",
        accent: "#00C2FF",
        violet: "#7C3AED",
        sev: {
          critical: "#FF4D6D",
          high: "#FF8A3D",
          medium: "#FFC94D",
          low: "#4DA8FF",
          info: "#7D8899",
          ok: "#35D07F",
        },
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "monospace"],
      },
    },
  },
  plugins: [],
};
