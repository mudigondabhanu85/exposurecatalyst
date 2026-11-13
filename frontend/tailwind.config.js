/** @type {import('tailwindcss').Config} */
// Brand tokens resolve to the CSS variables in src/brand/tokens.css (single source: brand/tokens).
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        "ec-navy": "var(--ec-navy)",
        "ec-orange": "var(--ec-orange)",
        "ec-orange-bright": "var(--ec-orange-bright)",
        "ec-slate": "var(--ec-slate)",
        "ec-slate-light": "var(--ec-slate-light)",
        "ec-surface": "var(--ec-surface)",
        "ec-surface-alt": "var(--ec-surface-alt)",
        "ec-border": "var(--ec-border)",
      },
      fontFamily: {
        heading: ["var(--ec-font-heading)"],
        body: ["var(--ec-font-body)"],
        sans: ["var(--ec-font-body)"],
      },
      borderRadius: {
        sm: "var(--ec-radius-sm)",
        md: "var(--ec-radius-md)",
        lg: "var(--ec-radius-lg)",
      },
    },
  },
  plugins: [],
};
