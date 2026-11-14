/** Colours and fonts come from samonboarding/web/theme.json.
 *  Every colour becomes a CSS variable (light values on :root, dark ones on :root[data-theme="dark"]),
 *  so the same classes (bg-slate-900, text-cyan-400 ...) follow the chosen appearance. */
const plugin = require('tailwindcss/plugin');
const theme = require('./samonboarding/web/theme.json');

const channels = (hex) => [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16)).join(' ');
const vars = (palette) => {
  const out = {};
  for (const [family, shades] of Object.entries(palette)) {
    for (const [shade, hex] of Object.entries(shades)) out[`--c-${family}-${shade}`] = channels(hex);
  }
  return out;
};
const colors = {};
for (const [family, shades] of Object.entries(theme.colors)) {
  colors[family] = {};
  for (const shade of Object.keys(shades)) colors[family][shade] = `rgb(var(--c-${family}-${shade}) / <alpha-value>)`;
}

module.exports = {
  // HTML and the interface script (its templates contain classes too)
  content: ['./samonboarding/web/**/*.html', './samonboarding/web/**/*.js'],
  darkMode: ['selector', '[data-theme="dark"]'],
  theme: {
    extend: {
      colors,
      fontFamily: theme.fontFamily,
    },
  },
  plugins: [
    plugin(({ addBase }) => {
      addBase({ ':root': vars(theme.colors), ':root[data-theme="dark"]': vars(theme.dark) });
    }),
  ],
};
