/** Farben und Schriften kommen aus samonboarding/web/theme.json (gleiche Quelle wie der CDN-Fallback). */
const theme = require('./samonboarding/web/theme.json');

module.exports = {
  // HTML and the interface script (its templates contain classes too)
  content: ['./samonboarding/web/**/*.html', './samonboarding/web/**/*.js'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: theme.colors,
      fontFamily: theme.fontFamily,
    },
  },
};
