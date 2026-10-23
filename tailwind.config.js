/** Farben und Schriften kommen aus samonboarding/web/theme.json (gleiche Quelle wie der CDN-Fallback). */
const theme = require('./samonboarding/web/theme.json');

module.exports = {
  content: ['./samonboarding/web/**/*.html'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: theme.colors,
      fontFamily: theme.fontFamily,
    },
  },
};
