/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [ "./src", "templates" ],
  theme: {
    extend: {
      colors: {
        'primary': '#c58ad4',
        'secondary': '#5170a9',
        'success': '#5da2a3',
        'warning': '#eac8a4',
        'danger': '#fb8f98',
      }
    }
  },
  plugins: [],
}

