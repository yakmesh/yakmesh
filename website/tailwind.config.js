/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./docs/**/*.html",
    "./index.html",
    "./pricing.html"
  ],
  theme: {
    extend: {
      colors: {
        theme: {
          primary: '#10b981',
          secondary: '#059669',
          accent: '#34d399',
          bg: '#022c22',
          glow: 'rgba(16, 185, 129, 0.1)'
        },
        mountain: {
          100: '#e8f4f0',
          200: '#b8d4cb',
          300: '#88b4a6',
          400: '#6a9a8a',
          500: '#4c7f6e',
          600: '#3d6659',
          700: '#2e4c43',
          800: '#1f332d',
          900: '#101a16'
        },
        Yakmesh: {
          400: '#10b981',
          500: '#059669',
          600: '#047857',
          700: '#065f46',
          800: '#064e3b',
          900: '#022c22'
        }
      }
    }
  },
  plugins: []
}
