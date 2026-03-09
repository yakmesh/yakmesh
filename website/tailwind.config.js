/*
 * YAKMESH™: Yielding Atomic Kernel Modular Encryption Secured Hub
 * Copyright (C) 2026 YAKMESH™ / [JGP]
 *
 * TRADEMARK NOTICE:
 * YAKMESH™ is a trademark of PeerQuanta, application pending (Serial No. 99594620).
 * Unauthorized use of the YAKMESH™ name, logo, or branding is strictly prohibited.
 *
 * LICENSE:
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 * "The standard is binary. The reality is ternary. The resonance is 432."
 */
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
