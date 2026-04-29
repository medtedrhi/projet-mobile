/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: "#0f172a",
        mist: "#f8fafc",
        coral: "#ef4444",
        moss: "#166534",
        amberline: "#f59e0b",
        steel: "#334155"
      },
      fontFamily: {
        sans: ["'Manrope'", "sans-serif"],
        display: ["'Space Grotesk'", "sans-serif"]
      },
      boxShadow: {
        panel: "0 20px 60px rgba(15, 23, 42, 0.12)"
      }
    },
  },
  plugins: [],
};
