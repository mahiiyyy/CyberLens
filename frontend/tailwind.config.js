export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: "#070b14",
          panel: "#0d1422",
          panel2: "#101a2b",
          line: "#1d2b3f",
          cyan: "#22d3ee",
          purple: "#a78bfa",
          red: "#f87171",
          amber: "#fbbf24",
          green: "#34d399"
        }
      },
      boxShadow: {
        glow: "0 0 40px rgba(34,211,238,.08)"
      }
    }
  },
  plugins: []
};
