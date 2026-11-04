import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./app/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
    "./lib/**/*.{ts,tsx,mjs}",
  ],
  theme: {
    extend: {
      colors: {
        night: "#060a13",
      },
    },
  },
  plugins: [],
};

export default config;
