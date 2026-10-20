/** @type {import('tailwindcss').Config} */
export default {
  content: ["./src/**/*.{astro,html,js,jsx,md,mdx,svelte,ts,tsx,vue}"],
  // Python slices in write-ups are code examples, not arbitrary CSS properties.
  blocklist: ["[-32:-16]", "[-80:-32]"],
  theme: {
    extend: {},
  },
  plugins: [require("@tailwindcss/typography")],
};
