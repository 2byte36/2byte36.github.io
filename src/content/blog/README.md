# Blog Content

Blog write-ups live in:

```text
src/content/blog/writeups/<year>/<slug>/
  index.md
  assets/
    hero.png
    image.png
```

Use relative image paths from `index.md`:

```md
---
title: "Example CTF 2026"
description: "Short description"
pubDate: "2026-01-01"
---

![alt text](./assets/image.png)
```

`heroImage` is optional. Add it only when the file already exists:

```md
heroImage: "./assets/hero.png"
```

If you edit `index.md` in VS Code and paste an image from the clipboard, the workspace setting copies it into the same post's `assets/` folder.

Zed currently drops pasted images beside `index.md`. Run this after pasting:

```sh
npm run tidy:blog-assets
```

The same command also runs automatically before `npm run build`, so GitHub Pages CI/CD tidies pasted root images before Astro builds the deployed site.
