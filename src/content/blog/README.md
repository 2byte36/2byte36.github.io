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
heroImage: "./assets/hero.png"
---

![alt text](./assets/image.png)
```

If you edit `index.md` in VS Code and paste an image from the clipboard, the workspace setting copies it into the same post's `assets/` folder.
