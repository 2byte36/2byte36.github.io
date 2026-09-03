import { constants as fsConstants } from "node:fs";
import fs from "node:fs/promises";
import path from "node:path";

const blogRoot = path.resolve("src/content/blog/writeups");
const imageExtensions = new Set([
  ".avif",
  ".gif",
  ".jpeg",
  ".jpg",
  ".png",
  ".svg",
  ".webp",
]);

const changes = {
  moved: [],
  rewrote: [],
  heroFallbacks: [],
};

async function exists(filePath) {
  try {
    await fs.access(filePath, fsConstants.F_OK);
    return true;
  } catch {
    return false;
  }
}

function isImageFile(fileName) {
  return imageExtensions.has(path.extname(fileName).toLowerCase());
}

function sanitizeFileName(fileName) {
  const ext = path.extname(fileName).toLowerCase();
  const baseName = path.basename(fileName, path.extname(fileName));
  const safeBaseName = baseName
    .toLowerCase()
    .normalize("NFKD")
    .replace(/[^\x00-\x7F]/g, "")
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "");

  return `${safeBaseName || "image"}${ext}`;
}

async function uniqueDestination(assetsDir, fileName) {
  const ext = path.extname(fileName);
  const baseName = path.basename(fileName, ext);
  let candidate = fileName;
  let counter = 1;

  while (await exists(path.join(assetsDir, candidate))) {
    candidate = `${baseName}-${counter}${ext}`;
    counter += 1;
  }

  return candidate;
}

async function findPostIndexes(dir) {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  const indexes = [];

  for (const entry of entries) {
    const entryPath = path.join(dir, entry.name);

    if (entry.isDirectory()) {
      indexes.push(...await findPostIndexes(entryPath));
      continue;
    }

    if (entry.isFile() && (entry.name === "index.md" || entry.name === "index.mdx")) {
      indexes.push(entryPath);
    }
  }

  return indexes;
}

function splitUrlSuffix(ref) {
  const suffixIndex = ref.search(/[?#]/);
  if (suffixIndex === -1) {
    return { refPath: ref, suffix: "" };
  }

  return {
    refPath: ref.slice(0, suffixIndex),
    suffix: ref.slice(suffixIndex),
  };
}

function localImageKey(ref) {
  if (
    ref.startsWith("/") ||
    ref.startsWith("#") ||
    /^[a-z][a-z0-9+.-]*:/i.test(ref)
  ) {
    return undefined;
  }

  const { refPath, suffix } = splitUrlSuffix(ref);
  let key = refPath.replace(/^\.\//, "");

  try {
    key = decodeURI(key);
  } catch {
    // Keep the original key if the editor inserted a partially encoded path.
  }

  return { key, suffix };
}

function rewriteTarget(ref, renameMap) {
  const localRef = localImageKey(ref);
  if (!localRef) {
    return undefined;
  }

  const replacement = renameMap.get(localRef.key);
  return replacement ? `${replacement}${localRef.suffix}` : undefined;
}

function rewriteMarkdownImages(content, renameMap, markdownPath) {
  return content.replace(/!\[([^\]]*)\]\(([^)\n]+)\)/g, (match, alt, rawTarget) => {
    const target = rawTarget.trim();

    if (target.startsWith("<")) {
      const closeIndex = target.indexOf(">");
      if (closeIndex === -1) {
        return match;
      }

      const imageRef = target.slice(1, closeIndex);
      const suffix = target.slice(closeIndex + 1);
      const replacement = rewriteTarget(imageRef, renameMap);

      if (!replacement) {
        return match;
      }

      changes.rewrote.push(path.relative(process.cwd(), markdownPath));
      return `![${alt}](<${replacement}>${suffix})`;
    }

    const targetMatch = target.match(/^(\S+)(.*)$/s);
    if (!targetMatch) {
      return match;
    }

    const [, imageRef, suffix] = targetMatch;
    const replacement = rewriteTarget(imageRef, renameMap);

    if (!replacement) {
      return match;
    }

    changes.rewrote.push(path.relative(process.cwd(), markdownPath));
    return `![${alt}](${replacement}${suffix})`;
  });
}

function rewriteHeroImage(content, renameMap, markdownPath) {
  return content.replace(
    /^(\s*heroImage:\s*)(["']?)([^"'\n]+)\2(\s*)$/m,
    (match, prefix, quote, imageRef, suffix) => {
      const replacement = rewriteTarget(imageRef.trim(), renameMap);
      if (!replacement) {
        return match;
      }

      changes.rewrote.push(path.relative(process.cwd(), markdownPath));
      return `${prefix}${quote || "\""}${replacement}${quote || "\""}${suffix}`;
    },
  );
}

async function collectAssetImages(assetsDir) {
  if (!await exists(assetsDir)) {
    return [];
  }

  const entries = await fs.readdir(assetsDir, { withFileTypes: true });
  return entries
    .filter((entry) => entry.isFile() && isImageFile(entry.name))
    .map((entry) => `./assets/${entry.name}`)
    .sort();
}

async function applyHeroFallback(content, postDir, movedTargets, markdownPath) {
  const heroMatch = content.match(/^(\s*heroImage:\s*)(["']?)([^"'\n]+)\2(\s*)$/m);
  if (!heroMatch) {
    return content;
  }

  const [, prefix, quote, imageRef, suffix] = heroMatch;
  const localRef = localImageKey(imageRef.trim());
  if (!localRef) {
    return content;
  }

  const heroPath = path.join(postDir, localRef.key);
  if (await exists(heroPath)) {
    return content;
  }

  const fallback = movedTargets[0];
  if (!fallback) {
    return content;
  }

  changes.heroFallbacks.push(
    `${path.relative(process.cwd(), markdownPath)}: ${imageRef.trim()} -> ${fallback}`,
  );

  return content.replace(
    heroMatch[0],
    `${prefix}${quote || "\""}${fallback}${quote || "\""}${suffix}`,
  );
}

async function tidyPost(markdownPath) {
  const postDir = path.dirname(markdownPath);
  const assetsDir = path.join(postDir, "assets");
  const entries = await fs.readdir(postDir, { withFileTypes: true });
  const rootImages = entries
    .filter((entry) => entry.isFile() && isImageFile(entry.name))
    .map((entry) => entry.name)
    .sort();

  const renameMap = new Map();
  const movedTargets = [];

  if (rootImages.length > 0) {
    await fs.mkdir(assetsDir, { recursive: true });
  }

  for (const rootImage of rootImages) {
    const source = path.join(postDir, rootImage);
    const safeName = await uniqueDestination(assetsDir, sanitizeFileName(rootImage));
    const destination = path.join(assetsDir, safeName);
    const relativeDestination = `./assets/${safeName}`;

    await fs.rename(source, destination);

    renameMap.set(rootImage, relativeDestination);
    renameMap.set(encodeURI(rootImage), relativeDestination);
    movedTargets.push(relativeDestination);
    changes.moved.push(
      `${path.relative(process.cwd(), source)} -> ${path.relative(process.cwd(), destination)}`,
    );
  }

  let content = await fs.readFile(markdownPath, "utf8");
  const originalContent = content;
  content = rewriteMarkdownImages(content, renameMap, markdownPath);
  content = rewriteHeroImage(content, renameMap, markdownPath);
  content = await applyHeroFallback(content, postDir, movedTargets, markdownPath);

  if (content !== originalContent) {
    await fs.writeFile(markdownPath, content);
  }
}

if (!await exists(blogRoot)) {
  console.error(`Blog writeups directory not found: ${path.relative(process.cwd(), blogRoot)}`);
  process.exit(1);
}

const postIndexes = await findPostIndexes(blogRoot);

for (const postIndex of postIndexes) {
  await tidyPost(postIndex);
}

const uniqueRewrites = [...new Set(changes.rewrote)];

if (changes.moved.length === 0 && uniqueRewrites.length === 0 && changes.heroFallbacks.length === 0) {
  console.log("Blog assets already tidy.");
} else {
  for (const moved of changes.moved) {
    console.log(`Moved ${moved}`);
  }

  for (const rewrite of uniqueRewrites) {
    console.log(`Updated links in ${rewrite}`);
  }

  for (const fallback of changes.heroFallbacks) {
    console.log(`Updated missing heroImage in ${fallback}`);
  }
}
