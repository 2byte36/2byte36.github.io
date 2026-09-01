import type { CollectionEntry } from "astro:content";

type BlogPost = CollectionEntry<"blog">;

export type BlogImage = string | {
  src: string;
};

export function getBlogSlug(post: BlogPost) {
  const normalizedId = post.id.replace(/\\/g, "/").replace(/\/index$/, "");
  const segments = normalizedId.split("/").filter(Boolean);

  return segments.at(-1) ?? normalizedId;
}

export function getBlogImageSrc(image: BlogImage | undefined) {
  return typeof image === "string" ? image : image?.src;
}
