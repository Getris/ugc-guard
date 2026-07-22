export interface NormalizeOptions {
  unicode: boolean;
  trim: boolean;
  collapseWhitespace: boolean;
}

export function normalizeText(text: string, options: NormalizeOptions): string {
  let value = options.unicode ? text.normalize("NFKC") : text;
  if (options.collapseWhitespace) value = value.replace(/\s+/gu, " ");
  if (options.trim) value = value.trim();
  return value;
}
