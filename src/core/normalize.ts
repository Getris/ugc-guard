import type { NormalizationChange } from "./types.js";

export interface NormalizeOptions {
  unicode: boolean;
  trim: boolean;
  collapseWhitespace: boolean;
  lineEndings: boolean;
}

export interface NormalizeResult {
  text: string;
  changes: NormalizationChange[];
}

export function normalizeText(text: string, options: NormalizeOptions): NormalizeResult {
  let value = text;
  const changes: NormalizationChange[] = [];

  if (options.lineEndings) {
    const normalized = value.replace(/\r\n?/gu, "\n");
    if (normalized !== value) {
      changes.push({ type: "line-endings", description: "Line endings were normalized to LF." });
      value = normalized;
    }
  }

  if (options.unicode) {
    const normalized = value.normalize("NFKC");
    if (normalized !== value) {
      changes.push({ type: "unicode", description: "Unicode compatibility characters were normalized with NFKC." });
      value = normalized;
    }
  }

  if (options.collapseWhitespace) {
    const normalized = value.replace(/[\p{Z}\t\f\v]+/gu, " ");
    if (normalized !== value) {
      changes.push({ type: "whitespace", description: "Repeated horizontal whitespace was collapsed." });
      value = normalized;
    }
  }

  if (options.trim) {
    const normalized = value.trim();
    if (normalized !== value) {
      changes.push({ type: "trim", description: "Leading or trailing whitespace was removed." });
      value = normalized;
    }
  }

  return { text: value, changes };
}
