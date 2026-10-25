/**
 * Characters that can split a line or make displayed text differ from what is
 * copied: C0/C1 controls (incl. newline, tab and DEL), Unicode line/paragraph
 * separators, and bidirectional embeddings/overrides/isolates.
 */
const UNSAFE_CHARS = /[\p{Cc}\u2028\u2029\u202A-\u202E\u2066-\u2069]/u;

export const hasUnsafeChars = (value: string): boolean => UNSAFE_CHARS.test(value);
