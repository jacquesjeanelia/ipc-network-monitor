const UNITS = ["B", "KB", "MB", "GB", "TB"];

export function fmtBytes(n: number): string {
  if (!Number.isFinite(n) || n < 0) return "—";
  let v = n;
  let i = 0;
  while (v >= 1024 && i < UNITS.length - 1) {
    v /= 1024;
    i++;
  }
  const d = i === 0 ? 0 : i === 1 ? 1 : 2;
  return `${v.toFixed(d)} ${UNITS[i]}`;
}

export function fmtRateBs(n: number): string {
  if (!Number.isFinite(n) || n < 0) return "—";
  return `${fmtBytes(n)}/s`;
}
