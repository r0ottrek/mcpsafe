// Turns findings into a 0-100 score and a letter grade.
import { SEVERITIES } from './rules.js';

export const WEIGHTS = { critical: 25, high: 12, medium: 5, low: 2, info: 0 };

export function score(findings) {
  // Repeats of the same rule count less each time, so one noisy rule
  // cannot sink the score on its own: full, half, quarter, then ignored.
  const seen = {};
  let penalty = 0;
  for (const f of [...findings].sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity))) {
    const n = (seen[f.id] = (seen[f.id] || 0) + 1);
    if (n > 3) continue;
    penalty += WEIGHTS[f.severity] / 2 ** (n - 1);
  }
  const value = Math.max(0, Math.round(100 - penalty));
  const grade = value >= 90 ? 'A' : value >= 80 ? 'B' : value >= 70 ? 'C' : value >= 60 ? 'D' : 'F';
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, findings.filter((f) => f.severity === s).length]));
  return { value, grade, counts };
}

export function sortFindings(findings) {
  return [...findings].sort((a, b) =>
    SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) || a.id.localeCompare(b.id) || String(a.server).localeCompare(String(b.server)));
}
