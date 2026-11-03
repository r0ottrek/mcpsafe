// Turns findings into a 0-100 score and a letter grade.
import { SEVERITIES } from './rules.js';

export const WEIGHTS = { critical: 25, high: 12, medium: 4, low: 1.5, info: 0 };

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
  // Map the penalty onto 0-100 with a soft curve: small problems cost a few
  // points, and only a pile of serious ones approaches zero.
  const value = Math.round(100 * Math.exp(-penalty / 75));
  const grade = value >= 90 ? 'A' : value >= 80 ? 'B' : value >= 70 ? 'C' : value >= 60 ? 'D' : 'F';
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, findings.filter((f) => f.severity === s).length]));
  return { value, grade, counts };
}

export function sortFindings(findings) {
  return [...findings].sort((a, b) =>
    SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) || a.id.localeCompare(b.id) || String(a.server).localeCompare(String(b.server)));
}

// Points the score would gain if every finding of each rule were fixed.
export function impactByRule(findings) {
  const base = score(findings).value;
  const out = {};
  for (const id of new Set(findings.map((f) => f.id))) out[id] = score(findings.filter((f) => f.id !== id)).value - base;
  return out;
}
