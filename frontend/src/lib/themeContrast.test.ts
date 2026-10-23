import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

/**
 * The theme's own colour pairs, measured.
 *
 * Every text colour in the SPA comes from a pair of tokens in `index.css`, and
 * nothing in the suite could see them: a token set to a value that reads fine on
 * the designer's monitor and fails WCAG AA on a laptop in daylight looked exactly
 * like a passing build. This file computes the ratios from the stylesheet itself,
 * so the numbers are checked against the CSS rather than against a copy of it.
 *
 * Floors are WCAG 2.1: 4.5:1 for text (1.4.3) and 3:1 for the visual information
 * that identifies a control or a focus state (1.4.11). Both themes are measured,
 * because a pair that passes in one can fail in the other — the light accent failed
 * at 2.30:1 while the dark one passed at 8.1:1 as a ring.
 *
 * When a token changes, this file either still passes or names the pair and the
 * number that failed. It does not judge hues, only readability.
 */

// `import.meta.url` is not a file URL under the jsdom environment, and the test
// runner's working directory is the frontend package.
const css = readFileSync(resolve(process.cwd(), "src/index.css"), "utf8");

type Hsl = [number, number, number];
type Rgb = [number, number, number];

/** The `--token: h s% l%` declarations inside the block that starts at `selector`. */
function themeBlock(selector: string): Record<string, Hsl> {
  const start = css.indexOf(selector);
  if (start < 0) throw new Error(`${selector} is missing from index.css`);
  const open = css.indexOf("{", start);
  const close = css.indexOf("}", open);
  const body = css.slice(open + 1, close);
  const tokens: Record<string, Hsl> = {};
  for (const match of body.matchAll(/--([a-z-]+):\s*([\d.]+)\s+([\d.]+)%\s+([\d.]+)%\s*;/g)) {
    tokens[match[1]] = [Number(match[2]), Number(match[3]), Number(match[4])];
  }
  return tokens;
}

function toRgb([hue, saturation, lightness]: Hsl): Rgb {
  const s = saturation / 100;
  const l = lightness / 100;
  const c = (1 - Math.abs(2 * l - 1)) * s;
  const segment = hue / 60;
  const x = c * (1 - Math.abs((segment % 2) - 1));
  const [r, g, b] =
    segment < 1 ? [c, x, 0]
    : segment < 2 ? [x, c, 0]
    : segment < 3 ? [0, c, x]
    : segment < 4 ? [0, x, c]
    : segment < 5 ? [x, 0, c]
    : [c, 0, x];
  const m = l - c / 2;
  return [r + m, g + m, b + m];
}

function luminance(rgb: Rgb): number {
  const [r, g, b] = rgb.map((channel) =>
    channel <= 0.03928 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4,
  );
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function ratio(a: Rgb, b: Rgb): number {
  const la = luminance(a);
  const lb = luminance(b);
  const [high, low] = la > lb ? [la, lb] : [lb, la];
  return (high + 0.05) / (low + 0.05);
}

/** `foreground` painted at `alpha` over `under`, which is what `/15` and friends do. */
function over(foreground: Hsl, alpha: number, under: Hsl): Rgb {
  const [r1, g1, b1] = toRgb(foreground);
  const [r2, g2, b2] = toRgb(under);
  return [r1 * alpha + r2 * (1 - alpha), g1 * alpha + g2 * (1 - alpha), b1 * alpha + b2 * (1 - alpha)];
}

const themes: Record<"light" | "dark", Record<string, Hsl>> = {
  light: themeBlock(":root {"),
  dark: themeBlock(".dark {"),
};

function token(theme: Record<string, Hsl>, name: string, scheme: string): Hsl {
  const value = theme[name];
  if (!value) throw new Error(`--${name} is missing from the ${scheme} theme`);
  return value;
}

/** Text painted on a filled control, in both its resting and hovered states. */
const TEXT_PAIRS: [string, string][] = [
  ["primary-foreground", "primary"],
  ["primary-foreground", "primary-hover"],
  ["destructive-foreground", "destructive"],
  ["destructive-foreground", "destructive-hover"],
  ["secondary-foreground", "secondary"],
  ["accent-foreground", "accent"],
  ["sidebar-primary-foreground", "sidebar-primary"],
  ["foreground", "background"],
  ["foreground", "card"],
  ["muted-foreground", "background"],
  ["muted-foreground", "card"],
  ["sidebar-foreground", "sidebar-background"],
];

/** Controls and focus indicators: 3:1 is the bar (1.4.11). */
const UI_PAIRS: [string, string][] = [
  ["ring", "background"],
  ["sidebar-ring", "sidebar-background"],
  ["primary", "background"],
  ["destructive", "background"],
];

describe.each(["light", "dark"] as const)("the %s theme", (scheme) => {
  const theme = themes[scheme];

  it.each(TEXT_PAIRS)("keeps %s readable on %s", (foreground, background) => {
    expect(ratio(toRgb(token(theme, foreground, scheme)), toRgb(token(theme, background, scheme)))).toBeGreaterThanOrEqual(4.5);
  });

  it.each(UI_PAIRS)("keeps %s distinguishable from %s", (foreground, background) => {
    expect(ratio(toRgb(token(theme, foreground, scheme)), toRgb(token(theme, background, scheme)))).toBeGreaterThanOrEqual(3);
  });

  it("darkens the hover fill rather than blending it toward the page", () => {
    // `hover:bg-primary/90` lightens the fill and drops white to 3.8:1. The
    // invariant that keeps a future edit honest is the direction, not the value.
    for (const [hover, resting] of [["primary-hover", "primary"], ["destructive-hover", "destructive"]] as const) {
      expect(luminance(toRgb(token(theme, hover, scheme)))).toBeLessThan(
        luminance(toRgb(token(theme, resting, scheme))),
      );
    }
  });

  it("keeps the initials readable on the accent tint they sit on", () => {
    // `AvatarFallback` is `bg-primary/15 text-foreground`: the tint keeps the
    // accent pale, so accent-coloured text on it measured 3.7:1 and the ink is
    // what the component uses instead.
    const tint = over(token(theme, "primary", scheme), 0.15, token(theme, "card", scheme));
    expect(ratio(toRgb(token(theme, "foreground", scheme)), tint)).toBeGreaterThanOrEqual(4.5);
  });
});
