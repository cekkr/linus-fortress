import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const cssPath = path.resolve(__dirname, "../public/css/app.css");

function keyframeBlock(css, name) {
  const marker = `@keyframes ${name}`;
  const markerIndex = css.indexOf(marker);
  assert.notEqual(markerIndex, -1, `Missing keyframes block for ${name}`);
  const openIndex = css.indexOf("{", markerIndex);
  assert.notEqual(openIndex, -1, `Malformed keyframes block for ${name}`);
  let depth = 0;
  for (let i = openIndex; i < css.length; i += 1) {
    if (css[i] === "{") {
      depth += 1;
    } else if (css[i] === "}") {
      depth -= 1;
      if (depth === 0) {
        return css.slice(openIndex + 1, i);
      }
    }
  }
  throw new Error(`Unterminated keyframes block for ${name}`);
}

test("wizard track keyframes do not animate transform", () => {
  const css = fs.readFileSync(cssPath, "utf8");
  const forward = keyframeBlock(css, "wizardSlideForward");
  const back = keyframeBlock(css, "wizardSlideBack");

  assert.equal(/transform\s*:/i.test(forward), false, "wizardSlideForward must not animate transform");
  assert.equal(/transform\s*:/i.test(back), false, "wizardSlideBack must not animate transform");
});
