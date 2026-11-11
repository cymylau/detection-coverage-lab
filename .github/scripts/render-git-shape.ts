// Render a git-shape log (git log --format='%H %ct %P%d') with pretty-git-tree,
// in the four styles its web page offers, using the page's own settings.
// The git-graphic workflow copies this into a pinned pretty-git-tree checkout
// (scripts/), because it imports that project's modules.
//
//   node scripts/render-git-shape.ts LOG OUT_DIR NAME
//   -> OUT_DIR/NAME-{arches,delta,particles,qubits}.{svg,png}
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { Resvg } from "@resvg/resvg-js";
import { parseCanvas, parseLog, sliceLog } from "../src/core/index.ts";
import { renderSvg } from "../src/web/render.ts";
import { DEFAULTS, LAYOUTS, type Settings } from "../src/web/settings.ts";

const [logPath, outDir, name] = process.argv.slice(2);
if (!logPath || !outDir || !name) throw new Error("usage: render-git-shape.ts LOG OUT_DIR NAME");

const graph = sliceLog(parseLog(readFileSync(logPath, "utf8")), { repoName: name });
const width = parseCanvas(DEFAULTS.format).width;
mkdirSync(outDir, { recursive: true });
for (const { id, label, ...layout } of LAYOUTS) {
  const settings: Settings = { ...DEFAULTS, ...layout };
  const svg = renderSvg(graph, settings);
  const base = join(outDir, `${name}-${id}`);
  writeFileSync(`${base}.svg`, svg);
  writeFileSync(`${base}.png`, new Resvg(svg, { fitTo: { mode: "width", value: width } }).render().asPng());
  console.log(`wrote ${base}.{svg,png} (${label})`);
}
