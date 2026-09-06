// Workerのソース（唯一の正）から tool.html を取り出して dist/ を作る。
// Web版とデスクトップ版で画面を二重管理しないための仕組み。
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");
const workerEntry = path.resolve(root, "../../workers/keiri-kaizen-mainpage/src/index.js");
const distDir = path.join(root, "dist");

// デスクトップ版はWorkerと同一オリジンではないため、APIは絶対URLで呼ぶ
const API_ORIGIN = process.env.TKC_API_ORIGIN || "https://tkc.surc.online";

if (!fs.existsSync(workerEntry)) {
  console.error("Worker のソースが見つかりません:", workerEntry);
  process.exit(1);
}

const mod = await import(new URL("file://" + workerEntry.replace(/\\/g, "/")));
const res = await mod.default.fetch(new Request("https://tkc.surc.online/tool.html"), {});
let html = await res.text();

if (!html.includes("AI 仕訳インポートツール")) {
  console.error("tool.html の取得に失敗しました（内容が想定と異なります）");
  process.exit(1);
}

// 1) 相対パスのAPI呼び出しを絶対URLへ
const before = html;
html = html.replaceAll("fetch('/api/", `fetch('${API_ORIGIN}/api/`);
html = html.replaceAll('fetch("/api/', `fetch("${API_ORIGIN}/api/`);
if (html === before) {
  console.warn("警告: API呼び出しの書き換え対象が見つかりませんでした（仕様変更の可能性）");
}

// 2) バージョン表示を差し込む（どの版で作った仕訳かを後から特定できるように）
const conf = JSON.parse(fs.readFileSync(path.join(root, "src-tauri", "tauri.conf.json"), "utf8"));
const badge = `
<div id="app-version" style="position:fixed;right:8px;bottom:6px;z-index:9999;font-size:10px;color:#999;font-family:monospace;background:rgba(255,255,255,.85);padding:2px 7px;border-radius:10px;border:.5px solid #e5e2dc">
デスクトップ版 v${conf.version}
</div>
</body>`;
html = html.replace("</body>", badge);

fs.rmSync(distDir, { recursive: true, force: true });
fs.mkdirSync(distDir, { recursive: true });
fs.writeFileSync(path.join(distDir, "index.html"), html, "utf8");

console.log(`dist/index.html を生成しました (${html.length} 文字, API=${API_ORIGIN}, version=${conf.version})`);
