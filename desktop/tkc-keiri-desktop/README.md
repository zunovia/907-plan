# TKC AI 仕訳インポートツール — デスクトップ版（Windows / macOS）

Web版（https://tkc.surc.online/tool.html）と**同じ画面**を、Windows と macOS に
インストールして使えるようにしたもの。Tauri v2 製。**自動更新に対応**。

## 設計上の約束ごと

1. **画面はWeb版と二重管理しない**
   `scripts/build-web.mjs` が Cloudflare Worker のソース
   （`../../workers/keiri-kaizen-mainpage/src/index.js`）から `tool.html` を取り出して `dist/index.html` を作る。
   Web版を直せばデスクトップ版も同じ内容になる。
2. **更新は黙って適用しない**
   起動時に新バージョンを確認し、**変更点を見せて同意を得てから**適用する（`src-tauri/src/lib.rs`）。
   月次の締め作業中に挙動が変わる事故を防ぐため。「あとで」を選べば何も起きない。
3. **どの版で作った仕訳かを特定できるようにする**
   画面右下に `デスクトップ版 vX.Y.Z` を常時表示する（`build-web.mjs` が差し込む）。
4. **AI読取のAPIは Worker 経由のまま**
   デスクトップ版では `https://tkc.surc.online/api/cc-read` を呼ぶ（同エンドポイントはCORS許可済み）。
   APIキーの持ち方をOSの資格情報ストアへ移す場合は、この経路を差し替える。

## 開発

```bash
npm install
npm run dev        # 画面を生成してアプリを起動（ホットリロードなし・都度 build:web）
npm run build      # インストーラを作る
```

`npm run build` のとき、更新用の署名鍵を環境変数で渡す:

```bash
# PowerShell
$env:TAURI_SIGNING_PRIVATE_KEY = Get-Content keys\updater.key -Raw
$env:TAURI_SIGNING_PRIVATE_KEY_PASSWORD = ""
npm run build
```

成果物:
- Windows: `src-tauri/target/release/bundle/msi/*.msi` と `bundle/nsis/*-setup.exe`（+ `.sig`）
- macOS: `bundle/dmg/*.dmg` と `bundle/macos/*.app`（+ `.sig`）※macOS上でビルドした場合

## リリース手順（自動更新を配る）

1. `src-tauri/tauri.conf.json` の `version` を上げる（例 `0.1.0` → `0.1.1`）
2. `git tag desktop-v0.1.1 && git push origin desktop-v0.1.1`
   （ワークフローはリポジトリ直下 `.github/workflows/release-desktop.yml`）
3. GitHub Actions が macOS（Apple Silicon＋Intel）と Windows をビルドし、
   **下書きのRelease**に `.msi` `.dmg` `latest.json` などを添付する
4. Release の本文に変更点を書いて公開する
   → その本文が、利用者の更新ダイアログにそのまま表示される
5. 利用者が次にアプリを起動したとき、更新の案内が出る

### 事前に必要な設定

| 場所 | 名前 | 中身 |
|---|---|---|
| GitHub Secrets | `TAURI_SIGNING_PRIVATE_KEY` | `keys/updater.key` の中身をそのまま |
| GitHub Secrets | `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` | 空（鍵にパスワードを付けていないため） |
| `src-tauri/tauri.conf.json` | `plugins.updater.endpoints` | 設定済み: `https://github.com/zunovia/keiri-dx-workers/releases/latest/download/latest.json` |

> **`keys/updater.key` を失うと、既存の利用者に更新を配れなくなります**（鍵が変わると署名検証に失敗するため、
> 全員に手動で入れ直してもらうしかない）。`.gitignore` 済みなので、別途バックアップを取ること。
> 公開鍵は `keys/updater.key.pub`（= `tauri.conf.json` の `pubkey`）。

## コード署名（未対応・βは未署名）

現状は**未署名**。配布時には次が必要:

- **macOS**: Developer ID 署名 ＋ 公証（notarization）。無いと Gatekeeper が起動を止める。
  macOS Sequoia 以降は Control-クリックでの回避もできない。Apple Developer Program 年99 USD。
  → workflow の `APPLE_*` を有効化すれば tauri-action が署名・公証まで行う。
- **Windows**: 未署名でも起動するが SmartScreen の警告が出る。
  Azure Artifact Signing（月$9.99）が最も安く、署名直後から警告が出ない。

βの間の回避策:
- Windows: 「詳細情報」→「実行」で起動できる
- macOS: 初回のみ「システム設定 > プライバシーとセキュリティ」から手動で許可が必要

## リポジトリ構成

Worker と同じリポジトリ `zunovia/keiri-dx-workers` に同居している。
`scripts/build-web.mjs` が `../../workers/keiri-kaizen-mainpage/src/index.js` を読むため、
この配置のまま CI でも画面を生成できる（`dist/` は生成物なのでコミットしない）。
