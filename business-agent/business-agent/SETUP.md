# ビジネスエージェント セットアップガイド

## クイックスタート（3分で完了）

### 方法A: Cursor で使う場合

```bash
# 1. ZIPを展開して好きな場所に配置
unzip business-agent.zip
cd business-agent

# 2. Cursorでフォルダを開く
cursor .

# 3. 作業データを data/ に配置
cp ~/Downloads/全仕訳明細20252026.XLSX data/
cp ~/Downloads/給与ﾃﾞｰﾀ*.CSV data/
```

Cursorが `.cursorrules` を自動的に読み込み、エージェントとして機能します。

### 方法B: Claude Code（ターミナル）で使う場合

```bash
# 1. ZIPを展開
unzip business-agent.zip
cd business-agent

# 2. Claude Codeを起動（CLAUDE.mdを自動認識）
claude

# 3. そのまま会話開始
> 令和8年3月の給与仕訳を生成して
```

### 方法C: VS Code + Claude Code拡張で使う場合

```bash
# 1. ZIPを展開してVS Codeで開く
unzip business-agent.zip
code business-agent

# 2. Claude Code拡張が CLAUDE.md を自動認識
# 3. サイドパネルから会話開始
```

---

## フォルダ構成の意味

```
business-agent/
├── CLAUDE.md          ← Claude Codeが自動で読む設定ファイル
│                         （エージェントの人格・知識・行動指針）
│
├── .cursorrules       ← Cursorが自動で読む設定ファイル
│                         （CLAUDE.mdと同内容）
│
├── context/           ← エージェントの専門知識
│   ├── tkc-import-spec.md      TKCインポートCSV仕様（29カラム）
│   ├── organization-info.md    組織・拠点・人事の概要
│   └── monthly-workflow.md     月次ワークフロー手順書
│
├── skills/            ← 実行可能なスキル集
│   ├── recycler-activity-record/  手書きPDF→Excel自動記入
│   ├── svg-infographic/           インフォグラフィック生成
│   ├── graphic-recording-svg/     グラレコ風イラスト
│   ├── html-presentation/         Webスライド作成
│   └── markdown-to-pptx/          MD→PowerPoint変換
│
└── data/              ← 作業データ配置場所
    └── README.md         必要なファイル一覧
```

---

## 使い方の例

### TKC仕訳生成
```
> data/ に給与CSVを置いたので、令和8年3月の給与仕訳CSVを生成して
```

### リサイクラー活動記録
```
> data/ にステーションと事業所のPDFを置いた。2月分のリサイクラー参加表を作って
```

### 月次レポート
```
> 科目残高ファイルから今月の試算表を作って、前月と比較して
```

### ビジュアライゼーション
```
> 今期の売上推移をインフォグラフィックにまとめて
```

---

## カスタマイズ

### スキルを追加する
`skills/` に新しいフォルダを作り、`SKILL.md` を配置するだけ：

```bash
mkdir skills/my-new-skill
# SKILL.mdを作成（フォーマットは既存スキルを参考に）
```

### コンテキストを追加する
`context/` にMarkdownファイルを追加：

```bash
# 例：銀行口座の詳細情報を追加
echo "# 銀行口座一覧\n..." > context/bank-accounts.md
```

### CLAUDE.mdを編集する
新しい業務知識やルールが増えたら、CLAUDE.mdに追記してください。
エージェントの「脳」にあたるファイルなので、
ここに書いたことはすべてエージェントが理解します。

---

## 注意事項

- `data/` 配下のファイルはGit管理しないことを推奨（機密データ）
- `.gitignore` に `data/` を追加してください
- CLAUDE.md と .cursorrules は同期を保ってください
