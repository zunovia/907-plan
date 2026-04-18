---
name: svg-infographic
description: "SVG/HTMLベースのインフォグラフィックを生成するスキル。外部API不要でプロ品質のビジュアルサマリーを作成。20種のレイアウトと12種のスタイルを組み合わせ可能。'インフォグラフィック', 'infographic', 'ビジュアルサマリー', 'visual summary', '図解まとめ', '情報デザイン', 'information design', '1枚にまとめて', 'one-page summary' などのキーワードでトリガー。"
---

# SVG インフォグラフィック生成スキル

外部APIなしで、SVG/HTMLベースのプロ品質インフォグラフィックを生成する。baoyu-infographicの「レイアウト×スタイル」マトリックス設計を参考に、コードベースで完全に再現。

## 設計思想: レイアウト × スタイル マトリックス

インフォグラフィックは**2つの次元**で定義される：

- **レイアウト** = 情報の構造（どう並べるか）
- **スタイル** = 視覚の美学（どう見せるか）

任意の組み合わせが可能。ユーザーが指定しない場合はコンテンツ分析から自動推薦する。

---

## レイアウト一覧（16種）

### フロー・プロセス系
| レイアウト | 用途 | 構造 |
|---|---|---|
| **timeline** | 時系列の変遷 | 縦または横の時間軸 + イベントノード |
| **flowchart** | プロセス・手順 | ステップ間を矢印で接続 |
| **roadmap** | 計画・ロードマップ | 曲線パスに沿ったマイルストーン |
| **cycle** | 循環プロセス | 円形に配置されたステップ |

### 比較・分類系
| レイアウト | 用途 | 構造 |
|---|---|---|
| **comparison** | 2つの対比 | 左右2カラムで対照表示 |
| **matrix** | 2軸分類 | 4象限マトリックス |
| **ranking** | 順位・ランキング | 縦並びのバー + ラベル |
| **category** | カテゴリ分類 | 色分けされたグループ |

### 階層・構造系
| レイアウト | 用途 | 構造 |
|---|---|---|
| **pyramid** | 階層構造 | 上から下へ広がるピラミッド |
| **tree** | 組織・系統 | ルートから分岐するツリー |
| **funnel** | 絞り込みプロセス | 上から下へ狭まるファネル |
| **nested** | 包含関係 | 入れ子の円や四角形 |

### データ・統計系
| レイアウト | 用途 | 構造 |
|---|---|---|
| **stats-grid** | KPI・数値ハイライト | 大きな数値 + 小さなラベルのグリッド |
| **bar-chart** | 量の比較 | 横/縦の棒グラフ |
| **pie-breakdown** | 割合・内訳 | 円グラフ + 凡例 |
| **icon-array** | 割合の視覚化 | アイコンの配列（100個中N個が色付き） |

---

## スタイル一覧（12種）

| スタイル | 雰囲気 | 色彩 | タイポグラフィ | 装飾 |
|---|---|---|---|---|
| **corporate** | プロフェッショナル | ネイビー + グレー + アクセント | Noto Sans JP | 直線的、クリーン |
| **minimal** | ミニマル | モノクロ + 1色アクセント | 細めサンセリフ | 余白重視、線画 |
| **sketch-note** | 手描き風 | 黒 + マーカー2色 | 手書きフォント | 揺らぎのある線 |
| **warm** | 温かみ | アースカラー | 丸ゴシック | 角丸、ソフト |
| **bold** | インパクト | 高コントラスト | 太字ゴシック | 大きな数値、太い線 |
| **notion** | Notion風 | 白背景 + パステル | システムフォント | アイコン + カード |
| **blueprint** | 設計図風 | 青背景 + 白線 | モノスペース | グリッド、テクニカル |
| **retro** | レトロ | アンバー + クリーム | セリフ体 | テクスチャ、枠線 |
| **watercolor** | 水彩風 | パステル半透明 | 細セリフ | にじみ効果 |
| **dark** | ダーク | 暗い背景 + ネオン | サンセリフ | グロー効果 |
| **pop** | ポップ | ビビッド多色 | 丸ゴシック | ドット、ジグザグ |
| **craft-handmade** | クラフト紙風 | ブラウン系 | 手書き風 | テープ、スタンプ |

---

## SVG実装パターン

### 共通ヘッダー
```html
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 800 1200">
  <defs>
    <!-- グラデーション、パターン、フィルター -->
    <filter id="sketch">
      <feTurbulence type="turbulence" baseFrequency="0.05" numOctaves="2" result="noise"/>
      <feDisplacementMap in="SourceGraphic" in2="noise" scale="1.5"/>
    </filter>
  </defs>
  <!-- 背景 -->
  <rect width="800" height="1200" fill="#FAFAFA"/>
  <!-- コンテンツ -->
</svg>
```

### アスペクト比プリセット
| 名前 | 比率 | viewBox | 用途 |
|---|---|---|---|
| **portrait** | 9:16 | 0 0 720 1280 | SNS投稿、縦スクロール |
| **landscape** | 16:9 | 0 0 1280 720 | プレゼンスライド埋込 |
| **square** | 1:1 | 0 0 800 800 | SNS投稿 |
| **A4-portrait** | A4 | 0 0 794 1123 | 印刷、レポート |
| **poster** | 2:3 | 0 0 800 1200 | ポスター |

### セクションカード（再利用可能コンポーネント）
```xml
<!-- カード: タイトル + 本文 -->
<g transform="translate(40, 100)">
  <rect x="0" y="0" width="320" height="180" rx="12" 
        fill="white" stroke="#E2E8F0" stroke-width="1"/>
  <rect x="0" y="0" width="320" height="4" rx="2" fill="#6366F1"/>
  <text x="20" y="36" font-size="16" font-weight="bold" fill="#1E293B">
    セクションタイトル
  </text>
  <text x="20" y="60" font-size="13" fill="#64748B">
    <tspan x="20" dy="0">説明テキスト1行目</tspan>
    <tspan x="20" dy="20">説明テキスト2行目</tspan>
  </text>
</g>
```

### 数値ハイライト
```xml
<g transform="translate(50, 200)">
  <text x="0" y="0" font-size="56" font-weight="900" fill="#6366F1">85%</text>
  <text x="0" y="24" font-size="14" fill="#94A3B8">顧客満足度</text>
  <text x="0" y="42" font-size="11" fill="#CBD5E1">前年比 +12pt</text>
</g>
```

### アイコンセット（SVGパス）
すべてのアイコンは12×12 viewBox基準のSVGパスで定義。スケーリング自由。

頻出アイコン: 
- ↑ 上昇 / ↓ 下降 / → 右矢印
- ● ドット / ★ 星 / ✓ チェック
- 👤 人物 / 💡 電球 / ⚙ 歯車 / 📊 グラフ / 🎯 ターゲット

---

## ワークフロー

### Step 1: コンテンツ分析
入力データから以下を抽出：
- **数値データ**があるか → stats-grid, bar-chart, pie-breakdown
- **時系列**があるか → timeline, roadmap
- **プロセス/手順**があるか → flowchart, funnel, cycle
- **比較/対比**があるか → comparison, matrix, ranking
- **分類/グループ**があるか → category, tree, pyramid

### Step 2: レイアウト×スタイル推薦
コンテンツの性質に基づいて最適な組み合わせを提案：

| コンテンツの性質 | 推薦レイアウト | 推薦スタイル |
|---|---|---|
| ビジネスレポート | stats-grid, funnel | corporate, minimal |
| プロジェクト計画 | roadmap, timeline | notion, blueprint |
| 商品比較 | comparison, ranking | bold, pop |
| 学習まとめ | category, pyramid | sketch-note, warm |
| SNS投稿 | stats-grid, comparison | pop, craft-handmade |
| 技術解説 | flowchart, tree | blueprint, minimal |

### Step 3: SVG生成
1. アスペクト比を決定
2. 背景・ヘッダー・フッターを配置
3. レイアウトに従ってコンテンツ要素を配置
4. スタイルに従って色・フォント・装飾を適用
5. レスポンシブ対応（viewBoxベース）

### Step 4: 出力
- **HTMLファイル**（`<svg>` 埋め込み）→ `/mnt/user-data/outputs/infographic.html`
- **SVGファイル** → `/mnt/user-data/outputs/infographic.svg`
- スライドへの組み込みが必要な場合はPNG変換も可能

---

## コンテンツ密度ガイドライン

| 密度レベル | 要素数 | 用途 |
|---|---|---|
| **minimal** | 3-5要素 | ヒーローイメージ、SNS |
| **balanced** | 6-10要素 | スライド挿入、サマリー |
| **rich** | 11-20要素 | 1枚まとめ、レポート |
| **dense** | 20+要素 | ポスター、詳細インフォグラフィック |

---

## 品質チェックリスト

生成後に以下を確認：
- [ ] テキストの重なりがないか
- [ ] フォントサイズが最小11px以上か
- [ ] 色のコントラスト比が4.5:1以上か（アクセシビリティ）
- [ ] 要素間のスペースが最低8px以上か
- [ ] SVGがブラウザで正しくレンダリングされるか
- [ ] viewBoxとアスペクト比が意図通りか
- [ ] 日本語テキストが文字化けしていないか

## 他スキルとの連携

- **graphic-recording-svg** → 手描き風スタイル（sketch-note）はこのスキルを呼び出す
- **html-presentation** → スライド内にインフォグラフィックを埋め込み
- **pptx** → SVGをPNG化してスライドに挿入
- **canvas-design** → より抽象的・芸術的なアプローチが必要な場合
