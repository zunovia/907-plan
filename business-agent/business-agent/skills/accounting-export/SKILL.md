---
name: accounting-export
description: "TKC仕訳CSVを freee会計・マネーフォワードクラウド・弥生会計 のインポートCSV形式に変換するスキル。「freee」「マネーフォワード」「弥生」「エクスポート」「変換」「会計ソフト」等のキーワードが出たら必ずこのスキルを使用すること。"
---

# マルチ会計ソフト対応エクスポート

## 概要

TKC FX4クラウドの仕訳CSV（cp932, 29列）を、以下の3つの会計ソフトのインポートCSV形式に変換する。

| プラットフォーム | エンコーディング | ヘッダー | 列数 |
|---|---|---|---|
| freee会計 | UTF-8 BOM | あり | 18列 |
| マネーフォワード | UTF-8 | あり | 23列 |
| 弥生会計 | cp932 | なし | 25列 |

## アーキテクチャ

```
TKC CSV (cp932, 29列)
    ↓
  tkc_reader.py  →  List[JournalEntry]  ←  account_mapper.py
    ↓                                         (JSON設定ファイル)
  ┌─────────────┬──────────────────┬────────────────┐
  FreeeAdapter  MoneyForwardAdapter  YayoiAdapter
  └─────────────┴──────────────────┴────────────────┘
```

## 処理フロー

### Step 1: 入力ファイルの確認
```python
from skills.accounting_export.src.reader.tkc_reader import read_tkc_csv

entries = read_tkc_csv("input.csv")
print(f"読み込み: {len(entries)}件")
```

### Step 2: プラットフォーム選択と変換
```python
from skills.accounting_export.src.exporter import export_from_tkc

# freee会計に変換
export_from_tkc("input.csv", "freee", "output_freee.csv")

# マネーフォワードに変換
export_from_tkc("input.csv", "moneyforward", "output_mf.csv")

# 弥生会計に変換
export_from_tkc("input.csv", "yayoi", "output_yayoi.csv")
```

### Step 3: カスタム科目マッピング（必要な場合）
```python
# NPO固有の科目マッピングを使用
export_from_tkc("input.csv", "freee", "output.csv", config_path="custom_map.json")
```

### Step 4: 出力検証
- 列数チェック（freee=18, MF=23, 弥生=25）
- エンコーディング確認（BOM有無含む）
- 貸借一致の確認
- 行数が入力と一致することを確認

## CLI使用法

```bash
python -m skills.accounting_export.src.exporter input.csv --platform freee
python -m skills.accounting_export.src.exporter input.csv --platform moneyforward -o output.csv
python -m skills.accounting_export.src.exporter input.csv --platform yayoi --config custom_map.json
```

## 科目マッピング設定

`config/account_map_default.json` にデフォルトマッピングあり。
NPO固有のマッピングは `config/account_map_template.json` をコピーして編集。

マッピングに該当しない科目はTKCの科目名をそのまま使用（フォールバック）。

## テスト実行

```bash
# ユニットテスト
python tests/test_models.py
python tests/test_tax_codes.py
python tests/test_adapters.py

# E2E検証
python tests/verify_output.py
```

## 制約事項（Phase 2で対応予定）
- 複合仕訳の分割は未対応（現状は単一行仕訳のみ）
- freee API直接連携は未対応（CSV経由のみ）
- 5,000行制限のチェックは未実装

## ファイル構成
```
accounting-export/
├── SKILL.md                    ← このファイル
├── src/
│   ├── models.py               ← JournalEntry dataclass
│   ├── tax_codes.py            ← 税区分マッピング
│   ├── account_mapper.py       ← 科目名マッピング
│   ├── exporter.py             ← メインオーケストレータ + CLI
│   ├── reader/
│   │   └── tkc_reader.py       ← TKC CSV → JournalEntry
│   └── adapters/
│       ├── base.py             ← AbstractExportAdapter
│       ├── freee.py            ← freee会計アダプタ
│       ├── moneyforward.py     ← MFクラウドアダプタ
│       └── yayoi.py            ← 弥生会計アダプタ
├── config/
│   ├── account_map_default.json   ← デフォルト科目マッピング
│   └── account_map_template.json  ← NPO固有カスタマイズ用
└── tests/
    ├── sample_tkc.csv          ← テストフィクスチャ（5行）
    ├── test_models.py
    ├── test_tax_codes.py
    ├── test_adapters.py
    └── verify_output.py        ← E2E検証スクリプト
```
