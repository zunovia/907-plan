# TKCインポートCSV仕様書

## 概要
TKC FX4クラウドの標準仕訳CSVインポート形式。
全仕訳明細20252026.XLSXから逆解析した仕様。

## 入力フォーマット（29カラム）

| # | カラム名 | 型 | 必須 | 説明 |
|---|---------|---|------|------|
| 1 | 事業CD | 文字列 | ○ | 事業コード（90, 311-392） |
| 2 | 事業名 | 文字列 | | 事業名称（全角、末尾空白あり） |
| 3 | 年月日 | 数値 | ○ | YMMDD形式（Y=令和年） |
| 4 | 伝番 | 数値 | ○ | 伝票番号（月内連番） |
| 5 | 証番 | 文字列 | | 証憑番号 |
| 6 | 課 | 文字列 | | 課税区分（5=課税等） |
| 7 | 事 | 文字列 | | |
| 8 | 小切手NO | 文字列 | | |
| 9 | 借方CD | 文字列 | ○ | 勘定科目コード4桁 |
| 10 | (借方補助) | 文字列 | | 補助科目コード（10,21,22等） |
| 11 | 借方科目名 | 文字列 | | |
| 12 | 借方口座名 | 文字列 | | 補助科目名（総務, あつた等） |
| 13 | 貸方CD | 文字列 | ○ | 勘定科目コード4桁 |
| 14 | (貸方補助) | 文字列 | | 補助科目コード |
| 15 | 貸方科目名 | 文字列 | | |
| 16 | 貸方口座名 | 文字列 | | |
| 17 | 取引金額 | 数値 | ○ | 正の整数 |
| 18 | 税率 | 文字列 | | 0.1, 0.08, 空 |
| 19 | 内、消費税等 | 数値 | | 税込金額中の消費税額 |
| 20 | 税抜き金額 | 数値 | | |
| 21 | 取引先CD | 文字列 | | 取引先マスタのコード |
| 22 | 取引先名 | 文字列 | | |
| 23 | 実際の仕入れ年月日 | 文字列 | | |
| 24 | 元帳摘要 | 文字列 | ○ | 仕訳の説明文 |
| 25 | プロジェクトCD | 文字列 | | |
| 26 | プロジェクト名 | 文字列 | | |
| 27 | 軽減対象取引区分 | 文字列 | | |
| 28 | 控除割合 | 文字列 | | |
| 29 | 事業者登録番号 | 文字列 | | インボイスT番号 |

## 年月日変換

```python
def wareki_to_ymmdd(year: int, month: int, day: int) -> str:
    """西暦→TKC内部形式"""
    reiwa_year = year - 2018
    return f"{reiwa_year}{month:02d}{day:02d}"

def ymmdd_to_date(ymmdd: str) -> tuple:
    """TKC内部形式→(西暦年, 月, 日)"""
    if len(ymmdd) == 5:
        y, m, d = int(ymmdd[0]), int(ymmdd[1:3]), int(ymmdd[3:5])
    elif len(ymmdd) == 6:
        y, m, d = int(ymmdd[0:2]), int(ymmdd[2:4]), int(ymmdd[4:6])
    return (y + 2018, m, d)
```

## 消費税計算

```python
def calc_tax(amount: int, rate: float) -> tuple:
    """税込金額から消費税と税抜金額を計算"""
    if rate in (0.1, 0.08):
        tax = int(amount * rate / (1 + rate))
        net = amount - tax
        return tax, net
    return 0, amount
```

## 仕訳CSV生成テンプレート

```python
import pandas as pd

def create_journal_entry(
    jigyo_cd, jigyo_name, date_ymmdd, denno,
    dr_cd, dr_sub, dr_name, dr_koza,
    cr_cd, cr_sub, cr_name, cr_koza,
    amount, tax_rate='', tax_amount=0, net_amount=None,
    torihiki_cd='', torihiki_name='', tekiyo='',
    invoice_no=''
):
    if net_amount is None:
        net_amount = amount
    return {
        '事業CD': jigyo_cd,
        '事業名': jigyo_name,
        '年月日': date_ymmdd,
        '伝番': denno,
        '証番': '',
        '課': '5' if tax_rate else '',
        '事': '',
        '小切手NO': '',
        '借方CD': dr_cd,
        ' ': dr_sub,
        '借方科目名': dr_name,
        '借方口座名': dr_koza,
        '貸方CD': cr_cd,
        '  ': cr_sub,  # 貸方補助
        '貸方科目名': cr_name,
        '貸方口座名': cr_koza,
        '取引金額': amount,
        '税率': tax_rate,
        '内、消費税等': tax_amount,
        '税抜き金額': net_amount,
        '取引先CD': torihiki_cd,
        '取引先名': torihiki_name,
        '実際の仕入れ年月日': '',
        '元帳摘要': tekiyo,
        'プロジェクトCD': '',
        'プロジェクト名': '',
        '軽減対象取引区分': '',
        '控除割合': '',
        '事業者登録番号': invoice_no,
    }
```

## 科目残高ファイル構造（TKC切り出し）

4シート構成:
- **口取残高**: 口座別（補助科目別）の月次残高
- **科目並列**: 科目×月の一覧表
- **科目内訳**: 科目の内訳明細
- **科目残高**: 科目別月次残高

各シートの列構造:
- 科目CD（4桁）
- 補助CD / 取引先CD
- 頭文字
- 科目名
- 以降、月ごとに「借方・貸方・残高」の3列×37ヶ月分

期間: 令和5年3月 ～ 令和8年3月
