"""TKC仕訳CSV（cp932, 29列）→ JournalEntry リストへの変換."""

from __future__ import annotations

import csv
import warnings
from datetime import date
from pathlib import Path
from typing import Optional

from ..models import JournalEntry


def ymmdd_to_date(ymmdd: str) -> date:
    """TKC内部形式（YMMDD / YYMMDD）→ Python date.

    Y=令和年。5桁なら1桁年、6桁なら2桁年。
    例: '80331' → 2026-03-31, '70401' → 2025-04-01
    """
    ymmdd = ymmdd.strip()
    if len(ymmdd) == 5:
        y, m, d = int(ymmdd[0]), int(ymmdd[1:3]), int(ymmdd[3:5])
    elif len(ymmdd) == 6:
        y, m, d = int(ymmdd[0:2]), int(ymmdd[2:4]), int(ymmdd[4:6])
    else:
        raise ValueError(f"不正な年月日形式: '{ymmdd}'")
    western_year = y + 2018
    return date(western_year, m, d)


def _parse_tax_rate(value: str) -> Optional[float]:
    """税率文字列をfloatに変換。空や0はNone."""
    value = value.strip()
    if not value or value == "0":
        return None
    try:
        rate = float(value)
        return rate if rate > 0 else None
    except ValueError:
        return None


def _parse_int(value: str, default: int = 0) -> int:
    """整数パース。空やエラーはdefault."""
    value = value.strip()
    if not value:
        return default
    try:
        return int(float(value))
    except ValueError:
        return default


def read_tkc_csv(filepath: str | Path) -> list[JournalEntry]:
    """TKC仕訳CSVを読み込み、JournalEntryリストを返す.

    Args:
        filepath: TKC CSVファイルパス（cp932エンコーディング）

    Returns:
        パースされた仕訳エントリのリスト

    Raises:
        FileNotFoundError: ファイルが存在しない場合
    """
    filepath = Path(filepath)
    if not filepath.exists():
        raise FileNotFoundError(f"ファイルが見つかりません: {filepath}")

    entries: list[JournalEntry] = []

    with open(filepath, encoding="cp932", newline="") as f:
        reader = csv.reader(f)
        for line_no, row in enumerate(reader, start=1):
            # ヘッダー行やコメント行のスキップ
            if not row or row[0].startswith("#"):
                continue

            # 29列未満の行は警告してスキップ
            if len(row) < 29:
                warnings.warn(
                    f"行{line_no}: 列数不足({len(row)}列)。スキップします。",
                    stacklevel=2,
                )
                continue

            # 年月日が空または非数値ならヘッダー行とみなしてスキップ
            date_str = row[2].strip()
            if not date_str or not date_str.isdigit():
                continue

            try:
                txn_date = ymmdd_to_date(date_str)
            except (ValueError, IndexError) as e:
                warnings.warn(f"行{line_no}: 日付変換エラー({e})。スキップします。", stacklevel=2)
                continue

            tax_rate = _parse_tax_rate(row[17])

            entry = JournalEntry(
                transaction_date=txn_date,
                voucher_no=_parse_int(row[3]),
                description=row[23].strip(),
                # 借方
                debit_code=row[8].strip(),
                debit_name=row[10].strip(),
                debit_sub_code=row[9].strip(),
                debit_sub_name=row[11].strip(),
                # 貸方
                credit_code=row[12].strip(),
                credit_name=row[14].strip(),
                credit_sub_code=row[13].strip(),
                credit_sub_name=row[15].strip(),
                # 金額
                amount=_parse_int(row[16]),
                tax_rate=tax_rate,
                tax_amount=_parse_int(row[18]),
                net_amount=_parse_int(row[19]),
                # TKC固有
                business_code=row[0].strip(),
                business_name=row[1].strip(),
                department=row[5].strip(),
                evidence_no=row[4].strip(),
                # 取引先
                partner_code=row[20].strip(),
                partner_name=row[21].strip(),
                # インボイス
                invoice_no=row[28].strip(),
                reduced_tax_flag=row[26].strip(),
                deduction_ratio=row[27].strip(),
            )

            entries.append(entry)

    return entries
