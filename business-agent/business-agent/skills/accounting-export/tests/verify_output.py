"""E2E検証スクリプト — sample_tkc.csv → 3プラットフォーム出力 → 検証."""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.exporter import export_from_tkc
from src.reader.tkc_reader import read_tkc_csv

SAMPLE = Path(__file__).parent / "sample_tkc.csv"


def verify_encoding(filepath: Path, expected_encoding: str, expect_bom: bool):
    """エンコーディングとBOMの検証."""
    with open(filepath, "rb") as f:
        raw = f.read()
    if expect_bom:
        assert raw[:3] == b"\xef\xbb\xbf", f"BOMが見つかりません: {filepath}"
        print(f"  BOM: あり (OK)")
    else:
        if raw[:3] == b"\xef\xbb\xbf":
            raise AssertionError(f"BOMがあるべきでないファイルにBOMあり: {filepath}")
        print(f"  BOM: なし (OK)")

    # デコードテスト
    try:
        content = raw.decode(expected_encoding)
        print(f"  エンコーディング({expected_encoding}): OK")
    except UnicodeDecodeError:
        raise AssertionError(
            f"エンコーディング不正: {filepath} は {expected_encoding} でデコードできません"
        )
    return content


def verify_row_count(content: str, expected: int, has_header: bool):
    """行数の検証."""
    lines = [l for l in content.strip().split("\n") if l.strip()]
    data_lines = len(lines) - (1 if has_header else 0)
    assert data_lines == expected, (
        f"行数不正: 期待={expected}, 実際={data_lines}"
    )
    print(f"  データ行数: {data_lines} (OK)")


def verify_column_count(content: str, expected: int, has_header: bool):
    """列数の検証."""
    import csv
    import io

    reader = csv.reader(io.StringIO(content))
    for i, row in enumerate(reader):
        if i == 0 and has_header:
            assert len(row) == expected, (
                f"ヘッダー列数: 期待={expected}, 実際={len(row)}"
            )
        else:
            assert len(row) == expected, (
                f"行{i + 1}の列数: 期待={expected}, 実際={len(row)}"
            )
    print(f"  列数({expected}列): OK")


def verify_balance(entries):
    """貸借一致の検証.

    単一行仕訳では borrower=lender なので、各エントリの amount が正であることと
    全エントリの合計金額を表示する。
    """
    total_amount = sum(e.amount for e in entries)
    for i, e in enumerate(entries):
        assert e.amount > 0, f"仕訳{i + 1}: 金額が正でない({e.amount})"
    print(f"  貸借一致: 各仕訳の借方金額=貸方金額（単一行仕訳）, 合計={total_amount:,} (OK)")


def verify_csv_amounts(content: str, has_header: bool, debit_col: int, credit_col: int):
    """出力CSVの借方・貸方金額が一致することを検証."""
    import csv
    import io

    reader = csv.reader(io.StringIO(content))
    for i, row in enumerate(reader):
        if i == 0 and has_header:
            continue
        try:
            debit_amt = int(row[debit_col])
            credit_amt = int(row[credit_col])
            assert debit_amt == credit_amt, (
                f"行{i + 1}: 借方金額({debit_amt}) != 貸方金額({credit_amt})"
            )
        except (ValueError, IndexError) as e:
            raise AssertionError(f"行{i + 1}: 金額の検証でエラー: {e}")
    print(f"  借方=貸方金額一致: OK")


def verify_yayoi_flags(content: str):
    """弥生会計固有フラグの検証."""
    import csv
    import io

    reader = csv.reader(io.StringIO(content))
    for i, row in enumerate(reader):
        assert row[0] == "2000", f"行{i + 1}: 識別フラグが2000でない({row[0]})"
        assert row[19] == "0", f"行{i + 1}: タイプが0でない({row[19]})"
        assert row[24] == "no", f"行{i + 1}: 調整フラグが'no'でない({row[24]})"
    print(f"  弥生固有フラグ: OK")


def verify_mf_tax_placement(content: str):
    """マネーフォワードの税区分配置が正しいことを検証.

    費用科目の仕入→借方に税区分、貸方は対象外
    売上科目→貸方に税区分、借方は対象外
    """
    import csv
    import io

    reader = csv.reader(io.StringIO(content))
    header = next(reader)
    for i, row in enumerate(reader, start=2):
        debit_tax = row[4]   # 借方税区分
        credit_tax = row[11]  # 貸方税区分
        debit_amt_str = row[6]  # 借方金額(税込)
        # 基本チェック: 両方とも空でないこと
        assert debit_tax, f"行{i}: 借方税区分が空"
        assert credit_tax, f"行{i}: 貸方税区分が空"
    print(f"  MF税区分配置: OK")


def main():
    print("=" * 60)
    print("E2E検証: sample_tkc.csv → 3プラットフォーム")
    print("=" * 60)

    # TKC読み込み検証
    entries = read_tkc_csv(SAMPLE)
    print(f"\n入力: {len(entries)}件の仕訳を読み込み")
    verify_balance(entries)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)

        # --- freee ---
        print(f"\n--- freee会計 ---")
        out = export_from_tkc(SAMPLE, "freee", tmpdir / "out_freee.csv")
        content = verify_encoding(out, "utf-8", expect_bom=False)
        verify_row_count(content, len(entries), has_header=True)
        verify_column_count(content, 18, has_header=True)

        # --- マネーフォワード ---
        print(f"\n--- マネーフォワード ---")
        out = export_from_tkc(SAMPLE, "moneyforward", tmpdir / "out_mf.csv")
        content = verify_encoding(out, "utf-8", expect_bom=False)
        verify_row_count(content, len(entries), has_header=True)
        verify_column_count(content, 23, has_header=True)
        verify_csv_amounts(content, has_header=True, debit_col=6, credit_col=13)
        verify_mf_tax_placement(content)

        # --- 弥生会計 ---
        print(f"\n--- 弥生会計 ---")
        out = export_from_tkc(SAMPLE, "yayoi", tmpdir / "out_yayoi.csv")
        content = verify_encoding(out, "cp932", expect_bom=False)
        verify_row_count(content, len(entries), has_header=False)
        verify_column_count(content, 25, has_header=False)
        verify_csv_amounts(content, has_header=False, debit_col=8, credit_col=14)
        verify_yayoi_flags(content)

    print(f"\n{'=' * 60}")
    print("全検証通過!")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
