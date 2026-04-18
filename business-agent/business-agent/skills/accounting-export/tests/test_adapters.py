"""各アダプタのユニットテスト."""

import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.adapters import FreeeAdapter, MoneyForwardAdapter, YayoiAdapter
from src.models import JournalEntry


def _make_entry(**overrides) -> JournalEntry:
    defaults = dict(
        transaction_date=date(2026, 4, 1),
        voucher_no=1,
        description="テスト仕訳",
        debit_code="5471",
        debit_name="消耗品費",
        credit_code="1113",
        credit_name="普通預金",
        credit_sub_name="ＵＦＪ",
        amount=10000,
        business_code="312",
        business_name="Re☆創庫・Re☆ショップ",
    )
    defaults.update(overrides)
    return JournalEntry(**defaults)


def test_yayoi_columns():
    adapter = YayoiAdapter()
    entry = _make_entry()
    row = adapter.convert_entry(entry)
    assert len(row) == 25, f"弥生: 列数={len(row)}, 期待=25"
    assert row[0] == "2000"  # 識別フラグ
    assert row[3] == "2026/04/01"
    assert row[8] == "10000"  # 借方金額
    assert row[14] == "10000"  # 貸方金額
    print("OK: 弥生 25列出力")


def test_freee_columns():
    adapter = FreeeAdapter()
    entry = _make_entry()
    row = adapter.convert_entry(entry)
    assert len(row) == 18, f"freee: 列数={len(row)}, 期待=18"
    assert row[2] == "2026/04/01"  # 発生日
    assert row[0] == "支出"  # 5xxx→支出
    print("OK: freee 18列出力")


def test_freee_income():
    adapter = FreeeAdapter()
    entry = _make_entry(
        debit_code="1113",
        debit_name="普通預金",
        credit_code="4211",
        credit_name="自主事業収入",
        tax_rate=0.1,
        tax_amount=3000,
        net_amount=30000,
        amount=33000,
    )
    row = adapter.convert_entry(entry)
    assert row[0] == "収入"
    print("OK: freee 収入区分")


def test_moneyforward_columns():
    adapter = MoneyForwardAdapter()
    entry = _make_entry()
    row = adapter.convert_entry(entry)
    assert len(row) == 23, f"MF: 列数={len(row)}, 期待=23"
    assert row[1] == "2026/04/01"  # 取引日
    assert row[6] == "10000"  # 借方金額(税込)
    assert row[13] == "10000"  # 貸方金額(税込)
    print("OK: マネーフォワード 23列出力")


def test_yayoi_validation():
    adapter = YayoiAdapter()
    entry = _make_entry()
    rows = adapter.convert_entries([entry])
    errors = adapter.validate(rows)
    assert errors == [], f"バリデーションエラー: {errors}"
    print("OK: 弥生バリデーション通過")


def test_yayoi_adjustment_flag():
    """弥生の調整フラグが 'no' であることを確認."""
    adapter = YayoiAdapter()
    entry = _make_entry()
    row = adapter.convert_entry(entry)
    assert row[24] == "no", f"弥生: 調整フラグ={row[24]}, 期待='no'"
    print("OK: 弥生 調整フラグ='no'")


def test_moneyforward_tax_placement_purchase():
    """MF: 費用仕訳 → 借方に課税仕入、貸方は対象外."""
    adapter = MoneyForwardAdapter()
    entry = _make_entry(
        debit_code="5471",
        debit_name="消耗品費",
        credit_code="1113",
        credit_name="普通預金",
        amount=11000,
        tax_rate=0.1,
        tax_amount=1000,
        net_amount=10000,
    )
    row = adapter.convert_entry(entry)
    assert row[4] == "課税仕入(10%)", f"MF借方税区分: {row[4]}"
    assert row[11] == "対象外", f"MF貸方税区分: {row[11]}"
    assert row[8] == "1000", f"MF借方消費税額: {row[8]}"
    assert row[15] == "0", f"MF貸方消費税額: {row[15]}"
    print("OK: MF 費用仕訳の税区分配置")


def test_moneyforward_tax_placement_sales():
    """MF: 売上仕訳 → 貸方に課税売上、借方は対象外."""
    adapter = MoneyForwardAdapter()
    entry = _make_entry(
        debit_code="1113",
        debit_name="普通預金",
        credit_code="4211",
        credit_name="自主事業収入",
        amount=33000,
        tax_rate=0.1,
        tax_amount=3000,
        net_amount=30000,
    )
    row = adapter.convert_entry(entry)
    assert row[4] == "対象外", f"MF借方税区分: {row[4]}"
    assert row[11] == "課税売上(10%)", f"MF貸方税区分: {row[11]}"
    assert row[8] == "0", f"MF借方消費税額: {row[8]}"
    assert row[15] == "3000", f"MF貸方消費税額: {row[15]}"
    print("OK: MF 売上仕訳の税区分配置")


def test_freee_no_tax():
    """freee: 非課税仕訳の税計算区分が'対象外'."""
    adapter = FreeeAdapter()
    entry = _make_entry(tax_rate=None, tax_amount=0)
    row = adapter.convert_entry(entry)
    assert row[8] == "対象外", f"freee税計算区分: {row[8]}"
    assert row[6] == "対象外", f"freee税区分: {row[6]}"
    print("OK: freee 非課税→対象外")


def test_freee_transfer():
    """freee: 振替仕訳（現金→預金）は収支区分が空."""
    adapter = FreeeAdapter()
    entry = _make_entry(
        debit_code="1113",
        debit_name="普通預金",
        credit_code="1111",
        credit_name="現金",
    )
    row = adapter.convert_entry(entry)
    assert row[0] == "", f"freee収支区分: '{row[0]}', 期待=''"
    print("OK: freee 振替仕訳の収支区分=空")


def test_yayoi_tax_placement_purchase():
    """弥生: 費用仕訳 → 借方に税区分+税額、貸方は対象外."""
    adapter = YayoiAdapter()
    entry = _make_entry(
        debit_code="5471",
        debit_name="消耗品費",
        credit_code="1113",
        credit_name="普通預金",
        amount=11000,
        tax_rate=0.1,
        tax_amount=1000,
        net_amount=10000,
    )
    row = adapter.convert_entry(entry)
    assert row[7] != "対象外", f"弥生: 借方税区分が対象外になっている"
    assert row[13] == "対象外", f"弥生: 貸方税区分={row[13]}"
    assert row[9] == "1000", f"弥生: 借方税金額={row[9]}"
    assert row[15] == "0", f"弥生: 貸方税金額={row[15]}"
    print("OK: 弥生 費用仕訳の税区分配置")


def test_yayoi_tax_placement_sales():
    """弥生: 売上仕訳 → 貸方に税区分+税額、借方は対象外."""
    adapter = YayoiAdapter()
    entry = _make_entry(
        debit_code="1113",
        debit_name="普通預金",
        credit_code="4211",
        credit_name="自主事業収入",
        amount=33000,
        tax_rate=0.1,
        tax_amount=3000,
        net_amount=30000,
    )
    row = adapter.convert_entry(entry)
    assert row[7] == "対象外", f"弥生: 借方税区分={row[7]}"
    assert row[13] != "対象外", f"弥生: 貸方税区分が対象外になっている"
    assert row[9] == "0", f"弥生: 借方税金額={row[9]}"
    assert row[15] == "3000", f"弥生: 貸方税金額={row[15]}"
    print("OK: 弥生 売上仕訳の税区分配置")


if __name__ == "__main__":
    test_yayoi_columns()
    test_freee_columns()
    test_freee_income()
    test_moneyforward_columns()
    test_yayoi_validation()
    test_yayoi_adjustment_flag()
    test_moneyforward_tax_placement_purchase()
    test_moneyforward_tax_placement_sales()
    test_freee_no_tax()
    test_freee_transfer()
    test_yayoi_tax_placement_purchase()
    test_yayoi_tax_placement_sales()
    print("\n全テスト通過")
