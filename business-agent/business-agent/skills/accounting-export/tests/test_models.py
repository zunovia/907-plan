"""JournalEntry dataclass のテスト."""

import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.models import JournalEntry


def test_valid_entry():
    entry = JournalEntry(
        transaction_date=date(2026, 4, 1),
        voucher_no=1,
        description="テスト仕訳",
        debit_code="5471",
        debit_name="消耗品費",
        credit_code="1113",
        credit_name="普通預金",
        amount=10000,
    )
    errors = entry.validate()
    assert errors == [], f"バリデーションエラー: {errors}"
    print("OK: 正常なエントリのバリデーション通過")


def test_invalid_debit_code():
    entry = JournalEntry(
        transaction_date=date(2026, 4, 1),
        voucher_no=1,
        description="テスト",
        debit_code="54",  # 不正（4桁でない）
        debit_name="消耗品費",
        credit_code="1113",
        credit_name="普通預金",
        amount=10000,
    )
    errors = entry.validate()
    assert len(errors) == 1
    assert "借方科目コード" in errors[0]
    print("OK: 不正な借方科目コードを検出")


def test_zero_amount():
    entry = JournalEntry(
        transaction_date=date(2026, 4, 1),
        voucher_no=1,
        description="テスト",
        debit_code="5471",
        debit_name="消耗品費",
        credit_code="1113",
        credit_name="普通預金",
        amount=0,
    )
    errors = entry.validate()
    assert any("取引金額" in e for e in errors)
    print("OK: 金額0を検出")


def test_tax_exceeds_amount():
    entry = JournalEntry(
        transaction_date=date(2026, 4, 1),
        voucher_no=1,
        description="テスト",
        debit_code="5471",
        debit_name="消耗品費",
        credit_code="1113",
        credit_name="普通預金",
        amount=10000,
        tax_amount=15000,
    )
    errors = entry.validate()
    assert any("消費税額" in e for e in errors)
    print("OK: 消費税額超過を検出")


def test_net_amount_mismatch():
    """税抜金額の不整合を検出."""
    entry = JournalEntry(
        transaction_date=date(2026, 4, 1),
        voucher_no=1,
        description="テスト",
        debit_code="5471",
        debit_name="消耗品費",
        credit_code="1113",
        credit_name="普通預金",
        amount=11000,
        tax_rate=0.1,
        tax_amount=1000,
        net_amount=9000,  # 不正: 11000-1000=10000であるべき
    )
    errors = entry.validate()
    assert any("税抜金額の不整合" in e for e in errors)
    print("OK: 税抜金額不整合を検出")


def test_non_digit_code():
    """科目コードが非数値のケース."""
    entry = JournalEntry(
        transaction_date=date(2026, 4, 1),
        voucher_no=1,
        description="テスト",
        debit_code="ABCD",
        debit_name="テスト",
        credit_code="1113",
        credit_name="普通預金",
        amount=10000,
    )
    errors = entry.validate()
    assert any("数字でない" in e for e in errors)
    print("OK: 非数値科目コードを検出")


def test_valid_with_tax():
    """税率ありの正常なエントリ."""
    entry = JournalEntry(
        transaction_date=date(2026, 4, 5),
        voucher_no=2,
        description="売上テスト",
        debit_code="1113",
        debit_name="普通預金",
        credit_code="4211",
        credit_name="自主事業収入",
        amount=33000,
        tax_rate=0.1,
        tax_amount=3000,
        net_amount=30000,
    )
    errors = entry.validate()
    assert errors == [], f"バリデーションエラー: {errors}"
    print("OK: 税率ありの正常エントリ")


if __name__ == "__main__":
    test_valid_entry()
    test_invalid_debit_code()
    test_zero_amount()
    test_tax_exceeds_amount()
    test_net_amount_mismatch()
    test_non_digit_code()
    test_valid_with_tax()
    print("\n全テスト通過")
