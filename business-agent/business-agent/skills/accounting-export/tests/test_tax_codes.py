"""税区分マッピングのテスト."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.tax_codes import get_tax_category, is_revenue_account


def test_revenue_account():
    assert is_revenue_account("4211") is True
    assert is_revenue_account("5471") is False
    assert is_revenue_account("1113") is False
    print("OK: 売上科目判定")


def test_no_tax():
    for platform in ("freee", "moneyforward", "yayoi"):
        result = get_tax_category(None, "5471", "1113", platform)
        assert result == "対象外", f"{platform}: {result}"
    print("OK: 非課税→対象外")


def test_purchase_10():
    r = get_tax_category(0.1, "5471", "1113", "freee")
    assert r == "課対仕入10%", f"freee: {r}"
    r = get_tax_category(0.1, "5471", "1113", "moneyforward")
    assert r == "課税仕入(10%)", f"mf: {r}"
    r = get_tax_category(0.1, "5471", "1113", "yayoi")
    assert r == "課対仕入10%", f"yayoi: {r}"
    print("OK: 課税仕入10%")


def test_sales_10():
    r = get_tax_category(0.1, "1113", "4211", "freee")
    assert r == "課税売上10%", f"freee: {r}"
    r = get_tax_category(0.1, "1113", "4211", "moneyforward")
    assert r == "課税売上(10%)", f"mf: {r}"
    print("OK: 課税売上10%")


def test_purchase_8r():
    r = get_tax_category(0.08, "5471", "1113", "freee")
    assert r == "課対仕入8%（軽）", f"freee: {r}"
    r = get_tax_category(0.08, "5471", "1113", "moneyforward")
    assert r == "課税仕入(軽8%)", f"mf: {r}"
    print("OK: 軽減税率8%仕入")


if __name__ == "__main__":
    test_revenue_account()
    test_no_tax()
    test_purchase_10()
    test_sales_10()
    test_purchase_8r()
    print("\n全テスト通過")
