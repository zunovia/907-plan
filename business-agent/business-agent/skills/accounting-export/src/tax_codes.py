"""税区分マッピング — TKC税率 → 各プラットフォームの税区分名."""

from __future__ import annotations

from typing import Optional


def is_revenue_account(account_code: str) -> bool:
    """科目コードが売上系（4xxx）かどうかを判定."""
    return account_code.startswith("4")


def get_tax_category(
    tax_rate: Optional[float],
    debit_code: str,
    credit_code: str,
    platform: str,
) -> str:
    """TKC税率から各プラットフォームの税区分名を返す.

    Args:
        tax_rate: TKCの税率 (0.1, 0.08, None)
        debit_code: 借方科目コード
        credit_code: 貸方科目コード
        platform: "freee", "moneyforward", "yayoi"
    """
    if tax_rate is None or tax_rate == 0:
        return _TAX_MAPS[platform]["none"]

    # 売上/仕入の判定: 貸方が4xxx→売上、借方が5xxx/6xxx/7xxx→仕入
    is_sales = is_revenue_account(credit_code)

    if tax_rate == 0.1:
        key = "sales_10" if is_sales else "purchase_10"
    elif tax_rate == 0.08:
        key = "sales_8r" if is_sales else "purchase_8r"
    else:
        return _TAX_MAPS[platform]["none"]

    return _TAX_MAPS[platform][key]


# 各プラットフォームの税区分名称
_TAX_MAPS: dict[str, dict[str, str]] = {
    "freee": {
        "none": "対象外",
        "sales_10": "課税売上10%",
        "sales_8r": "課税売上8%（軽）",
        "purchase_10": "課対仕入10%",
        "purchase_8r": "課対仕入8%（軽）",
    },
    "moneyforward": {
        "none": "対象外",
        "sales_10": "課税売上(10%)",
        "sales_8r": "課税売上(軽8%)",
        "purchase_10": "課税仕入(10%)",
        "purchase_8r": "課税仕入(軽8%)",
    },
    "yayoi": {
        "none": "対象外",
        "sales_10": "課税売上10%",
        "sales_8r": "課税売上8%（軽減税率）",
        "purchase_10": "課対仕入10%",
        "purchase_8r": "課対仕入8%（軽減税率）",
    },
}
