"""freee会計インポートCSVアダプタ.

仕様:
- エンコーディング: UTF-8 BOM
- ヘッダー: あり（必須）
- 列数: 18列
- 日付形式: YYYY/MM/DD
- 複合仕訳: 片側を空白（Phase 2）
"""

from __future__ import annotations

from ..models import JournalEntry
from .base import AbstractExportAdapter


class FreeeAdapter(AbstractExportAdapter):
    """freee会計用エクスポートアダプタ."""

    platform = "freee"
    encoding = "utf-8"
    has_header = True
    bom = True

    def get_headers(self) -> list[str]:
        return [
            "収支区分",  # 0: 収入/支出/（空白=振替）
            "管理番号",  # 1
            "発生日",  # 2: YYYY/MM/DD
            "決済期日",  # 3
            "取引先",  # 4
            "勘定科目",  # 5: 借方科目
            "税区分",  # 6
            "金額",  # 7
            "税計算区分",  # 8: 内税/外税/対象外
            "税額",  # 9
            "備考",  # 10
            "品目",  # 11
            "部門",  # 12
            "メモタグ",  # 13
            "セグメント1",  # 14
            "セグメント2",  # 15
            "セグメント3",  # 16
            "決済口座",  # 17
        ]

    def _get_income_expense_type(self, entry: JournalEntry) -> str:
        """収支区分を判定."""
        if entry.credit_code.startswith("4"):
            return "収入"
        if entry.debit_code.startswith(("5", "6", "7")):
            return "支出"
        return ""  # 振替

    def convert_entry(self, entry: JournalEntry) -> list[str]:
        """JournalEntryをfreeeの18列CSVデータに変換."""
        date_str = entry.transaction_date.strftime("%Y/%m/%d")
        income_expense = self._get_income_expense_type(entry)

        # freeeでは収入→貸方科目、支出→借方科目を「勘定科目」に設定
        if income_expense == "収入":
            account_name = self.map_account(entry.credit_code, entry.credit_name)
        elif income_expense == "支出":
            account_name = self.map_account(entry.debit_code, entry.debit_name)
        else:
            account_name = self.map_account(entry.debit_code, entry.debit_name)

        tax_category = self.map_tax(
            entry.tax_rate, entry.debit_code, entry.credit_code
        )

        # 税計算区分
        if entry.tax_rate:
            tax_calc = "内税"
        else:
            tax_calc = "対象外"

        return [
            income_expense,  # 収支区分
            str(entry.voucher_no),  # 管理番号
            date_str,  # 発生日
            "",  # 決済期日
            entry.partner_name,  # 取引先
            account_name,  # 勘定科目
            tax_category,  # 税区分
            str(entry.amount),  # 金額
            tax_calc,  # 税計算区分
            str(entry.tax_amount),  # 税額
            entry.description,  # 備考
            "",  # 品目
            entry.business_name.strip(),  # 部門
            "",  # メモタグ
            "",  # セグメント1
            "",  # セグメント2
            "",  # セグメント3
            "",  # 決済口座
        ]
