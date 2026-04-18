"""マネーフォワードクラウド会計インポートCSVアダプタ.

仕様:
- エンコーディング: UTF-8（BOMなし）
- ヘッダー: あり（必須）
- 列数: 23列
- 日付形式: YYYY/MM/DD
- 複合仕訳: 同一取引Noでグルーピング
"""

from __future__ import annotations

from ..models import JournalEntry
from .base import AbstractExportAdapter


class MoneyForwardAdapter(AbstractExportAdapter):
    """マネーフォワードクラウド会計用エクスポートアダプタ."""

    platform = "moneyforward"
    encoding = "utf-8"
    has_header = True
    bom = False

    def get_headers(self) -> list[str]:
        return [
            "取引No",  # 0
            "取引日",  # 1: YYYY/MM/DD
            "借方勘定科目",  # 2
            "借方補助科目",  # 3
            "借方税区分",  # 4
            "借方部門",  # 5
            "借方金額(税込)",  # 6
            "借方金額(税抜)",  # 7
            "借方消費税額",  # 8
            "貸方勘定科目",  # 9
            "貸方補助科目",  # 10
            "貸方税区分",  # 11
            "貸方部門",  # 12
            "貸方金額(税込)",  # 13
            "貸方金額(税抜)",  # 14
            "貸方消費税額",  # 15
            "摘要",  # 16
            "仕訳メモ",  # 17
            "タグ",  # 18
            "MF仕訳タイプ",  # 19: 空白=通常
            "決算整理仕訳",  # 20: 0=通常
            "作成日時",  # 21
            "最終更新日時",  # 22
        ]

    def convert_entry(self, entry: JournalEntry) -> list[str]:
        """JournalEntryをマネーフォワードの23列CSVデータに変換."""
        date_str = entry.transaction_date.strftime("%Y/%m/%d")
        debit_name = self.map_account(entry.debit_code, entry.debit_name)
        credit_name = self.map_account(entry.credit_code, entry.credit_name)

        # 税区分の配置: 課税側に税区分、対向側は「対象外」
        # 借方が費用科目（5/6/7xxx）→ 借方が課税仕入、貸方は対象外
        # 貸方が売上科目（4xxx）→ 貸方が課税売上、借方は対象外
        if entry.debit_code.startswith(("5", "6", "7")):
            debit_tax = self.map_tax(entry.tax_rate, entry.debit_code, entry.credit_code)
            credit_tax = "対象外"
            d_tax_amt = str(entry.tax_amount)
            c_tax_amt = "0"
        elif entry.credit_code.startswith("4"):
            debit_tax = "対象外"
            credit_tax = self.map_tax(entry.tax_rate, entry.debit_code, entry.credit_code)
            d_tax_amt = "0"
            c_tax_amt = str(entry.tax_amount)
        else:
            # 振替仕訳等: 両方対象外
            debit_tax = self.map_tax(entry.tax_rate, entry.debit_code, entry.credit_code)
            credit_tax = self.map_tax(entry.tax_rate, entry.debit_code, entry.credit_code)
            d_tax_amt = str(entry.tax_amount)
            c_tax_amt = "0"

        net = entry.net_amount if entry.net_amount else entry.amount

        return [
            str(entry.voucher_no),  # 取引No
            date_str,  # 取引日
            debit_name,  # 借方勘定科目
            entry.debit_sub_name,  # 借方補助科目
            debit_tax,  # 借方税区分
            "",  # 借方部門
            str(entry.amount),  # 借方金額(税込)
            str(net),  # 借方金額(税抜)
            d_tax_amt,  # 借方消費税額
            credit_name,  # 貸方勘定科目
            entry.credit_sub_name,  # 貸方補助科目
            credit_tax,  # 貸方税区分
            "",  # 貸方部門
            str(entry.amount),  # 貸方金額(税込)
            str(net),  # 貸方金額(税抜)
            c_tax_amt,  # 貸方消費税額
            entry.description,  # 摘要
            "",  # 仕訳メモ
            entry.business_name.strip(),  # タグ
            "",  # MF仕訳タイプ
            "0",  # 決算整理仕訳
            "",  # 作成日時
            "",  # 最終更新日時
        ]
