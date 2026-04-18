"""弥生会計インポートCSVアダプタ.

仕様:
- エンコーディング: Shift_JIS (cp932)
- ヘッダー: なし
- 列数: 25列固定
- 識別フラグ: 2000=通常仕訳（単一行）
- 日付形式: YYYY/MM/DD
"""

from __future__ import annotations

from ..models import JournalEntry
from .base import AbstractExportAdapter


class YayoiAdapter(AbstractExportAdapter):
    """弥生会計用エクスポートアダプタ."""

    platform = "yayoi"
    encoding = "cp932"
    has_header = False
    bom = False

    def get_headers(self) -> list[str]:
        """弥生はヘッダーなしだが、内部参照用に列名を返す."""
        return [
            "識別フラグ",  # 0: 2000=通常仕訳
            "伝票No.",  # 1
            "決算",  # 2
            "取引日付",  # 3: YYYY/MM/DD
            "借方勘定科目",  # 4
            "借方補助科目",  # 5
            "借方部門",  # 6
            "借方税区分",  # 7
            "借方金額",  # 8
            "借方税金額",  # 9
            "貸方勘定科目",  # 10
            "貸方補助科目",  # 11
            "貸方部門",  # 12
            "貸方税区分",  # 13
            "貸方金額",  # 14
            "貸方税金額",  # 15
            "摘要",  # 16
            "番号",  # 17
            "期日",  # 18
            "タイプ",  # 19: 0=通常
            "生成元",  # 20
            "仕訳メモ",  # 21
            "付箋1",  # 22
            "付箋2",  # 23
            "調整",  # 24
        ]

    def convert_entry(self, entry: JournalEntry) -> list[str]:
        """JournalEntryを弥生会計の25列CSVデータに変換."""
        date_str = entry.transaction_date.strftime("%Y/%m/%d")
        debit_name = self.map_account(entry.debit_code, entry.debit_name)
        credit_name = self.map_account(entry.credit_code, entry.credit_name)
        tax_category = self.map_tax(
            entry.tax_rate, entry.debit_code, entry.credit_code
        )

        # 弥生: 税区分と税金額は課税側にのみ設定、対向側は「対象外」/0
        # 費用仕入（借方5/6/7xxx）→ 借方に税区分+税額
        # 売上（貸方4xxx）→ 貸方に税区分+税額
        # それ以外（振替等）→ 両方対象外
        is_purchase = entry.debit_code.startswith(("5", "6", "7"))
        is_sales = entry.credit_code.startswith("4")

        if is_purchase:
            debit_tax_cat = tax_category
            credit_tax_cat = "対象外"
            debit_tax_amt = str(entry.tax_amount) if entry.tax_rate else "0"
            credit_tax_amt = "0"
        elif is_sales:
            debit_tax_cat = "対象外"
            credit_tax_cat = tax_category
            debit_tax_amt = "0"
            credit_tax_amt = str(entry.tax_amount) if entry.tax_rate else "0"
        else:
            debit_tax_cat = tax_category
            credit_tax_cat = tax_category
            debit_tax_amt = str(entry.tax_amount) if entry.tax_rate else "0"
            credit_tax_amt = "0"

        return [
            "2000",  # 識別フラグ（単一仕訳）
            str(entry.voucher_no),  # 伝票No.
            "",  # 決算
            date_str,  # 取引日付
            debit_name,  # 借方勘定科目
            entry.debit_sub_name,  # 借方補助科目
            "",  # 借方部門
            debit_tax_cat,  # 借方税区分
            str(entry.amount),  # 借方金額
            debit_tax_amt,  # 借方税金額
            credit_name,  # 貸方勘定科目
            entry.credit_sub_name,  # 貸方補助科目
            "",  # 貸方部門
            credit_tax_cat,  # 貸方税区分
            str(entry.amount),  # 貸方金額
            credit_tax_amt,  # 貸方税金額
            entry.description,  # 摘要
            "",  # 番号
            "",  # 期日
            "0",  # タイプ
            "",  # 生成元
            "",  # 仕訳メモ
            "0",  # 付箋1
            "0",  # 付箋2
            "no",  # 調整
        ]

    def validate(self, rows: list[list[str]]) -> list[str]:
        """弥生固有のバリデーション."""
        errors = []
        for i, row in enumerate(rows):
            if len(row) != 25:
                errors.append(f"行{i + 1}: 列数が25でない（{len(row)}列）")
            if not row[3]:
                errors.append(f"行{i + 1}: 取引日付が空")
            try:
                amt = int(row[8])
                if amt <= 0:
                    errors.append(f"行{i + 1}: 借方金額が正でない（{amt}）")
            except ValueError:
                errors.append(f"行{i + 1}: 借方金額が数値でない（{row[8]}）")
        return errors
