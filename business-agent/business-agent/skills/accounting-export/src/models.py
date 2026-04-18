"""仕訳エントリのプラットフォーム非依存データモデル."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from typing import Optional


@dataclass
class JournalEntry:
    """単一仕訳行を表す内部データ構造.

    TKC CSV（29列）から読み込んだデータを保持し、
    各会計ソフト用アダプタへの変換元となる。
    """

    # 基本情報
    transaction_date: date
    voucher_no: int  # 伝票番号
    description: str  # 元帳摘要

    # 借方
    debit_code: str  # 4桁科目コード
    debit_name: str  # 科目名
    debit_sub_code: str = ""  # 補助科目コード
    debit_sub_name: str = ""  # 補助科目名（口座名）

    # 貸方
    credit_code: str = ""  # 4桁科目コード
    credit_name: str = ""  # 科目名
    credit_sub_code: str = ""  # 補助科目コード
    credit_sub_name: str = ""  # 補助科目名（口座名）

    # 金額
    amount: int = 0  # 取引金額（税込）
    tax_rate: Optional[float] = None  # 0.1, 0.08, or None
    tax_amount: int = 0  # 内消費税等
    net_amount: int = 0  # 税抜き金額

    # TKC固有
    business_code: str = ""  # 事業CD
    business_name: str = ""  # 事業名
    department: str = ""  # 課税区分（5=課税等）
    evidence_no: str = ""  # 証番

    # 取引先
    partner_code: str = ""
    partner_name: str = ""

    # インボイス
    invoice_no: str = ""  # 事業者登録番号（T番号）
    reduced_tax_flag: str = ""  # 軽減対象取引区分
    deduction_ratio: str = ""  # 控除割合

    # 複合仕訳（Phase 2用スタブ）
    is_compound: bool = False
    compound_group_id: Optional[str] = None

    def validate(self) -> list[str]:
        """基本バリデーション。エラーメッセージのリストを返す."""
        errors = []
        if not self.debit_code or len(self.debit_code) != 4:
            errors.append(f"借方科目コードが不正: '{self.debit_code}'")
        if not self.credit_code or len(self.credit_code) != 4:
            errors.append(f"貸方科目コードが不正: '{self.credit_code}'")
        if self.amount <= 0:
            errors.append(f"取引金額が正でない: {self.amount}")
        if self.tax_amount < 0:
            errors.append(f"消費税額が負: {self.tax_amount}")
        if self.tax_amount > self.amount:
            errors.append(f"消費税額({self.tax_amount})が取引金額({self.amount})を超過")
        if self.net_amount and self.tax_rate:
            expected_net = self.amount - self.tax_amount
            if self.net_amount != expected_net:
                errors.append(
                    f"税抜金額の不整合: net_amount={self.net_amount}, "
                    f"期待値(amount-tax)={expected_net}"
                )
        if self.debit_code and not self.debit_code.isdigit():
            errors.append(f"借方科目コードが数字でない: '{self.debit_code}'")
        if self.credit_code and not self.credit_code.isdigit():
            errors.append(f"貸方科目コードが数字でない: '{self.credit_code}'")
        return errors
