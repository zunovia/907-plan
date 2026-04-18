"""会計ソフトエクスポートアダプタの基底クラス."""

from __future__ import annotations

import csv
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

from ..account_mapper import AccountMapper
from ..models import JournalEntry
from ..tax_codes import get_tax_category


class AbstractExportAdapter(ABC):
    """各会計ソフト用エクスポートアダプタの抽象基底クラス."""

    platform: str = ""
    encoding: str = "utf-8"
    has_header: bool = True
    bom: bool = False

    def __init__(self, account_mapper: Optional[AccountMapper] = None):
        self._mapper = account_mapper or AccountMapper()

    def map_account(self, tkc_code: str, tkc_name: str) -> str:
        """科目コードをプラットフォーム用科目名に変換."""
        return self._mapper.map_account(tkc_code, tkc_name, self.platform)

    def map_tax(
        self, tax_rate: Optional[float], debit_code: str, credit_code: str
    ) -> str:
        """税率をプラットフォーム用税区分名に変換."""
        return get_tax_category(tax_rate, debit_code, credit_code, self.platform)

    @abstractmethod
    def get_headers(self) -> list[str]:
        """CSVヘッダー行を返す."""

    @abstractmethod
    def convert_entry(self, entry: JournalEntry) -> list[str]:
        """JournalEntryを1行のCSVデータに変換."""

    def convert_entries(self, entries: list[JournalEntry]) -> list[list[str]]:
        """全エントリを変換."""
        return [self.convert_entry(e) for e in entries]

    def validate(self, rows: list[list[str]]) -> list[str]:
        """出力データのバリデーション。エラーメッセージのリストを返す."""
        errors = []
        expected_cols = len(self.get_headers()) if self.has_header else None
        for i, row in enumerate(rows):
            if expected_cols and len(row) != expected_cols:
                errors.append(
                    f"行{i + 1}: 列数不正（期待{expected_cols}、実際{len(row)}）"
                )
        return errors

    def export(self, entries: list[JournalEntry], output_path: str | Path) -> Path:
        """JournalEntryリストをCSVファイルに出力.

        Returns:
            出力ファイルパス
        """
        output_path = Path(output_path)
        rows = self.convert_entries(entries)

        errors = self.validate(rows)
        if errors:
            raise ValueError(
                f"バリデーションエラー ({self.platform}):\n" + "\n".join(errors)
            )

        mode = "w"
        newline = ""
        encoding = self.encoding

        with open(output_path, mode, encoding=encoding, newline=newline) as f:
            # UTF-8 BOM
            if self.bom:
                f.write("\ufeff")

            writer = csv.writer(f)
            if self.has_header:
                writer.writerow(self.get_headers())
            writer.writerows(rows)

        return output_path
