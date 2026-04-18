"""科目名マッピング — TKC科目コード → 各プラットフォームの科目名."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional


class AccountMapper:
    """JSON設定ファイルに基づく勘定科目マッピング.

    マッピングに該当しない科目はTKCの科目名をそのまま使用（フォールバック）。
    """

    def __init__(self, config_path: Optional[str | Path] = None):
        self._mapping: dict[str, dict[str, str]] = {}
        if config_path:
            self.load(config_path)

    def load(self, config_path: str | Path) -> None:
        """JSON設定ファイルを読み込む.

        JSONの構造:
        {
            "freee": {"1111": "現金", "4211": "売上高", ...},
            "moneyforward": {"1111": "現金", ...},
            "yayoi": {"1111": "現金", ...}
        }
        """
        path = Path(config_path)
        if not path.exists():
            return
        with open(path, encoding="utf-8") as f:
            self._mapping = json.load(f)

    def map_account(
        self,
        tkc_code: str,
        tkc_name: str,
        platform: str,
    ) -> str:
        """TKC科目コードをプラットフォーム用の科目名に変換.

        マッピングが存在しなければTKCの科目名をそのまま返す。
        """
        platform_map = self._mapping.get(platform, {})
        return platform_map.get(tkc_code, tkc_name)
