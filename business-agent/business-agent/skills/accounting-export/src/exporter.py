"""メインオーケストレータ — TKC CSV → 各プラットフォームCSVへの変換.

CLI使用例:
    python -m skills.accounting-export.src.exporter input.csv --platform freee -o output.csv
    python -m skills.accounting-export.src.exporter input.csv --platform yayoi
    python -m skills.accounting-export.src.exporter input.csv --platform moneyforward --config custom_map.json
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional

from .account_mapper import AccountMapper
from .adapters import FreeeAdapter, MoneyForwardAdapter, YayoiAdapter
from .adapters.base import AbstractExportAdapter
from .reader.tkc_reader import read_tkc_csv

ADAPTERS: dict[str, type[AbstractExportAdapter]] = {
    "freee": FreeeAdapter,
    "moneyforward": MoneyForwardAdapter,
    "yayoi": YayoiAdapter,
}

# デフォルト出力ファイル名のサフィックス
_SUFFIXES: dict[str, str] = {
    "freee": "_freee.csv",
    "moneyforward": "_mf.csv",
    "yayoi": "_yayoi.csv",
}


def export_from_tkc(
    input_path: str | Path,
    platform: str,
    output_path: Optional[str | Path] = None,
    config_path: Optional[str | Path] = None,
) -> Path:
    """TKC CSVを指定プラットフォームのCSVに変換.

    Args:
        input_path: TKC仕訳CSVファイルパス
        platform: "freee", "moneyforward", "yayoi"
        output_path: 出力先パス（省略時は入力ファイル名+サフィックス）
        config_path: 科目マッピングJSON（省略時はデフォルト設定を使用）

    Returns:
        出力ファイルパス
    """
    if platform not in ADAPTERS:
        raise ValueError(
            f"未対応プラットフォーム: '{platform}'. "
            f"対応: {', '.join(ADAPTERS.keys())}"
        )

    input_path = Path(input_path)

    # 科目マッピングの読み込み
    mapper = AccountMapper()
    if config_path:
        mapper.load(config_path)
    else:
        default_config = (
            Path(__file__).parent.parent / "config" / "account_map_default.json"
        )
        if default_config.exists():
            mapper.load(default_config)

    # 出力パスの決定
    if output_path is None:
        output_path = input_path.with_name(
            input_path.stem + _SUFFIXES[platform]
        )
    output_path = Path(output_path)

    # 変換実行
    entries = read_tkc_csv(input_path)
    if not entries:
        raise ValueError(f"仕訳データが0件です: {input_path}")

    # バリデーション
    all_errors = []
    for i, entry in enumerate(entries, start=1):
        entry_errors = entry.validate()
        for err in entry_errors:
            all_errors.append(f"仕訳{i}(伝票No.{entry.voucher_no}): {err}")
    if all_errors:
        import warnings

        warnings.warn(
            f"バリデーション警告 ({len(all_errors)}件):\n" + "\n".join(all_errors),
            stacklevel=2,
        )

    adapter = ADAPTERS[platform](account_mapper=mapper)
    result_path = adapter.export(entries, output_path)

    print(f"変換完了: {len(entries)}件 → {result_path}")
    print(f"  プラットフォーム: {platform}")
    print(f"  エンコーディング: {adapter.encoding}")
    return result_path


def main() -> None:
    """CLIエントリポイント."""
    parser = argparse.ArgumentParser(
        description="TKC仕訳CSVを各会計ソフト用CSVに変換"
    )
    parser.add_argument("input", help="TKC仕訳CSVファイルパス")
    parser.add_argument(
        "--platform",
        "-p",
        required=True,
        choices=list(ADAPTERS.keys()),
        help="出力先プラットフォーム",
    )
    parser.add_argument("--output", "-o", help="出力ファイルパス（省略時は自動命名）")
    parser.add_argument("--config", "-c", help="科目マッピングJSONファイルパス")

    args = parser.parse_args()

    try:
        export_from_tkc(args.input, args.platform, args.output, args.config)
    except (FileNotFoundError, ValueError) as e:
        print(f"エラー: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
