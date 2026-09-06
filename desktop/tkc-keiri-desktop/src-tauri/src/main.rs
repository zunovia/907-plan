// TKC AI 仕訳インポートツール デスクトップ版
// 画面はWeb版と同一（dist/index.html はWorkerのソースから生成）。
// 更新は「黙って適用しない」方針: 新版を検知したら内容を提示し、利用者が同意したときだけ適用する。
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    tkc_keiri_desktop_lib::run()
}
