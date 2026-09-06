use tauri_plugin_dialog::{DialogExt, MessageDialogButtons, MessageDialogKind};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_dialog::init());

    #[cfg(desktop)]
    let builder = builder
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(|app| {
            let handle = app.handle().clone();
            // 起動時に1度だけ確認する。失敗しても本体の利用は妨げない。
            tauri::async_runtime::spawn(async move {
                if let Err(e) = check_for_update(handle).await {
                    eprintln!("更新確認に失敗しました: {e}");
                }
            });
            Ok(())
        });

    builder
        .run(tauri::generate_context!())
        .expect("アプリケーションの起動に失敗しました");
}

#[cfg(desktop)]
async fn check_for_update(app: tauri::AppHandle) -> tauri_plugin_updater::Result<()> {
    use tauri_plugin_updater::UpdaterExt;

    let Some(update) = app.updater()?.check().await? else {
        return Ok(());
    };

    let notes = update
        .body
        .clone()
        .filter(|b| !b.trim().is_empty())
        .unwrap_or_else(|| "（変更点の記載はありません）".to_string());

    let message = format!(
        "新しいバージョン v{} が公開されています。\n\n【変更点】\n{}\n\n\
         いま更新すると、ダウンロード後にアプリを再起動します。\n\
         月次の締め作業中など、動作を変えたくないときは「あとで」を選んでください。",
        update.version, notes
    );

    let accepted = app
        .dialog()
        .message(message)
        .title("アップデートのお知らせ")
        .kind(MessageDialogKind::Info)
        .buttons(MessageDialogButtons::OkCancelCustom(
            "いま更新する".to_string(),
            "あとで".to_string(),
        ))
        .blocking_show();

    if accepted {
        update.download_and_install(|_chunk, _total| {}, || {}).await?;
        app.restart();
    }

    Ok(())
}
