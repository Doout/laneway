mod daemon;

use daemon::{DesktopSnapshot, LocalDaemon};

#[tauri::command]
async fn desktop_snapshot() -> Result<DesktopSnapshot, String> {
    LocalDaemon::from_environment()
        .snapshot()
        .await
        .map_err(|error| error.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![desktop_snapshot])
        .run(tauri::generate_context!())
        .expect("run Laneway desktop client");
}
