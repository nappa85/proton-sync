pub const API_BASE: &str = "https://mail.proton.me/api";
pub const APP_VERSION: &str = "web-mail@6.3.2";

use reqwest::blocking::Client;
use std::time::Duration;

#[derive(Default)]
pub(crate) struct RequestPacer(std::sync::Mutex<Option<std::time::Instant>>);

impl RequestPacer {
    pub fn wait(&self) {
        let mut last = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(start) = *last {
            if let Some(delay) = Duration::from_millis(100).checked_sub(start.elapsed()) {
                std::thread::sleep(delay);
            }
        }
        *last = Some(std::time::Instant::now());
    }
}

pub fn build_client(timeout: Duration) -> Client {
    Client::builder()
        .timeout(timeout)
        .user_agent("curl/8.0")
        .build()
        .expect("HTTP client")
}
