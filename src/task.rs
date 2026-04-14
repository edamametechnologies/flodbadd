use std::sync::Arc;
use tokio::sync::watch;
use tokio::task::JoinHandle;

#[derive(Debug)]
pub struct TaskHandle {
    pub handle: JoinHandle<()>,
    pub stop_tx: Arc<watch::Sender<bool>>,
}
