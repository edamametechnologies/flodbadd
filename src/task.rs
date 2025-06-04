use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use tokio::task::JoinHandle;

#[derive(Debug)]
pub struct TaskHandle {
    pub handle: JoinHandle<()>,
    pub stop_flag: Arc<AtomicBool>,
}
