use async_trait::async_trait;
use std::error::Error;

#[async_trait]
pub trait Modem: Send + Sync {
    async fn reboot(&mut self) -> Result<(), Box<dyn Error>>;
}