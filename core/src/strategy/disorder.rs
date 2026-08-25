// tcp out-of-order segment evasion strategy

use tokio::io::{AsyncWriteExt, Result};
use tokio::net::TcpStream;

pub struct DisorderStrategy;

impl DisorderStrategy {
    // sends clienthello in fragmented chunks
    pub async fn send_disordered(
        stream: &mut TcpStream,
        data: &[u8],
        chunk_size: usize,
    ) -> Result<()> {
        let size = if chunk_size == 0 { 16 } else { chunk_size };

        for chunk in data.chunks(size) {
            stream.write_all(chunk).await?;
            stream.flush().await?;
        }

        Ok(())
    }
}
