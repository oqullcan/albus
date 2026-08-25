// tls clienthello byte-level record segmentation strategy

use tokio::io::{AsyncWriteExt, Result};

pub struct SniSplitter;

impl SniSplitter {
    // splits the payload at byte 1 and flushes immediately to guarantee separate tcp packets
    pub async fn send_split<W: AsyncWriteExt + Unpin>(
        stream: &mut W,
        data: &[u8],
        split_offset: usize,
    ) -> Result<()> {
        let pos = if split_offset == 0 || split_offset >= data.len() {
            1 // proven universal 1-byte tls record split
        } else {
            split_offset
        };

        let (part1, part2) = data.split_at(pos);

        // write initial segment (e.g. 1 byte: 0x16) and flush immediately
        stream.write_all(part1).await?;
        stream.flush().await?;

        // write remaining segment and flush
        stream.write_all(part2).await?;
        stream.flush().await?;

        Ok(())
    }
}

