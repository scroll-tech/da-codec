use zstd::stream::Encoder;
use zstd::zstd_safe::{CParameter, ParamSwitch};

// re-export zstd
pub use zstd;

// we use offset window no more than = 25
// TODO: use for multi-block zstd.
#[allow(dead_code)]
pub const CL_WINDOW_LIMIT: usize = 25;

/// Maximum number of blocks that we can expect in the encoded data.
pub const N_MAX_BLOCKS: u64 = 10;

/// Zstd encoder configuration
pub fn init_zstd_encoder() -> Encoder<'static, Vec<u8>> {
    let mut encoder = Encoder::new(Vec::new(), 22).expect("infallible");

    // disable compression of literals, i.e. literals will be raw bytes.
    encoder
        .set_parameter(CParameter::LiteralCompressionMode(ParamSwitch::Disable))
        .expect("infallible");
    // with a hack in zstd we can set window log <= 25 with single segment kept
    encoder
        .set_parameter(CParameter::WindowLog(25))
        .expect("infallible");
    // do not include the checksum at the end of the encoded data.
    encoder.include_checksum(false).expect("infallible");
    // do not include magic bytes at the start of the frame since we will have a single
    // frame.
    encoder.include_magicbytes(false).expect("infallible");
    // do not include dictionary id so we have more simple content
    encoder.include_dictid(false).expect("infallible");
    // include the content size to know at decode time the expected size of decoded
    // data.
    encoder.include_contentsize(true).expect("infallible");

    encoder
}
