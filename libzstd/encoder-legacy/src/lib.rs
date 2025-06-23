use core::slice;
use std::io::Write;
use std::os::raw::{c_char, c_uchar};
use std::ptr::null;
use zstd::stream::Encoder;
use zstd::zstd_safe::{CParameter, ParamSwitch};

// re-export zstd
pub use zstd;

// we use offset window no more than = 17
// TODO: use for multi-block zstd.
#[allow(dead_code)]
pub const CL_WINDOW_LIMIT: usize = 17;

/// zstd block size target.
pub const N_BLOCK_SIZE_TARGET: u32 = 124 * 1024;

/// Maximum number of blocks that we can expect in the encoded data.
pub const N_MAX_BLOCKS: u64 = 10;

/// Zstd encoder configuration
pub fn init_zstd_encoder(target_block_size: u32) -> Encoder<'static, Vec<u8>> {
    let mut encoder = Encoder::new(Vec::new(), 0).expect("infallible");

    // disable compression of literals, i.e. literals will be raw bytes.
    encoder
        .set_parameter(CParameter::LiteralCompressionMode(ParamSwitch::Disable))
        .expect("infallible");
    // with a hack in zstd we can set window log <= CL_WINDOW_LIMIT with single segment kept
    encoder
        .set_parameter(CParameter::WindowLog(CL_WINDOW_LIMIT.try_into().unwrap()))
        .expect("infallible");
    // set target block size to fit within a single block.
    encoder
        .set_parameter(CParameter::TargetCBlockSize(target_block_size))
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

/// Helper function to convert error message to C-style string in output buffer
fn out_as_err(err: &str, out: &mut [u8]) -> *const c_char {
    let msg = if err.len() + 1 > out.len() {
        "compress_scroll_batch_bytes_legacy: not enough output buffer for the error message"
    } else {
        err
    };

    let cpy_src = unsafe { slice::from_raw_parts(msg.as_ptr(), msg.len()) };
    out[..cpy_src.len()].copy_from_slice(cpy_src);
    out[cpy_src.len()] = 0; // build the c-style string
    out.as_ptr() as *const c_char
}

/// Legacy compression function for codec v2-v7
/// Uses the customized scroll-tech/zstd-rs implementation
#[no_mangle]
pub unsafe extern "C" fn compress_scroll_batch_bytes_legacy(
    src: *const c_uchar,
    src_size: u64,
    output_buf: *mut c_uchar,
    output_buf_size: *mut u64,
) -> *const c_char {
    let buf_size = *output_buf_size;
    let src = unsafe { slice::from_raw_parts(src, src_size as usize) };
    let out = unsafe { slice::from_raw_parts_mut(output_buf, buf_size as usize) };

    let mut encoder = init_zstd_encoder(N_BLOCK_SIZE_TARGET);
    encoder.set_pledged_src_size(Some(src.len() as u64)).expect(
        "compress_scroll_batch_bytes_legacy: failed to set pledged src size, should be infallible",
    );

    let ret = encoder.write_all(src);
    let ret = ret.and_then(|_| encoder.finish());
    if let Err(e) = ret {
        return out_as_err(e.to_string().as_str(), out);
    }

    let ret = ret.unwrap();
    if ret.len() > buf_size as usize {
        return out_as_err(
            "compress_scroll_batch_bytes_legacy: not enough output buffer for compressed data",
            out,
        );
    }
    out[..ret.len()].copy_from_slice(&ret);
    *output_buf_size = ret.len() as u64;

    null()
}
