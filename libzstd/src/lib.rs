use aggregator::init_zstd_encoder;
use core::slice;
use std::io::Write;
use std::os::raw::{c_char, c_uchar};
use std::ptr::null;

fn out_as_err(err: &str, out: &mut [u8]) -> *const c_char {
    let msg = if err.len() + 1 > out.len() {
        "compress_scroll_batch_bytes: not enough output buffer for the error message"
    } else {
        err
    };

    let cpy_src = unsafe { slice::from_raw_parts(msg.as_ptr(), msg.len()) };
    out[..cpy_src.len()].copy_from_slice(cpy_src);
    out[cpy_src.len()] = 0; // build the c-style string
    out.as_ptr() as *const c_char
}

/// Entry
#[no_mangle]
pub unsafe extern "C" fn compress_scroll_batch_bytes(
    src: *const c_uchar,
    src_size: u64,
    output_buf: *mut c_uchar,
    output_buf_size: *mut u64,
) -> *const c_char {
    let buf_size = *output_buf_size;
    let src = unsafe { slice::from_raw_parts(src, src_size as usize) };
    let out = unsafe { slice::from_raw_parts_mut(output_buf, buf_size as usize)};

    let mut encoder = init_zstd_encoder(None);
    encoder
        .set_pledged_src_size(Some(src.len() as u64))
        .expect("compress_scroll_batch_bytes: failed to set pledged src size, should be infallible");

    let ret = encoder.write_all(src);
    let ret = ret.and_then(|_| encoder.finish());
    if let Err(e) = ret {
        return out_as_err(e.to_string().as_str(), out);
    }

    let ret = ret.unwrap();
    if ret.len() > buf_size as usize {
        return out_as_err("compress_scroll_batch_bytes: not enough output buffer for compressed data", out);
    }
    out[..ret.len()].copy_from_slice(&ret);
    *output_buf_size = ret.len() as u64;

    null()
}
