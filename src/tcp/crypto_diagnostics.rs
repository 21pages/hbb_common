use super::{secretbox, FramedStream, ResultType};
use sha2::{Digest, Sha256};

const TARGET: &str = "hbb_common::crypto_diag";

pub(super) fn key_set(stream: &FramedStream) {
    log::trace!(target: TARGET,
        "crypto_diag event=key_set pid={} stream={:p} addr={}",
        std::process::id(), stream.0.get_ref().0.as_ref(), stream.1,
    );
}

pub(super) fn frame(stream: &FramedStream, direction: &str, bytes: &[u8]) {
    if !log::log_enabled!(target: TARGET, log::Level::Trace) {
        return;
    }
    let Some(key) = stream.2.as_ref() else {
        return;
    };
    let seq = if direction == "tx" {
        key.1
    } else {
        key.2.saturating_add(u64::from(bytes.len() > 1))
    };
    log::trace!(target: TARGET,
        "crypto_diag event={direction} pid={} stream={:p} addr={} seq={seq} len={} sha256={:x}",
        std::process::id(), stream.0.get_ref().0.as_ref(), stream.1,
        bytes.len(), Sha256::digest(bytes),
    );
}

pub(super) fn sent(stream: &FramedStream, result: &ResultType<()>) {
    if let Some(key) = stream.2.as_ref() {
        log::trace!(target: TARGET,
            "crypto_diag event=tx_result pid={} stream={:p} addr={} seq={} result={result:?}",
            std::process::id(), stream.0.get_ref().0.as_ref(), stream.1, key.1,
        );
    }
}

pub(super) fn decryption_failed(stream: &FramedStream, bytes: &[u8]) {
    if !log::log_enabled!(target: TARGET, log::Level::Trace) {
        return;
    }
    let Some(key) = stream.2.as_ref() else {
        return;
    };
    // Probe without advancing counters or accepting the recovered plaintext.
    let matched_seq = (key.2.saturating_sub(4)..=key.2.saturating_add(4)).find(|seq| {
        *seq != key.2
            && secretbox::open(
                bytes,
                &FramedStream::get_nonce(*seq),
                key.3.as_ref().unwrap_or(&key.0),
            )
            .is_ok()
    });
    log::trace!(target: TARGET,
        "crypto_diag event=decrypt_failed pid={} stream={:p} addr={} expected_seq={} matched_seq={matched_seq:?} tx_seq={} len={} sha256={:x}",
        std::process::id(), stream.0.get_ref().0.as_ref(), stream.1,
        key.2, key.1, bytes.len(), Sha256::digest(bytes),
    );
}
