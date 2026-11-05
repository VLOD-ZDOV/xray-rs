//! Erase delivered plaintext so the optimizer cannot elide the zeroing.
use zeroize::Zeroize;

pub(crate) fn erase(bytes: &mut [u8]) {
    bytes.zeroize();
}

#[cfg(test)]
mod tests {
    #[test]
    fn every_alignment_and_partial_length_is_erased_without_touching_neighbors() {
        for start in 0..32 {
            for len in 0..260 {
                let mut bytes = vec![0xa5; start + len + 32];
                super::erase(&mut bytes[start..start + len]);
                assert!(bytes[..start].iter().all(|&b| b == 0xa5));
                assert!(bytes[start..start + len].iter().all(|&b| b == 0));
                assert!(bytes[start + len..].iter().all(|&b| b == 0xa5));
            }
        }
    }
}
