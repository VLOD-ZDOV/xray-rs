//! XHTTP padding values, as in Xray-core's splithttp/xpadding.go. `tokenish`
//! lengths are measured after HPACK Huffman coding, which is what the wire shows.

use rand::Rng;

const BASE62: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const TOLERANCE: usize = 2;
const MAX_ADJUSTMENTS: usize = 150;

/// Xray draws from `[from, to)`; equal bounds are exact.
pub fn draw(range: (usize, usize)) -> usize {
    if range.0 >= range.1 {
        return range.0;
    }
    rand::thread_rng().gen_range(range.0..range.1)
}

pub fn generate(tokenish: bool, length: usize) -> String {
    if !tokenish || length == 0 {
        return "X".repeat(length);
    }
    let mut rng = rand::thread_rng();
    let initial = (length * 5).div_ceil(4).max(1);
    let mut padding: String = (0..initial)
        .map(|_| BASE62[rng.gen_range(0..BASE62.len())] as char)
        .collect();
    // 'X' and 'Z' have 8-bit codes; alternating them avoids long runs.
    let mut adjust = 'X';
    for _ in 0..MAX_ADJUSTMENTS {
        let current = huffman_len(&padding);
        if current.abs_diff(length) <= TOLERANCE {
            break;
        }
        if current < length {
            padding.push(adjust);
            adjust = if adjust == 'X' { 'Z' } else { 'X' };
        } else if padding.len() > 1 {
            padding.pop();
        } else {
            break;
        }
    }
    padding
}

pub fn is_valid(value: &str, range: (usize, usize), tokenish: bool) -> bool {
    if value.is_empty() {
        return false;
    }
    if tokenish {
        let n = huffman_len(value);
        n >= range.0.saturating_sub(TOLERANCE) && n <= range.1 + TOLERANCE
    } else {
        (range.0..=range.1).contains(&value.len())
    }
}

fn huffman_len(value: &str) -> usize {
    value
        .bytes()
        .map(|b| usize::from(HPACK_HUFFMAN_CODE_LENGTHS[usize::from(b)]))
        .sum::<usize>()
        .div_ceil(8)
}

// RFC 7541 Appendix B code lengths in bits.
const HPACK_HUFFMAN_CODE_LENGTHS: [u8; 256] = [
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 30, 28,
    28, 28, 28, 28, 28, 28, 28, 28, 6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6, 5, 5,
    5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10, 13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6, 15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6,
    6, 5, 6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28, 20, 22, 20, 20, 22, 22, 22, 23, 22,
    23, 23, 23, 23, 23, 24, 23, 24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24, 22,
    21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23, 21, 21, 22, 21, 23, 22, 23, 23, 20,
    22, 22, 22, 23, 22, 22, 23, 26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25, 19,
    21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27, 20, 24, 20, 21, 22, 21, 21, 23, 22,
    22, 25, 25, 24, 24, 26, 23, 26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenish_targets_huffman_length() {
        for length in [1, 100, 500, 1000] {
            let value = generate(true, length);
            assert!(value.bytes().all(|b| BASE62.contains(&b)));
            assert!(
                is_valid(&value, (length, length), true),
                "{length}: {}",
                huffman_len(&value)
            );
        }
        assert_eq!(generate(false, 3), "XXX");
        assert!(!is_valid("", (0, 10), false));
        assert!(!is_valid("XX", (3, 10), false));
    }
}
