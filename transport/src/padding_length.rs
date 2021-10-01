//! Aids with customization of the padding lengths for outgoing packets.

use rand::distributions::Distribution;
use rand_distr::Gamma;
use russh_definitions::algorithms::internal::CryptoRngCore;

use crate::constants::MAX_EXTRA_PADDING_BLOCKS;

/// Defines a padding length distribution.
///
/// It is a function that, given a random number generator, will return the number of additional
/// (non-needed) "blocks" of padding that are to be used.
///
/// A "block" of padding refers to `n` bytes of random padding, where `n` is either the cipher
/// block size or `8`, whichever is larger, as defined in
/// [RFC4253](https://tools.ietf.org/html/rfc4253#section-6).
///
/// Randomizing this number makes it harder for attackers to infer anything about the content by
/// observing the packet lengths.
/// However more random padding also increases the required network capacity.
/// The default random padding distribution tries to balance these two aspects.
///
/// If the returned value would result in a padding that is too large to hold in the
/// `padding_length` field of a packet, it will be cropped to be small enough. Therefore any value
/// returned by these functions is a valid one.
pub type PaddingLengthDistribution = dyn FnMut(&mut dyn CryptoRngCore) -> u8;

/// Returns the distribution for padding lengths to be used by default.
///
/// # Overview for padding length distribution `default_distribution`:
///
/// Measured in 1_000_000 trials.
///
/// +-----+---------+-----+---------+-----+---------+-----+---------+-----+---------+
/// | blk |  chance | blk |  chance | blk |  chance | blk |  chance | blk |  chance |
/// +-----+---------+-----+---------+-----+---------+-----+---------+-----+---------+
/// |   0 |  43.58% |   7 |   1.22% |  14 |   0.09% |  21 |   0.01% |  28 |   0.00% |
/// |   1 |  24.68% |   8 |   0.80% |  15 |   0.05% |  22 |   0.00% |  29 |   0.00% |
/// |   2 |  12.12% |   9 |   0.54% |  16 |   0.04% |  23 |   0.00% |  30 |   0.00% |
/// |   3 |   7.00% |  10 |   0.37% |  17 |   0.02% |  24 |   0.00% |  31 |   0.00% |
/// |   4 |   4.32% |  11 |   0.25% |  18 |   0.02% |  25 |   0.00% |     |         |
/// |   5 |   2.75% |  12 |   0.18% |  19 |   0.01% |  26 |   0.00% |     |         |
/// |   6 |   1.80% |  13 |   0.12% |  20 |   0.01% |  27 |   0.00% |     |         |
/// +-----+---------+-----+---------+-----+---------+-----+---------+-----+---------+
///
/// >=25% chance to have at most 1 additional blocks.
/// >=50% chance to have at most 2 additional blocks.
/// >=75% chance to have at most 3 additional blocks.
/// >=90% chance to have at most 5 additional blocks.
/// >=95% chance to have at most 7 additional blocks.
/// >=99% chance to have at most 11 additional blocks.
pub fn default_distribution() -> Box<PaddingLengthDistribution> {
    let gamma = Gamma::new(0.5, 3.0).unwrap();

    Box::new(move |rng| {
        let mut float = gamma.sample(rng);
        while float > MAX_EXTRA_PADDING_BLOCKS as f64 {
            float = gamma.sample(rng);
        }

        // Make sure it's a valid u8
        float.max(0x00 as f64).min(0xff as f64).round() as u8
    })
}

/// Returns the distribution that always results in padding lengths of zero.
///
/// # Overview for padding length distribution `zero_distribution`:
///
/// Measured in 1000000 trials.
///
/// +-----+---------+-----+---------+-----+---------+-----+---------+-----+---------+
/// | blk |  chance | blk |  chance | blk |  chance | blk |  chance | blk |  chance |
/// +-----+---------+-----+---------+-----+---------+-----+---------+-----+---------+
/// |   0 | 100.00% |   7 |   0.00% |  14 |   0.00% |  21 |   0.00% |  28 |   0.00% |
/// |   1 |   0.00% |   8 |   0.00% |  15 |   0.00% |  22 |   0.00% |  29 |   0.00% |
/// |   2 |   0.00% |   9 |   0.00% |  16 |   0.00% |  23 |   0.00% |  30 |   0.00% |
/// |   3 |   0.00% |  10 |   0.00% |  17 |   0.00% |  24 |   0.00% |  31 |   0.00% |
/// |   4 |   0.00% |  11 |   0.00% |  18 |   0.00% |  25 |   0.00% |     |         |
/// |   5 |   0.00% |  12 |   0.00% |  19 |   0.00% |  26 |   0.00% |     |         |
/// |   6 |   0.00% |  13 |   0.00% |  20 |   0.00% |  27 |   0.00% |     |         |
/// +-----+---------+-----+---------+-----+---------+-----+---------+-----+---------+
///
/// >=25% chance to have at most 1 additional blocks.
/// >=50% chance to have at most 1 additional blocks.
/// >=75% chance to have at most 1 additional blocks.
/// >=90% chance to have at most 1 additional blocks.
/// >=95% chance to have at most 1 additional blocks.
/// >=99% chance to have at most 1 additional blocks.
pub fn zero_distribution() -> Box<PaddingLengthDistribution> {
    Box::new(|_| 0)
}
