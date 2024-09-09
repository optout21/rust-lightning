use bech32::Fe32;

/// Adaptor to pad a Fe32 iter
// #[derive(Clone, PartialEq, Eq)]
pub struct FesPadder<I: Iterator<Item = Fe32>> {
	end_reached: bool,
	fe32_count: usize,
	pad_count: u8,
	iter: I,
}

/// Compute how many trailing extra 5-bit elements are needed
/// such that no significant bits are dropped if the last byte is dropped.
/// Returns 0 (result falls on byte boundary), 1, or 2.
fn pad_count_from_fe32_count(fe32_count: usize) -> u8 {
    let leftover_bits = (fe32_count * 5) % 8;
    if leftover_bits == 0 {
        0
    } else {
        let needed_bits = 8 - leftover_bits; // 1..7
        let needed_extra_fe32s = (needed_bits + (5 - 1)) / 5; // 1..2
        needed_extra_fe32s as u8
    }
}

fn padded_count(fe32_count: usize) -> usize {
    fe32_count + pad_count_from_fe32_count(fe32_count) as usize
}

impl<I> FesPadder<I>
where
	I: Iterator<Item = Fe32>,
{
	fn new(iter: I) -> Self {
		Self {
			end_reached: false,
			fe32_count: 0,
			pad_count: 0,
			iter,
		}
	}
}

impl<I> Iterator for FesPadder<I>
where
	I: Iterator<Item = Fe32>,
{
	type Item = Fe32;

	fn next(&mut self) -> Option<Self::Item> {
		if let Some(elem) = self.iter.next() {
			self.fe32_count += 1;
			Some(elem)
		} else {
			// end reached
			if !self.end_reached {
				self.end_reached = true;
				self.pad_count = pad_count_from_fe32_count(self.fe32_count);
			}
			if self.pad_count > 0 {
				self.pad_count -= 1;
				Some(Fe32::Q)
			} else {
				None
			}
		}
	}

	fn size_hint(&self) -> (usize, Option<usize>) {
		let (fes_min, fes_max) = self.iter.size_hint();
		// +1 because we set last_fe with call to `next`.
		let min = padded_count(fes_min + 1);
		let max = fes_max.map(|max| padded_count(max));
		(min, max)
	}
}

/// Trait to pad an Fe32 iterator
pub trait FesPaddable: Sized + Iterator<Item = Fe32> {
	/// Pad the iterator
	fn pad_fes(self) -> FesPadder<Self> {
		FesPadder::new(self)
	}
}

impl<I> FesPaddable for I where I: Iterator<Item = Fe32> {}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_pad_count_from_fe32_count() {
        assert_eq!(pad_count_from_fe32_count(1), 1);
        assert_eq!(pad_count_from_fe32_count(2), 2);
        assert_eq!(pad_count_from_fe32_count(3), 1);
        assert_eq!(pad_count_from_fe32_count(4), 1);
        assert_eq!(pad_count_from_fe32_count(5), 2);
        assert_eq!(pad_count_from_fe32_count(6), 1);
        assert_eq!(pad_count_from_fe32_count(7), 1);
        assert_eq!(pad_count_from_fe32_count(8), 0);
    }

    #[test]
    fn test_frombech32_with_pad() {
        // use crate::ser::Base32Iterable;
        // use crate::de::FromBase32;
        use bech32::{Fe32, Fe32IterExt};

        let fes = vec![1, 2, 3, 4, 5].iter().map(|v| Fe32::try_from(*v).unwrap()).collect::<Vec<Fe32>>();
        assert_eq!(fes.len(), 5);

        assert_eq!(
            fes.iter().copied()
                .fes_to_bytes()
                .collect::<Vec<u8>>(),
            vec![8, 134, 66]
        );
        assert_eq!(
            fes.iter().copied()
                .pad_fes()
                .fes_to_bytes()
                .collect::<Vec<u8>>(),
            vec![8, 134, 66, 128]
        );
    }
}
