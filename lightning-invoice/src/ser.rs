use core::fmt;
use core::fmt::{Display, Formatter};
use core::{array, iter};
use alloc::boxed::Box;

use bech32::{ByteIterExt, Fe32, Fe32IterExt};
use crate::prelude::*;

use super::{Bolt11Invoice, Bolt11InvoiceFeatures, Sha256, TaggedField, ExpiryTime, MinFinalCltvExpiryDelta, Fallback, PayeePubKey, Bolt11InvoiceSignature, PaymentSecret, PositiveTimestamp,
	PrivateRoute, Description, RawTaggedField, Currency, RawHrp, SiPrefix, constants, SignedRawBolt11Invoice, RawDataPart, RouteHintHop};

/// Objects that can be encoded to base32 (bech32).
///
/// Private to this crate to avoid polluting the API.
pub trait Base32Iterable {
	/// apoelstra: In future we want to replace this Box<dyn Iterator> with an explicit
	/// associated type, to avoid the allocation. But we cannot do this until
	/// Rust 1.65 and GATs since the iterator may contain a reference to self.
	fn fe_iter<'s>(&'s self) -> Box<dyn Iterator<Item = Fe32> + 's>;
}

/// Interface to calculate the length of the base32 representation before actually serializing
pub(crate) trait Base32Len: Base32Iterable {
	/// Calculate the bech32 serialized length
	fn base32_len(&self) -> usize;
}

// Base32Iterable & Base32Len implementations are here, because the traits are in this module.

impl<const N: usize> Base32Iterable for [u8; N] {
	fn fe_iter<'s>(&'s self) -> Box<dyn Iterator<Item = Fe32> + 's> {
		Box::new((*self).into_iter().bytes_to_fes())
	}
}

impl<const N: usize> Base32Len for [u8; N] {
	/// Calculate the base32 serialized length
	fn base32_len(&self) -> usize {
		bytes_size_to_base32_size(N)
	}
}

impl Base32Iterable for [u8] {
	fn fe_iter<'s>(&'s self) -> Box<dyn Iterator<Item = Fe32> + 's> {
		Box::new(self.iter().copied().bytes_to_fes())
	}
}

impl Base32Len for [u8] {
	/// Calculate the base32 serialized length
	fn base32_len(&self) -> usize {
		bytes_size_to_base32_size(self.len())
	}
}

impl Base32Iterable for Vec<u8> {
	fn fe_iter<'s>(&'s self) -> Box<dyn Iterator<Item = Fe32> + 's> {
		Box::new(self.iter().copied().bytes_to_fes())
	}
}

impl Base32Len for Vec<u8> {
	/// Calculate the base32 serialized length
	fn base32_len(&self) -> usize {
		bytes_size_to_base32_size(self.len())
	}
}

impl Base32Iterable for PaymentSecret {
	fn fe_iter<'s>(&'s self) -> Box<dyn Iterator<Item = Fe32> + 's> {
		Box::new(self.0[..].fe_iter())
	}
}

impl Base32Len for PaymentSecret {
	fn base32_len(&self) -> usize {
		52
	}
}

impl Base32Iterable for Bolt11InvoiceFeatures {
	fn fe_iter<'s>(&'s self) -> Box<dyn Iterator<Item = Fe32> + 's> {
		// Note: here bytes are grouped into 5-bit values from rigth-to-left, therefore
		// Bech32 convversion cannot be used.
		// Explanation for the "4": the normal way to round up when dividing is to add the divisor
		// minus one before dividing
		let length_u5s = (self.le_flags().len() * 8 + 4) / 5 as usize;
		let mut res_u5s: Vec<Fe32> = vec![Fe32::Q; length_u5s];
		for (byte_idx, byte) in self.le_flags().iter().enumerate() {
			let bit_pos_from_left_0_indexed = byte_idx * 8;
			let new_u5_idx = length_u5s - (bit_pos_from_left_0_indexed / 5) as usize - 1;
			let new_bit_pos = bit_pos_from_left_0_indexed % 5;
			let shifted_chunk_u16 = (*byte as u16) << new_bit_pos;
			let curr_u5_as_u8 = res_u5s[new_u5_idx].to_u8();
			res_u5s[new_u5_idx] = Fe32::try_from(curr_u5_as_u8 | ((shifted_chunk_u16 & 0x001f) as u8)).unwrap();
			if new_u5_idx > 0 {
				let curr_u5_as_u8 = res_u5s[new_u5_idx - 1].to_u8();
				res_u5s[new_u5_idx - 1] = Fe32::try_from(curr_u5_as_u8 | (((shifted_chunk_u16 >> 5) & 0x001f) as u8)).unwrap();
			}
			if new_u5_idx > 1 {
				let curr_u5_as_u8 = res_u5s[new_u5_idx - 2].to_u8();
				res_u5s[new_u5_idx - 2] = Fe32::try_from(curr_u5_as_u8 | (((shifted_chunk_u16 >> 10) & 0x001f) as u8)).unwrap();
			}
		}
		// Trim the highest feature bits.
		while !res_u5s.is_empty() && res_u5s[0] == Fe32::Q {
			res_u5s.remove(0);
		}

		Box::new(res_u5s.into_iter())
	}
}

impl Base32Len for Bolt11InvoiceFeatures {
	fn base32_len(&self) -> usize {
		// Here we actually do the conversion
		self.fe_iter().collect::<Vec<Fe32>>().len()
	}
}

/// Calculates the base32 encoded size of a byte slice
fn bytes_size_to_base32_size(byte_size: usize) -> usize {
	let bits = byte_size * 8;
	if bits % 5 == 0 {
		// without padding bits
		bits / 5
	} else {
		// with padding bits
		bits / 5 + 1
	}
}

impl Display for Bolt11Invoice {
	fn fmt(&self, f: &mut Formatter) -> fmt::Result {
		self.signed_invoice.fmt(f)
	}
}

impl Display for SignedRawBolt11Invoice {
	fn fmt(&self, f: &mut Formatter) -> fmt::Result {
		let hrp = self.raw_invoice.hrp.to_hrp();
		for ch in
			self.raw_invoice.data.fe_iter()
			.chain(self.signature.fe_iter())
			.with_checksum::<bech32::Bech32>(&hrp).chars()
		{
			write!(f, "{}", ch)?;
		}
		Ok(())
	}
}

/// This is not exported to bindings users
impl Display for RawHrp {
	fn fmt(&self, f: &mut Formatter) -> fmt::Result {
		let amount = match self.raw_amount {
			Some(ref amt) => amt.to_string(),
			None => String::new(),
		};

		let si_prefix = match self.si_prefix {
			Some(ref si) => si.to_string(),
			None => String::new(),
		};

		write!(
			f,
			"ln{}{}{}",
			self.currency,
			amount,
			si_prefix
		)
	}
}

impl Display for Currency {
	fn fmt(&self, f: &mut Formatter) -> fmt::Result {
		let currency_code = match *self {
			Currency::Bitcoin => "bc",
			Currency::BitcoinTestnet => "tb",
			Currency::Regtest => "bcrt",
			Currency::Simnet => "sb",
			Currency::Signet => "tbs",
		};
		write!(f, "{}", currency_code)
	}
}

impl Display for SiPrefix {
	fn fmt(&self, f: &mut Formatter) -> fmt::Result {
		write!(f, "{}",
			match *self {
				SiPrefix::Milli => "m",
				SiPrefix::Micro => "u",
				SiPrefix::Nano => "n",
				SiPrefix::Pico => "p",
			}
		)
	}
}

/// Encode an integer to base32, big endian, without leading zeros
fn encode_int_be_base32(int: u64) -> Vec<Fe32> {
	let base = 32u64;

	const LEN: usize = (64 + 4) / 5;
	debug_assert!(LEN == 13); // for validating LEN (mutants)
	let mut out_vec = Vec::<Fe32>::with_capacity(LEN);
	let mut rem_int = int;
	while rem_int != 0 {
		out_vec.push(Fe32::try_from((rem_int % base) as u8).expect("always <32"));
		rem_int /= base;
	}

	out_vec.reverse();
	out_vec
}

/// The length of the output of `encode_int_be_base32`.
fn encoded_int_be_base32_size(int: u64) -> usize {
	let bit_len = 64 - int.leading_zeros() as usize; // cast ok as value is in 0..=64.
	(bit_len + 4) / 5
}

impl Base32Iterable for RawDataPart {
	fn fe_iter<'s>(&'s self) -> Box<dyn Iterator<Item = Fe32> + 's> {
		let ts_iter = self.timestamp.fe_iter();
		let fields_iter = self.tagged_fields.iter().map(RawTaggedField::fe_iter).flatten();
		Box::new(ts_iter.chain(fields_iter))
	}
}

impl Base32Iterable for PositiveTimestamp {
	fn fe_iter<'s>(&'s self) -> Box<dyn Iterator<Item = Fe32> + 's> {
		let fes = encode_int_be_base32(self.as_unix_timestamp());
		debug_assert!(fes.len() <= 7, "Invalid timestamp length");
		let to_pad = 7 - fes.len();
		Box::new(core::iter::repeat(Fe32::Q).take(to_pad).chain(fes.into_iter()))
	}
}

impl Base32Iterable for RawTaggedField {
	fn fe_iter<'s>(&'s self) -> Box<dyn Iterator<Item = Fe32> + 's> {
		// Annoyingly, when we move to explicit types, we will need an
		// explicit enum holding the two iterator variants.
		match *self {
			RawTaggedField::UnknownSemantics(ref content) => {
				Box::new(content.iter().copied())
			},
			RawTaggedField::KnownSemantics(ref tagged_field) => tagged_field.fe_iter(),
		}
	}
}

impl Base32Iterable for Sha256 {
	fn fe_iter<'s>(&'s self) -> Box<dyn Iterator<Item = Fe32> + 's> {
		Box::new(self.0[..].fe_iter())
	}
}

impl Base32Len for Sha256 {
	fn base32_len(&self) -> usize {
		self.0[..].base32_len()
	}
}

impl Base32Iterable for Description {
	fn fe_iter<'s>(&'s self) -> Box<dyn Iterator<Item = Fe32> + 's> {
		Box::new(self.0.0.as_bytes().fe_iter())
	}
}

impl Base32Len for Description {
	fn base32_len(&self) -> usize {
		self.0.0.as_bytes().base32_len()
	}
}

impl Base32Iterable for PayeePubKey {
	fn fe_iter<'s>(&'s self) -> Box<dyn Iterator<Item = Fe32> + 's> {
		Box::new(self.serialize().into_iter().bytes_to_fes())
	}
}

impl Base32Len for PayeePubKey {
	fn base32_len(&self) -> usize {
		bytes_size_to_base32_size(bitcoin::secp256k1::constants::PUBLIC_KEY_SIZE)
	}
}

impl Base32Iterable for ExpiryTime {
	fn fe_iter<'s>(&'s self) -> Box<dyn Iterator<Item = Fe32> + 's> {
		Box::new(encode_int_be_base32(self.as_seconds()).into_iter())
	}
}

impl Base32Len for ExpiryTime {
	fn base32_len(&self) -> usize {
		encoded_int_be_base32_size(self.0.as_secs())
	}
}

impl Base32Iterable for MinFinalCltvExpiryDelta {
	fn fe_iter<'s>(&'s self) -> Box<dyn Iterator<Item = Fe32> + 's> {
		Box::new(encode_int_be_base32(self.0).into_iter())
	}
}

impl Base32Len for MinFinalCltvExpiryDelta {
	fn base32_len(&self) -> usize {
		encoded_int_be_base32_size(self.0)
	}
}

impl Base32Iterable for Fallback {
	fn fe_iter<'s>(&'s self) -> Box<dyn Iterator<Item = Fe32> + 's> {
		Box::new(match *self {
			Fallback::SegWitProgram {version: v, program: ref p} => {
				let v = Fe32::try_from(v.to_num()).expect("valid version");
				core::iter::once(v).chain(p[..].fe_iter())
			}
			Fallback::PubKeyHash(ref hash) => {
				// 17 '3'
				core::iter::once(Fe32::_3).chain(hash[..].fe_iter())
			}
			Fallback::ScriptHash(ref hash) => {
				// 18 'J'
				core::iter::once(Fe32::J).chain(hash[..].fe_iter())
			}
		})
	}
}

impl Base32Len for Fallback {
	fn base32_len(&self) -> usize {
		match *self {
			Fallback::SegWitProgram {program: ref p, ..} => {
				bytes_size_to_base32_size(p.len()) + 1
			},
			Fallback::PubKeyHash(_) | Fallback::ScriptHash(_) => {
				33
			},
		}
	}
}

// Shorthand type
type RouteHintHopIter = iter::Chain<iter::Chain<iter::Chain<iter::Chain<array::IntoIter<u8, 33>, array::IntoIter<u8, 8>>, array::IntoIter<u8, 4>>, array::IntoIter<u8, 4>>, array::IntoIter<u8, 2>>;

impl Base32Iterable for PrivateRoute {
	fn fe_iter<'s>(&'s self) -> Box<dyn Iterator<Item = Fe32> + 's> {
		fn serialize_to_iter(hop: &RouteHintHop) -> RouteHintHopIter {
			let i1 = hop.src_node_id.serialize().into_iter();
			let i2 = u64::to_be_bytes(hop.short_channel_id).into_iter();
			let i3 = u32::to_be_bytes(hop.fees.base_msat).into_iter();
			let i4 = u32::to_be_bytes(hop.fees.proportional_millionths).into_iter();
			let i5 = u16::to_be_bytes(hop.cltv_expiry_delta).into_iter();
			i1.chain(i2).chain(i3).chain(i4).chain(i5)
		}

		Box::new(self.0.0.iter().map(serialize_to_iter).flatten().bytes_to_fes())
	}
}

impl Base32Len for PrivateRoute {
	fn base32_len(&self) -> usize {
		bytes_size_to_base32_size((self.0).0.len() * 51)
	}
}

// Shorthand type
type TaggedFieldIter<I> = core::iter::Chain<core::array::IntoIter<Fe32, 3>, I>;

impl Base32Iterable for TaggedField {
	fn fe_iter<'s>(&'s self) -> Box<dyn Iterator<Item = Fe32> + 's> {
		/// Writes a tagged field: tag, length and data. `tag` should be in `0..32` otherwise the
		/// function will panic.
		fn write_tagged_field<'s, P>(tag: u8, payload: &'s P) -> TaggedFieldIter<Box<dyn Iterator<Item = Fe32> + 's>>
			where P: Base32Iterable + Base32Len + ?Sized
		{
			let len = payload.base32_len();
			assert!(len < 1024, "Every tagged field data can be at most 1023 bytes long.");

			[
				Fe32::try_from(tag).expect("invalid tag, not in 0..32"),
				Fe32::try_from((len / 32) as u8).expect("< 32"),
				Fe32::try_from((len % 32) as u8).expect("< 32"),
			].into_iter().chain(payload.fe_iter())
		}

		// we will also need a giant enum for this
		Box::new(match *self {
			TaggedField::PaymentHash(ref hash) => {
				write_tagged_field(constants::TAG_PAYMENT_HASH, hash)
			},
			TaggedField::Description(ref description) => {
				write_tagged_field(constants::TAG_DESCRIPTION, description)
			},
			TaggedField::PayeePubKey(ref pub_key) => {
				write_tagged_field(constants::TAG_PAYEE_PUB_KEY, pub_key)
			},
			TaggedField::DescriptionHash(ref hash) => {
				write_tagged_field(constants::TAG_DESCRIPTION_HASH, hash)
			},
			TaggedField::ExpiryTime(ref duration) => {
				write_tagged_field(constants::TAG_EXPIRY_TIME, duration)
			},
			TaggedField::MinFinalCltvExpiryDelta(ref expiry) => {
				write_tagged_field(constants::TAG_MIN_FINAL_CLTV_EXPIRY_DELTA, expiry)
			},
			TaggedField::Fallback(ref fallback_address) => {
				write_tagged_field(constants::TAG_FALLBACK, fallback_address)
			},
			TaggedField::PrivateRoute(ref route_hops) => {
				write_tagged_field(constants::TAG_PRIVATE_ROUTE, route_hops)
			},
			TaggedField::PaymentSecret(ref payment_secret) => {
				write_tagged_field(constants::TAG_PAYMENT_SECRET, payment_secret)
			},
			TaggedField::PaymentMetadata(ref payment_metadata) => {
				write_tagged_field(constants::TAG_PAYMENT_METADATA, payment_metadata)
			},
			TaggedField::Features(ref features) => {
				write_tagged_field(constants::TAG_FEATURES, features)
			},
		})
	}
}

impl Base32Iterable for Bolt11InvoiceSignature {
	fn fe_iter<'s>(&'s self) -> Box<dyn Iterator<Item = Fe32> + 's> {
		let (recovery_id, signature) = self.0.serialize_compact();
		Box::new(
			signature.into_iter()
				.chain(core::iter::once(recovery_id.to_i32() as u8))
				.bytes_to_fes()
		)
	}
}

#[cfg(test)]
mod test {
	#[test]
	fn test_currency_code() {
		use crate::Currency;

		assert_eq!("bc", Currency::Bitcoin.to_string());
		assert_eq!("tb", Currency::BitcoinTestnet.to_string());
		assert_eq!("bcrt", Currency::Regtest.to_string());
		assert_eq!("sb", Currency::Simnet.to_string());
		assert_eq!("tbs", Currency::Signet.to_string());
	}

	#[test]
	fn test_raw_hrp() {
		use crate::{Currency, RawHrp, SiPrefix};

		let hrp = RawHrp {
			currency: Currency::Bitcoin,
			raw_amount: Some(100),
			si_prefix: Some(SiPrefix::Micro),
		};

		assert_eq!(hrp.to_string(), "lnbc100u");
	}

	#[test]
	fn test_encode_int_be_base32() {
		use crate::ser::encode_int_be_base32;
		use bech32::Fe32;

		let input: u64 = 33764;
		let expected_out = [1, 0, 31, 4].iter().copied().map(|v| Fe32::try_from(v).expect("<= 31")).collect::<Vec<Fe32>>();

		assert_eq!(expected_out, encode_int_be_base32(input));
	}
}
