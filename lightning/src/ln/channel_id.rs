// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use crate::ln::msgs::DecodeError;
use crate::sign::EntropySource;
use crate::util::ser::{Readable, Writeable, Writer};

use bitcoin::hashes::hex::ToHex;

use crate::io;
use crate::prelude::*;
use core::fmt;
use core::ops::Deref;


/// A unique 32-byte identifier for a channel.
/// Depending on how the ID is generated, several varieties are distinguished (but all are stored as 32 bytes):
/// - v1: generated based on funding tx outpoint (txid&index)
/// - temporary: generated randomly
/// (later planned v2: based on revocation point)
/// The variety (context) is not stored, it is relevant only at creation.
/// This is not exported to bindings users as we just use [u8; 32] directly
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ChannelId {
	// The 32-byte data of the ID
	data: [u8; 32],
}

impl ChannelId {
	/// Create v1 channel ID based on a funding TX ID and output index
	pub fn v1_from_funding_txid(txid: &[u8; 32], output_index: u16) -> Self {
		let mut res = [0; 32];
		res[..].copy_from_slice(&txid[..]);
		res[30] ^= ((output_index >> 8) & 0xff) as u8;
		res[31] ^= ((output_index >> 0) & 0xff) as u8;
		Self::from_bytes(res)
	}

	/// Create a temporary channel ID randomly, based on an entropy source.
	pub fn temporary_from_entropy_source<ES: Deref>(entropy_source: &ES) -> Self
	where ES::Target: EntropySource {
		Self::from_bytes(entropy_source.get_secure_random_bytes())
	}

	/// Generic constructor; create a new channel ID from the provided data.
	/// Use a more specific *from_* constructor when possible.
	/// This constructor is useful for tests, and internally, e.g. when the channel ID is being deserialized.
	pub fn from_bytes(data: [u8; 32]) -> Self {
		Self{data}
	}

	/// Create a channel ID consisting of all-zeros data (placeholder).
	pub fn new_zero() -> Self {
		Self::from_bytes([0; 32])
	}

	/// Accessor for the channel ID data
	pub fn bytes(&self) -> &[u8; 32] {
		&self.data
	}
}

impl Writeable for ChannelId {
	fn write<W: Writer>(&self, w: &mut W) -> Result<(), io::Error> {
		self.data.write(w)
	}
}

impl Readable for ChannelId {
	fn read<R: io::Read>(r: &mut R) -> Result<Self, DecodeError> {
		let buf: [u8; 32] = Readable::read(r)?;
		Ok(ChannelId::from_bytes(buf))
	}
}

impl ToHex for ChannelId {
	fn to_hex(&self) -> String {
		self.data.to_hex()
	}
}

impl fmt::Display for ChannelId {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		crate::util::logger::DebugBytes(&self.data).fmt(f)
	}
}

#[cfg(test)]
mod tests {
	use crate::ln::ChannelId;
	use crate::util::ser::{Readable, Writeable};
	use crate::util::test_utils;
	use bitcoin::hashes::hex::ToHex;
	use crate::prelude::*;
	use crate::io;

	#[test]
	fn test_channel_id_new_from_data() {
		let data: [u8; 32] = [2; 32];
		let channel_id = ChannelId::from_bytes(data.clone());
		assert_eq!(*channel_id.bytes(), data);
	}

	#[test]
	fn test_channel_id_from_funding_tx2() {
		let channel_id = ChannelId::v1_from_funding_txid(&[2; 32], 1);
		assert_eq!(channel_id.to_hex(), "0202020202020202020202020202020202020202020202020202020202020203");
	}

	#[test]
	fn test_channel_id_equals() {
		let channel_id11 = ChannelId::v1_from_funding_txid(&[2; 32], 2);
		let channel_id12 = ChannelId::v1_from_funding_txid(&[2; 32], 2);
		let channel_id21 = ChannelId::v1_from_funding_txid(&[2; 32], 42);
		assert_eq!(channel_id11, channel_id12);
		assert_ne!(channel_id11, channel_id21);
	}

	#[test]
	fn test_channel_id_write_read() {
		let data: [u8; 32] = [2; 32];
		let channel_id = ChannelId::from_bytes(data.clone());

		let mut w = test_utils::TestVecWriter(Vec::new());
		channel_id.write(&mut w).unwrap();

		let channel_id_2 = ChannelId::read(&mut io::Cursor::new(&w.0)).unwrap();
		assert_eq!(channel_id_2, channel_id);
		assert_eq!(channel_id_2.bytes(), &data);
	}

	#[test]
	fn test_channel_id_display() {
		let channel_id = ChannelId::from_bytes([42; 32]);
		assert_eq!(format!("{}", &channel_id), "2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a");
	}
}
