// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

// Splicing related utilities

use bitcoin::blockdata::transaction::Transaction;
use crate::chain::transaction::OutPoint;
use crate::ln::ChannelId;
use core::convert::TryFrom;

/// Info about a pending splice, used in the pre-splice channel
#[derive(Clone)]
pub(crate) struct PendingSpliceInfoPre {
	/// The post splice value (current + relative)
	pub post_channel_value: u64,
	/// Reference to the post-splice channel (may be missing if channel_id is the same)
	pub post_channel_id: Option<ChannelId>,
	pub funding_feerate_perkw: u32,
	pub locktime: u32,
}

/// Info about a pending splice, used in the post-splice channel
#[derive(Clone)]
pub(crate) struct PendingSpliceInfoPost {
	/// The post splice value (current + relative)
	pub post_channel_value: u64, // TODO may be removed, it's in the channel capacity
	/// The pre splice value (a bit redundant)
	pub pre_channel_value: u64,
	/// Reference to the pre-splice channel (may be missing if channel_id was the same)
	pub pre_channel_id: Option<ChannelId>,

	pub prev_funding_input_index: Option<u16>,

	pub pre_funding_transaction: Option<Transaction>,
	pub pre_funding_txo: Option<OutPoint>,
}

impl PendingSpliceInfoPre {
	pub(crate) fn new(relative_satoshis: i64, pre_channel_value: u64,
		post_channel_id: Option<ChannelId>, funding_feerate_perkw: u32, locktime: u32
	) -> Self {
		let post_channel_value = Self::add_checked(pre_channel_value, relative_satoshis);
		Self {
			post_channel_value,
			post_channel_id,
			funding_feerate_perkw,
			locktime,
		}
	}

	/// Add a u64 and an i64, handling i64 overflow cases (doing without cast to i64)
	pub(crate) fn add_checked(pre_channel_value: u64, relative_satoshis: i64) -> u64 {
		if relative_satoshis >= 0 {
			pre_channel_value.saturating_add(relative_satoshis as u64)
		} else {
			pre_channel_value.saturating_sub((-relative_satoshis) as u64)
		}
	}
}

impl PendingSpliceInfoPost {
	pub(crate) fn new(relative_satoshis: i64, pre_channel_value: u64, pre_channel_id: Option<ChannelId>,
		pre_funding_transaction: Option<Transaction>, pre_funding_txo: Option<OutPoint>
	) -> Self {
		let post_channel_value = PendingSpliceInfoPre::add_checked(pre_channel_value, relative_satoshis);
		Self {
			post_channel_value,
			pre_channel_value,
			pre_channel_id,
			prev_funding_input_index: None,
			pre_funding_transaction,
			pre_funding_txo,
		}
	}

	/// The relative splice value (change in capacity value relative to current value)
	#[cfg(test)]
	pub(crate) fn relative_satoshis(&self) -> i64 {
		if self.post_channel_value > self.pre_channel_value {
			i64::try_from(self.post_channel_value.saturating_sub(self.pre_channel_value)).unwrap_or_default()
		} else {
			-i64::try_from(self.pre_channel_value.saturating_sub(self.post_channel_value)).unwrap_or_default()
		}
	}
}


#[cfg(test)]
mod tests {
	use crate::ln::channel_splice::PendingSpliceInfoPost;

	fn create_pending_splice_info(pre_channel_value: u64, post_channel_value: u64) -> PendingSpliceInfoPost {
		PendingSpliceInfoPost {
			post_channel_value,
			pre_channel_value,
			pre_channel_id: None,
			prev_funding_input_index: None,
			pre_funding_transaction: None,
			pre_funding_txo: None,
		}
	}

	#[test]
	fn test_pending_splice_info_new() {
		{
			// increase, small amounts
			let ps = create_pending_splice_info(9_000, 15_000);
			assert_eq!(ps.pre_channel_value, 9_000);
			assert_eq!(ps.post_channel_value, 15_000);
			assert_eq!(ps.relative_satoshis(), 6_000);
		}
		{
			// decrease, small amounts
			let ps = create_pending_splice_info(15_000, 9_000);
			assert_eq!(ps.pre_channel_value, 15_000);
			assert_eq!(ps.post_channel_value, 9_000);
			assert_eq!(ps.relative_satoshis(), -6_000);
		}
		let base2: u64 = 2;
		let huge63 = base2.pow(63);
		assert_eq!(huge63, 9223372036854775808);
		{
			// increase, one huge amount
			let ps = create_pending_splice_info(9_000, huge63 + 9_000 - 1);
			assert_eq!(ps.pre_channel_value, 9_000);
			assert_eq!(ps.post_channel_value, 9223372036854784807); // 2^63 + 9000 - 1
			assert_eq!(ps.relative_satoshis(), 9223372036854775807); // 2^63 - 1
		}
		{
			// decrease, one huge amount
			let ps = create_pending_splice_info(huge63 + 9_000 - 1, 9_000);
			assert_eq!(ps.pre_channel_value, 9223372036854784807); // 2^63 + 9000 - 1
			assert_eq!(ps.post_channel_value, 9_000);
			assert_eq!(ps.relative_satoshis(), -9223372036854775807); // 2^63 - 1
		}
		{
			// increase, two huge amounts
			let ps = create_pending_splice_info(huge63 + 9_000, huge63 + 15_000);
			assert_eq!(ps.pre_channel_value, 9223372036854784808); // 2^63 + 9000
			assert_eq!(ps.post_channel_value, 9223372036854790808); // 2^63 + 15000
			assert_eq!(ps.relative_satoshis(), 6_000);
		}
		{
			// decrease, two huge amounts
			let ps = create_pending_splice_info(huge63 + 15_000, huge63 + 9_000);
			assert_eq!(ps.pre_channel_value, 9223372036854790808); // 2^63 + 15000
			assert_eq!(ps.post_channel_value, 9223372036854784808); // 2^63 + 9000
			assert_eq!(ps.relative_satoshis(), -6_000);
		}
		{
			// underflow
			let ps = create_pending_splice_info(9_000, huge63 + 9_000 + 20);
			assert_eq!(ps.pre_channel_value, 9_000);
			assert_eq!(ps.post_channel_value, 9223372036854784828); // 2^63 + 9000 + 20
			assert_eq!(ps.relative_satoshis(), -0);
		}
		{
			// underflow
			let ps = create_pending_splice_info(huge63 + 9_000 + 20, 9_000);
			assert_eq!(ps.pre_channel_value, 9223372036854784828); // 2^63 + 9000 + 20
			assert_eq!(ps.post_channel_value, 9_000);
			assert_eq!(ps.relative_satoshis(), -0);
		}
	}
}
