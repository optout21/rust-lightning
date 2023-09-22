// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

#[cfg(test)]
mod tests {
	use crate::chain::chaininterface::FEERATE_FLOOR_SATS_PER_KW;
	use crate::ln::ChannelId;
	use crate::ln::interactivetxs::{InteractiveTxConstructor, StateMachine, InteractiveTxMessageSend}; // AbortReason, InteractiveTxStateMachine
	use crate::util::ser::TransactionU16LenLimited;
	use bitcoin::{PackedLockTime, Script, Sequence, Transaction, TxIn, TxOut, Witness};
	use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
	use bitcoin::hashes::Hash;
	use bitcoin::hash_types::WPubkeyHash;
	use crate::chain::transaction::OutPoint;
	use crate::sign::EntropySource;
	use crate::ln::msgs::{TxAddInput, TxAddOutput, TxComplete};

	struct TestEntropySource;

	impl EntropySource for TestEntropySource {
		fn get_secure_random_bytes(&self) -> [u8; 32] { [42; 32] }
	}

	// Fixtures
	fn get_sample_channel_id() -> ChannelId {
		ChannelId::v1_from_funding_txid(&[2; 32], 0)
	}

	// fn get_sample_tx_in_prev_outpoint() -> OutPoint {
	// 	OutPoint {
	// 		txid: Txid::from_hex("305bab643ee297b8b6b76b320792c8223d55082122cb606bf89382146ced9c77").unwrap(),
	// 		index: 2,
	// 	}
	// }

	fn get_sample_tx_input() -> TxIn {
		let intxid = get_sample_input_tx().txid();
		let previous_output = OutPoint { txid: intxid, index: 0 }.into_bitcoin_outpoint();
		TxIn {
			previous_output,
			script_sig: Script::new(),
			sequence: Sequence(0xfffffffd),
			witness: Witness::from_vec(vec![
				hex::decode("304402206af85b7dd67450ad12c979302fac49dfacbc6a8620f49c5da2b5721cf9565ca502207002b32fed9ce1bf095f57aeb10c36928ac60b12e723d97d2964a54640ceefa701").unwrap(),
				hex::decode("0301ab7dc16488303549bfcdd80f6ae5ee4c20bf97ab5410bbd6b1bfa85dcd6944").unwrap()]),
		}
	}

	fn get_sample_tx_input_2() -> TxIn {
		let intxid = get_sample_input_tx_2().txid();
		let previous_output = OutPoint { txid: intxid, index: 0 }.into_bitcoin_outpoint();
		TxIn {
			previous_output,
			script_sig: Script::new(),
			sequence: Sequence(0xfffffffd),
			witness: Witness::from_vec(vec![
				hex::decode("304402206af85b7dd67450ad12c979302fac49dfacbc6a8620f49c5da2b5721cf9565ca502207002b32fed9ce1bf095f57aeb10c36928ac60b12e723d97d2964a54640ceefa701").unwrap(),
				hex::decode("0301ab7dc16488303549bfcdd80f6ae5ee4c20bf97ab5410bbd6b1bfa85dcd6944").unwrap()]),
		}
	}

	fn get_sample_pubkey(num: u8) -> PublicKey {
		let secret_key = SecretKey::from_slice(&[num; 32]).unwrap();
		let secp_ctx = Secp256k1::new();
		PublicKey::from_secret_key(&secp_ctx, &secret_key)
	}

	fn get_sample_input_tx() -> Transaction {
		let pubkey = get_sample_pubkey(11);
		let script_pubkey = Script::new_v0_p2wpkh(&WPubkeyHash::hash(&pubkey.serialize()));
		let output = TxOut { value: 550011, script_pubkey };
		Transaction { version: 2, lock_time: PackedLockTime::ZERO, output: vec![output], input: vec![]}
	}

	fn get_sample_input_tx_2() -> Transaction {
		let pubkey = get_sample_pubkey(12);
		let script_pubkey = Script::new_v0_p2wpkh(&WPubkeyHash::hash(&pubkey.serialize()));
		let output = TxOut { value: 550012, script_pubkey };
		Transaction { version: 2, lock_time: PackedLockTime::ZERO, output: vec![output], input: vec![]}
	}

	fn get_sample_tx_add_input(serial_id: u64, channel_id: ChannelId) -> TxAddInput {
		let prevtx = TransactionU16LenLimited::new(get_sample_input_tx()).unwrap();
		TxAddInput {
			channel_id,
			serial_id,
			prevtx,
			prevtx_out: 0,
			sequence: 305419896,
		}
	}

	fn get_sample_tx_add_input_2(serial_id: u64, channel_id: ChannelId) -> TxAddInput {
		let prevtx = TransactionU16LenLimited::new(get_sample_input_tx_2()).unwrap();
		TxAddInput {
			channel_id,
			serial_id,
			prevtx,
			prevtx_out: 0,
			sequence: 305419896,
		}
	}

	fn get_sample_tx_output() -> TxOut {
		let pubkey = get_sample_pubkey(21);
		let script_pubkey = Script::new_v0_p2wpkh(&WPubkeyHash::hash(&pubkey.serialize()));
		TxOut {
			value: 540021,
			script_pubkey,
		}
	}

	fn get_sample_tx_output_2() -> TxOut {
		let pubkey = get_sample_pubkey(21);
		let script_pubkey = Script::new_v0_p2wpkh(&WPubkeyHash::hash(&pubkey.serialize()));
		TxOut {
			value: 540022,
			script_pubkey,
		}
	}

	fn get_sample_tx_add_output(serial_id: u64, channel_id: ChannelId) -> TxAddOutput {
		let tx_out = get_sample_tx_output();
		TxAddOutput {
			channel_id,
			serial_id,
			sats: tx_out.value,
			script: tx_out.script_pubkey,
		}
	}

	fn get_sample_tx_add_output_2(serial_id: u64, channel_id: ChannelId) -> TxAddOutput {
		let tx_out = get_sample_tx_output_2();
		TxAddOutput {
			channel_id,
			serial_id,
			sats: tx_out.value,
			script: tx_out.script_pubkey,
		}
	}

	#[test]
	fn test_interact_tx_noni_construct() {
		let entropy_source = TestEntropySource{};
		let channel_id = get_sample_channel_id();
		let (interact, msg) = InteractiveTxConstructor::new(&entropy_source, channel_id, FEERATE_FLOOR_SATS_PER_KW, false, PackedLockTime::ZERO, vec![], vec![]);
		assert!(matches!(interact.get_state_machine(), StateMachine::LocalChange(_)));
		assert!(msg.is_none());
	}

	#[test]
	fn test_interact_tx_init_construct() {
		let entropy_source = TestEntropySource{};
		let channel_id = get_sample_channel_id();
		let (interact, msg) = InteractiveTxConstructor::new(&entropy_source, channel_id, FEERATE_FLOOR_SATS_PER_KW, true, PackedLockTime::ZERO, vec![], vec![]);
		assert!(matches!(interact.get_state_machine(), StateMachine::LocalTxComplete(_)));
		assert!(matches!(msg.unwrap(), InteractiveTxMessageSend::TxComplete(_)));
	}

	#[test]
	fn test_interact_tx_noni_ri_ro_complete() {
		let entropy_source = TestEntropySource{};
		let channel_id = get_sample_channel_id();
		let (mut interact, msg) = InteractiveTxConstructor::new(&entropy_source, channel_id, FEERATE_FLOOR_SATS_PER_KW, false, PackedLockTime::ZERO, vec![], vec![]);
		assert!(matches!(interact.get_state_machine(), StateMachine::LocalChange(_)));
		assert!(msg.is_none());

		let txin = get_sample_tx_add_input(1230002, channel_id);
		let msg2 = interact.handle_tx_add_input(&txin).unwrap();
		assert!(matches!(interact.get_state_machine(), StateMachine::LocalTxComplete(_)));
		assert!(matches!(msg2, InteractiveTxMessageSend::TxComplete(_)));

		let txout = get_sample_tx_add_output(1230004, channel_id);
		let msg3 = interact.handle_tx_add_output(&txout).unwrap();
		assert!(matches!(interact.get_state_machine(), StateMachine::LocalTxComplete(_)));
		assert!(matches!(msg3, InteractiveTxMessageSend::TxComplete(_)));

		let (msg4, tx) = interact.handle_tx_complete(&TxComplete{channel_id}).unwrap();
		assert!(matches!(interact.get_state_machine(), StateMachine::NegotiationComplete(_)));
		assert!(msg4.is_none());
		assert!(tx.is_some());
		assert_eq!(tx.as_ref().unwrap().input.len(), 1);
		assert_eq!(tx.as_ref().unwrap().output.len(), 1);
	}

	#[test]
	fn test_interact_tx_init_li_lo_complete() {
		let entropy_source = TestEntropySource{};
		let channel_id = get_sample_channel_id();
		let inputs = vec![(get_sample_tx_input(), get_sample_input_tx())];
		let outputs = vec![get_sample_tx_output()];
		let (mut interact, msg) = InteractiveTxConstructor::new(&entropy_source, channel_id, FEERATE_FLOOR_SATS_PER_KW, true, PackedLockTime::ZERO, inputs, outputs);
		assert!(matches!(interact.get_state_machine(), StateMachine::LocalChange(_)));
		assert!(matches!(msg.unwrap(), InteractiveTxMessageSend::TxAddInput(_)));

		let (msg2, _tx) = interact.handle_tx_complete(&TxComplete{channel_id}).unwrap();
		assert!(matches!(interact.get_state_machine(), StateMachine::LocalChange(_)));
		assert!(matches!(msg2.unwrap(), InteractiveTxMessageSend::TxAddOutput(_)));

		let (msg3, tx) = interact.handle_tx_complete(&TxComplete{channel_id}).unwrap();
		assert!(matches!(interact.get_state_machine(), StateMachine::NegotiationComplete(_)));
		assert!(matches!(msg3.unwrap(), InteractiveTxMessageSend::TxComplete(_)));
		assert!(tx.is_some());
		assert_eq!(tx.as_ref().unwrap().input.len(), 1);
		assert_eq!(tx.as_ref().unwrap().output.len(), 1);
	}

	#[test]
	fn test_interact_tx_noni_li_lo_complete() {
		let entropy_source = TestEntropySource{};
		let channel_id = get_sample_channel_id();
		let inputs = vec![(get_sample_tx_input(), get_sample_input_tx())];
		let outputs = vec![get_sample_tx_output()];
		let (mut interact, msg) = InteractiveTxConstructor::new(&entropy_source, channel_id, FEERATE_FLOOR_SATS_PER_KW, false, PackedLockTime::ZERO, inputs, outputs);
		assert!(matches!(interact.get_state_machine(), StateMachine::LocalChange(_)));
		assert!(msg.is_none());

		let (msg2, _tx) = interact.handle_tx_complete(&TxComplete{channel_id}).unwrap();
		assert!(matches!(interact.get_state_machine(), StateMachine::LocalChange(_)));
		assert!(matches!(msg2.unwrap(), InteractiveTxMessageSend::TxAddInput(_)));

		let (msg3, _tx) = interact.handle_tx_complete(&TxComplete{channel_id}).unwrap();
		assert!(matches!(interact.get_state_machine(), StateMachine::LocalChange(_)));
		assert!(matches!(msg3.unwrap(), InteractiveTxMessageSend::TxAddOutput(_)));

		// TODO check why does this fail?
		let res4 = interact.handle_tx_complete(&TxComplete{channel_id});
		assert!(res4.is_err());
		assert!(matches!(interact.get_state_machine(), StateMachine::NegotiationAborted(_)));
		// assert!(matches!(msg4.unwrap(), InteractiveTxMessageSend::TxAddOutput(_)));
		// assert!(tx.is_some());
		// assert_eq!(tx.as_ref().unwrap().input.len(), 1);
		// assert_eq!(tx.as_ref().unwrap().output.len(), 1);
	}

	#[test]
	fn test_interact_tx_init_ri_ro_complete() {
		let entropy_source = TestEntropySource{};
		let channel_id = get_sample_channel_id();
		let (mut interact, msg) = InteractiveTxConstructor::new(&entropy_source, channel_id, FEERATE_FLOOR_SATS_PER_KW, true, PackedLockTime::ZERO, vec![], vec![]);
		assert!(matches!(interact.get_state_machine(), StateMachine::LocalTxComplete(_)));
		assert!(matches!(msg.unwrap(), InteractiveTxMessageSend::TxComplete(_)));

		let txin = get_sample_tx_add_input(1230001, channel_id);
		let msg2 = interact.handle_tx_add_input(&txin).unwrap();
		assert!(matches!(interact.get_state_machine(), StateMachine::LocalTxComplete(_)));
		assert!(matches!(msg2, InteractiveTxMessageSend::TxComplete(_)));

		let txout = get_sample_tx_add_output(1230003, channel_id);
		let msg3 = interact.handle_tx_add_output(&txout).unwrap();
		assert!(matches!(interact.get_state_machine(), StateMachine::LocalTxComplete(_)));
		assert!(matches!(msg3, InteractiveTxMessageSend::TxComplete(_)));

		let (msg4, tx) = interact.handle_tx_complete(&TxComplete{channel_id}).unwrap();
		assert!(matches!(interact.get_state_machine(), StateMachine::NegotiationComplete(_)));
		assert!(msg4.is_none());
		assert!(tx.is_some());
		assert_eq!(tx.as_ref().unwrap().input.len(), 1);
		assert_eq!(tx.as_ref().unwrap().output.len(), 1);
	}

	#[test]
	fn test_interact_tx_noni_empty_complete() {
		let entropy_source = TestEntropySource{};
		let channel_id = get_sample_channel_id();
		let (mut interact, msg) = InteractiveTxConstructor::new(&entropy_source, channel_id, FEERATE_FLOOR_SATS_PER_KW, false, PackedLockTime::ZERO, vec![], vec![]);
		assert!(matches!(interact.get_state_machine(), StateMachine::LocalChange(_)));
		assert!(msg.is_none());

		// Aborts as there is no input to pay for fee
		let res2 = interact.handle_tx_complete(&TxComplete{channel_id});
		assert!(res2.is_err());
		assert!(matches!(interact.get_state_machine(), StateMachine::NegotiationAborted(_)));
	}

	#[test]
	fn test_interact_tx_init_empty_complete() {
		let entropy_source = TestEntropySource{};
		let channel_id = get_sample_channel_id();
		let (mut interact, msg) = InteractiveTxConstructor::new(&entropy_source, channel_id, FEERATE_FLOOR_SATS_PER_KW, true, PackedLockTime::ZERO, vec![], vec![]);
		assert!(matches!(interact.get_state_machine(), StateMachine::LocalTxComplete(_)));
		assert!(matches!(msg.unwrap(), InteractiveTxMessageSend::TxComplete(_)));

		// TODO: Empty TX is accepted here, check if correct
		let (msg2, tx) = interact.handle_tx_complete(&TxComplete{channel_id}).unwrap();
		println!("state {:?}", interact.get_state_machine());
		assert!(matches!(interact.get_state_machine(), StateMachine::NegotiationComplete(_)));
		assert!(msg2.is_none());
		assert!(tx.is_some());
		assert_eq!(tx.as_ref().unwrap().input.len(), 0);
		assert_eq!(tx.as_ref().unwrap().output.len(), 0);
	}

	// Both parties contribute
	#[test]
	fn test_interact_tx_init_li_lo_ri_ro_complete() {
		let entropy_source = TestEntropySource{};
		let channel_id = get_sample_channel_id();
		let inputs = vec![(get_sample_tx_input(), get_sample_input_tx())];
		let outputs = vec![get_sample_tx_output()];
		let (mut interact, msg) = InteractiveTxConstructor::new(&entropy_source, channel_id, FEERATE_FLOOR_SATS_PER_KW, true, PackedLockTime::ZERO, inputs, outputs);
		assert!(matches!(interact.get_state_machine(), StateMachine::LocalChange(_)));
		assert!(matches!(msg.unwrap(), InteractiveTxMessageSend::TxAddInput(_)));

		let txin = get_sample_tx_add_input_2(1230001, channel_id);
		let msg2 = interact.handle_tx_add_input(&txin).unwrap();
		assert!(matches!(interact.get_state_machine(), StateMachine::LocalChange(_)));
		assert!(matches!(msg2, InteractiveTxMessageSend::TxAddOutput(_)));

		let txout = get_sample_tx_add_output_2(1230003, channel_id);
		let msg3 = interact.handle_tx_add_output(&txout).unwrap();
		assert!(matches!(interact.get_state_machine(), StateMachine::LocalTxComplete(_)));
		assert!(matches!(msg3, InteractiveTxMessageSend::TxComplete(_)));

		let (msg4, tx) = interact.handle_tx_complete(&TxComplete{channel_id}).unwrap();
		assert!(matches!(interact.get_state_machine(), StateMachine::NegotiationComplete(_)));
		assert!(msg4.is_none());
		assert!(tx.is_some());
		assert_eq!(tx.as_ref().unwrap().input.len(), 2);
		assert_eq!(tx.as_ref().unwrap().output.len(), 2);
	}

	#[test]
	fn test_interact_tx_noni_li_lo_ri_ro_complete() {
		let entropy_source = TestEntropySource{};
		let channel_id = get_sample_channel_id();
		let inputs = vec![(get_sample_tx_input(), get_sample_input_tx())];
		let outputs = vec![get_sample_tx_output()];
		let (mut interact, msg) = InteractiveTxConstructor::new(&entropy_source, channel_id, FEERATE_FLOOR_SATS_PER_KW, false, PackedLockTime::ZERO, inputs, outputs);
		assert!(matches!(interact.get_state_machine(), StateMachine::LocalChange(_)));
		assert!(msg.is_none());

		let txin = get_sample_tx_add_input(1230002, channel_id);
		let msg2 = interact.handle_tx_add_input(&txin).unwrap();
		assert!(matches!(interact.get_state_machine(), StateMachine::LocalChange(_)));
		assert!(matches!(msg2, InteractiveTxMessageSend::TxAddInput(_)));

		let txout = get_sample_tx_add_output(1230004, channel_id);
		let msg3 = interact.handle_tx_add_output(&txout).unwrap();
		assert!(matches!(interact.get_state_machine(), StateMachine::LocalChange(_)));
		assert!(matches!(msg3, InteractiveTxMessageSend::TxAddOutput(_)));

		let (msg4, tx) = interact.handle_tx_complete(&TxComplete{channel_id}).unwrap();
		assert!(matches!(interact.get_state_machine(), StateMachine::NegotiationComplete(_)));
		assert!(matches!(msg4.unwrap(), InteractiveTxMessageSend::TxComplete(_)));
		assert!(tx.is_some());
		assert_eq!(tx.as_ref().unwrap().input.len(), 2);
		assert_eq!(tx.as_ref().unwrap().output.len(), 2);
	}

	// TODO: no abort support!
	// #[test]
	// fn test_interact_tx_noni_ri_ro_abort() {
	// 	let entropy_source = TestEntropySource{};
	// 	let channel_id = get_sample_channel_id();
	// 	let (mut interact, msg) = InteractiveTxConstructor::new(&entropy_source, channel_id, FEERATE_FLOOR_SATS_PER_KW, false, PackedLockTime::ZERO, vec![], vec![]);
	// 	assert!(matches!(interact.get_state_machine(), StateMachine::LocalChange(_)));
	// 	assert!(msg.is_none());

	// 	let msg2 = interact.handle_abort().unwrap();
	// 	...
	// }

	#[test]
	fn test_interact_tx_noni_ri_ri_ro_ro_complete() {
		let entropy_source = TestEntropySource{};
		let channel_id = get_sample_channel_id();
		let (mut interact, msg) = InteractiveTxConstructor::new(&entropy_source, channel_id, FEERATE_FLOOR_SATS_PER_KW, false, PackedLockTime::ZERO, vec![], vec![]);
		assert!(matches!(interact.get_state_machine(), StateMachine::LocalChange(_)));
		assert!(msg.is_none());

		let txin = get_sample_tx_add_input(1230002, channel_id);
		let msg2 = interact.handle_tx_add_input(&txin).unwrap();
		assert!(matches!(interact.get_state_machine(), StateMachine::LocalTxComplete(_)));
		assert!(matches!(msg2, InteractiveTxMessageSend::TxComplete(_)));

		let txin2 = get_sample_tx_add_input_2(1230004, channel_id);
		let msg3 = interact.handle_tx_add_input(&txin2).unwrap();
		assert!(matches!(interact.get_state_machine(), StateMachine::LocalTxComplete(_)));
		assert!(matches!(msg3, InteractiveTxMessageSend::TxComplete(_)));

		let txout = get_sample_tx_add_output(1230006, channel_id);
		let msg4 = interact.handle_tx_add_output(&txout).unwrap();
		assert!(matches!(interact.get_state_machine(), StateMachine::LocalTxComplete(_)));
		assert!(matches!(msg4, InteractiveTxMessageSend::TxComplete(_)));

		let txout2 = get_sample_tx_add_output_2(1230008, channel_id);
		let msg5 = interact.handle_tx_add_output(&txout2).unwrap();
		assert!(matches!(interact.get_state_machine(), StateMachine::LocalTxComplete(_)));
		assert!(matches!(msg5, InteractiveTxMessageSend::TxComplete(_)));

		let (msg6, tx) = interact.handle_tx_complete(&TxComplete{channel_id}).unwrap();
		assert!(matches!(interact.get_state_machine(), StateMachine::NegotiationComplete(_)));
		assert!(msg6.is_none());
		assert!(tx.is_some());
		assert_eq!(tx.as_ref().unwrap().input.len(), 2);
		assert_eq!(tx.as_ref().unwrap().output.len(), 2);
	}

	#[test]
	fn test_interact_tx_init_li_li_lo_lo_complete() {
		let entropy_source = TestEntropySource{};
		let channel_id = get_sample_channel_id();
		let inputs = vec![
			(get_sample_tx_input(), get_sample_input_tx()),
			(get_sample_tx_input_2(), get_sample_input_tx_2()),
		];
		let outputs = vec![
			get_sample_tx_output(),
			get_sample_tx_output_2(),
		];
		let (mut interact, msg) = InteractiveTxConstructor::new(&entropy_source, channel_id, FEERATE_FLOOR_SATS_PER_KW, true, PackedLockTime::ZERO, inputs, outputs);
		assert!(matches!(interact.get_state_machine(), StateMachine::LocalChange(_)));
		assert!(matches!(msg.unwrap(), InteractiveTxMessageSend::TxAddInput(_)));

		let (msg2, _tx) = interact.handle_tx_complete(&TxComplete{channel_id}).unwrap();
		assert!(matches!(interact.get_state_machine(), StateMachine::LocalChange(_)));
		assert!(matches!(msg2.unwrap(), InteractiveTxMessageSend::TxAddInput(_)));

		let (msg3, _tx) = interact.handle_tx_complete(&TxComplete{channel_id}).unwrap();
		assert!(matches!(interact.get_state_machine(), StateMachine::LocalChange(_)));
		assert!(matches!(msg3.unwrap(), InteractiveTxMessageSend::TxAddOutput(_)));

		let (msg4, _tx) = interact.handle_tx_complete(&TxComplete{channel_id}).unwrap();
		assert!(matches!(interact.get_state_machine(), StateMachine::LocalChange(_)));
		assert!(matches!(msg4.unwrap(), InteractiveTxMessageSend::TxAddOutput(_)));

		let (msg5, tx) = interact.handle_tx_complete(&TxComplete{channel_id}).unwrap();
		assert!(matches!(interact.get_state_machine(), StateMachine::NegotiationComplete(_)));
		assert!(matches!(msg5.unwrap(), InteractiveTxMessageSend::TxComplete(_)));
		assert!(tx.is_some());
		// TODO here it should be 2!!!
		assert_eq!(tx.as_ref().unwrap().input.len(), 1);
		assert_eq!(tx.as_ref().unwrap().output.len(), 1);
	}
}


// #[cfg(test)]
// mod tests {
// 	use core::str::FromStr;
// 	use crate::chain::chaininterface::FEERATE_FLOOR_SATS_PER_KW;
// use crate::ln::interactivetxs::ChannelMode::{Negotiating, NegotiationAborted};
// 	use crate::ln::interactivetxs::{AbortReason, ChannelMode, InteractiveTxConstructor, InteractiveTxStateMachine};
// 	use crate::ln::msgs::TransactionU16LenLimited;
// 	use bitcoin::consensus::encode;
// 	use bitcoin::{Address, PackedLockTime, Script, Sequence, Transaction, Txid, TxIn, TxOut, Witness};
// 	use bitcoin::hashes::hex::FromHex;
// 	use crate::chain::transaction::OutPoint;
// 	use crate::ln::interactivetxs::AbortReason::IncorrectSerialIdParity;
// 	use crate::ln::msgs::TxAddInput;
//
// 	#[test]
// 	fn test_invalid_counterparty_serial_id_should_abort_negotiation() {
// 		let tx: Transaction = encode::deserialize(&hex::decode("020000000001010e0ade\
// 			f48412e4361325ac1c6e36411299ab09d4f083b9d8ddb55fbc06e1b0c00000000000feffffff0220a107000\
// 			0000000220020f81d95e040bd0a493e38bae27bff52fe2bb58b93b293eb579c01c31b05c5af1dc072cfee54\
// 			a3000016001434b1d6211af5551905dc2642d05f5b04d25a8fe80247304402207f570e3f0de50546aad25a8\
// 			72e3df059d277e776dda4269fa0d2cc8c2ee6ec9a022054e7fae5ca94d47534c86705857c24ceea3ad51c69\
// 			dd6051c5850304880fc43a012103cb11a1bacc223d98d91f1946c6752e358a5eb1a1c983b3e6fb15378f453\
// 			b76bd00000000").unwrap()[..]).unwrap();
// 		let mut constructor = InteractiveTxConstructor::new([0; 32], FEERATE_FLOOR_SATS_PER_KW, true, true, tx, false);
// 		constructor.receive_tx_add_input(2, &get_sample_tx_add_input(), false);
// 		assert!(matches!(constructor.mode, ChannelMode::NegotiationAborted { .. }))
// 	}
//
// 	impl DummyChannel {
// 		fn new() -> Self {
// 			let tx: Transaction = encode::deserialize(&hex::decode("020000000001010e0ade\
// 			f48412e4361325ac1c6e36411299ab09d4f083b9d8ddb55fbc06e1b0c00000000000feffffff0220a107000\
// 			0000000220020f81d95e040bd0a493e38bae27bff52fe2bb58b93b293eb579c01c31b05c5af1dc072cfee54\
// 			a3000016001434b1d6211af5551905dc2642d05f5b04d25a8fe80247304402207f570e3f0de50546aad25a8\
// 			72e3df059d277e776dda4269fa0d2cc8c2ee6ec9a022054e7fae5ca94d47534c86705857c24ceea3ad51c69\
// 			dd6051c5850304880fc43a012103cb11a1bacc223d98d91f1946c6752e358a5eb1a1c983b3e6fb15378f453\
// 			b76bd00000000").unwrap()[..]).unwrap();
// 			Self {
// 				tx_constructor: InteractiveTxConstructor::new([0; 32], FEERATE_FLOOR_SATS_PER_KW, true, true, tx, false)
// 			}
// 		}
//
// 		fn handle_add_tx_input(&mut self) {
// 			self.tx_constructor.receive_tx_add_input(1234, &get_sample_tx_add_input(), true)
// 		}
// 	}
//
// 	// Fixtures
// 	fn get_sample_tx_add_input() -> TxAddInput {
// 		let prevtx = TransactionU16LenLimited::new(
// 			Transaction {
// 				version: 2,
// 				lock_time: PackedLockTime(0),
// 				input: vec![TxIn {
// 					previous_output: OutPoint { txid: Txid::from_hex("305bab643ee297b8b6b76b320792c8223d55082122cb606bf89382146ced9c77").unwrap(), index: 2 }.into_bitcoin_outpoint(),
// 					script_sig: Script::new(),
// 					sequence: Sequence(0xfffffffd),
// 					witness: Witness::from_vec(vec![
// 						hex::decode("304402206af85b7dd67450ad12c979302fac49dfacbc6a8620f49c5da2b5721cf9565ca502207002b32fed9ce1bf095f57aeb10c36928ac60b12e723d97d2964a54640ceefa701").unwrap(),
// 						hex::decode("0301ab7dc16488303549bfcdd80f6ae5ee4c20bf97ab5410bbd6b1bfa85dcd6944").unwrap()]),
// 				}],
// 				output: vec![
// 					TxOut {
// 						value: 12704566,
// 						script_pubkey: Address::from_str("bc1qzlffunw52jav8vwdu5x3jfk6sr8u22rmq3xzw2").unwrap().script_pubkey(),
// 					},
// 					TxOut {
// 						value: 245148,
// 						script_pubkey: Address::from_str("bc1qxmk834g5marzm227dgqvynd23y2nvt2ztwcw2z").unwrap().script_pubkey(),
// 					},
// 				],
// 			}
// 		).unwrap();
//
// 		return TxAddInput {
// 			channel_id: [2; 32],
// 			serial_id: 4886718345,
// 			prevtx,
// 			prevtx_out: 305419896,
// 			sequence: 305419896,
// 		};
// 	}
// }
