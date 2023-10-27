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
	use crate::chain::transaction::OutPoint;
	use crate::ln::interactivetxs::{AbortReason, InteractiveTxConstructor, InteractiveTxMessageSend, StateMachine};
	use crate::ln::msgs::{SerialId, TxAddInput, TxAddOutput, TxComplete, TxRemoveInput, TxRemoveOutput};
	use crate::ln::ChannelId;
	use crate::sign::EntropySource;
	use crate::util::atomic_counter::AtomicCounter;
	use crate::util::chacha20::ChaCha20;
	use crate::util::ser::TransactionU16LenLimited;
	use bitcoin::hash_types::WPubkeyHash;
	use bitcoin::hashes::Hash;
	use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
	use bitcoin::{PackedLockTime, Script, Sequence, Transaction, TxIn, TxOut, Witness};

	// Fixtures

	/// Returns pseudo-random data
	/// TODO: Maybe this could be moved to test_utils?
	struct TestEntropySource {
		/// Tracks the number of times we've produced randomness to ensure we don't return the same bytes twice.
		rand_bytes_index: AtomicCounter,
	}

	impl TestEntropySource {
		fn new() -> Self {
			Self { rand_bytes_index: AtomicCounter::new() }
		}
	}

	impl EntropySource for TestEntropySource {
		fn get_secure_random_bytes(&self) -> [u8; 32] {
			let index = self.rand_bytes_index.get_increment();
			let mut nonce = [0u8; 16];
			nonce[..8].copy_from_slice(&index.to_be_bytes());
			ChaCha20::get_single_block(&[42; 32], &nonce)
		}
	}

	fn get_sample_channel_id() -> ChannelId {
		ChannelId::v1_from_funding_txid(&[2; 32], 0)
	}

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

	fn get_sample_input_tx_intern(pubkey: PublicKey, value: u64) -> Transaction {
		let script_pubkey = Script::new_v0_p2wpkh(&WPubkeyHash::hash(&pubkey.serialize()));
		let output = TxOut { value, script_pubkey };
		Transaction { version: 2, lock_time: PackedLockTime::ZERO, output: vec![output], input: vec![] }
	}

	fn get_sample_input_tx() -> Transaction {
		get_sample_input_tx_intern(get_sample_pubkey(11), 550011)
	}

	fn get_sample_input_tx_2() -> Transaction {
		get_sample_input_tx_intern(get_sample_pubkey(12), 550012)
	}

	fn get_sample_input_tx_3() -> Transaction {
		get_sample_input_tx_intern(get_sample_pubkey(13), 550013)
	}

	fn get_sample_tx_add_input_intern(
		serial_id: u64, channel_id: ChannelId, prevtx: TransactionU16LenLimited,
	) -> TxAddInput {
		TxAddInput { channel_id, serial_id, prevtx, prevtx_out: 0, sequence: 305419896 }
	}

	fn get_sample_tx_add_input(serial_id: u64, channel_id: ChannelId) -> TxAddInput {
		get_sample_tx_add_input_intern(
			serial_id,
			channel_id,
			TransactionU16LenLimited::new(get_sample_input_tx()).unwrap(),
		)
	}

	fn get_sample_tx_add_input_2(serial_id: u64, channel_id: ChannelId) -> TxAddInput {
		get_sample_tx_add_input_intern(
			serial_id,
			channel_id,
			TransactionU16LenLimited::new(get_sample_input_tx_2()).unwrap(),
		)
	}

	fn get_sample_tx_add_input_3(serial_id: u64, channel_id: ChannelId) -> TxAddInput {
		get_sample_tx_add_input_intern(
			serial_id,
			channel_id,
			TransactionU16LenLimited::new(get_sample_input_tx_3()).unwrap(),
		)
	}

	fn get_sample_tx_output() -> TxOut {
		let pubkey = get_sample_pubkey(21);
		let script_pubkey = Script::new_v0_p2wpkh(&WPubkeyHash::hash(&pubkey.serialize()));
		TxOut { value: 540021, script_pubkey }
	}

	fn get_sample_tx_output_2() -> TxOut {
		let pubkey = get_sample_pubkey(21);
		let script_pubkey = Script::new_v0_p2wpkh(&WPubkeyHash::hash(&pubkey.serialize()));
		TxOut { value: 540022, script_pubkey }
	}

	fn get_sample_tx_add_output(serial_id: u64, channel_id: ChannelId) -> TxAddOutput {
		let tx_out = get_sample_tx_output();
		TxAddOutput { channel_id, serial_id, sats: tx_out.value, script: tx_out.script_pubkey }
	}

	fn get_sample_tx_add_output_2(serial_id: u64, channel_id: ChannelId) -> TxAddOutput {
		let tx_out = get_sample_tx_output_2();
		TxAddOutput { channel_id, serial_id, sats: tx_out.value, script: tx_out.script_pubkey }
	}

	// Use shortened names here, InvHM for InvokeHandleMethod
	#[derive(Debug)]
	enum InvHM {
		AddI(TxAddInput),     // AddInput
		AddO(TxAddOutput),    // AddOutput
		Comp(ChannelId),      // Complete
		RemI(TxRemoveInput),  // RemoveInput
		RemO(TxRemoveOutput), // RemoveOutput
	}

	impl InvHM {
		fn do_invoke(
			&self, interact_tx: &mut InteractiveTxConstructor,
		) -> Result<(Option<InteractiveTxMessageSend>, Option<Transaction>), AbortReason> {
			match self {
				InvHM::AddI(txai) => {
					let msg = interact_tx.handle_tx_add_input(txai)?;
					Ok((Some(msg), None))
				}
				InvHM::AddO(txao) => {
					let msg = interact_tx.handle_tx_add_output(txao)?;
					Ok((Some(msg), None))
				}
				InvHM::Comp(channel_id) => interact_tx.handle_tx_complete(&TxComplete { channel_id: *channel_id }),
				InvHM::RemI(txri) => {
					let msg = interact_tx.handle_tx_remove_input(txri)?;
					Ok((Some(msg), None))
				}
				InvHM::RemO(txro) => {
					let msg = interact_tx.handle_tx_remove_output(txro)?;
					Ok((Some(msg), None))
				}
			}
		}
	}

	// Use shortened names here, ExSt for ExpectedState
	#[derive(Debug)]
	enum ExSt {
		LocalCh, // LocalChange
		// RemoteCh,   // RemoteChange
		LocalComp, // LocalComplete
		// RemoteComp, // RemoteComplete
		NegComp, // NegotiationComplete
		NegAb,   // NegotiationAborted
	}

	impl ExSt {
		fn match_state(&self, state: &StateMachine) {
			println!("Current state: {:?}", state);
			match self {
				ExSt::LocalCh => {
					assert!(matches!(state, StateMachine::LocalChange(_)))
				}
				// ExSt::RemoteCh => {
				// 	assert!(matches!(state, StateMachine::RemoteChange(_)))
				// }
				ExSt::LocalComp => {
					assert!(matches!(state, StateMachine::LocalTxComplete(_)))
				}
				// ExSt::RemoteComp => {
				// 	assert!(matches!(state, StateMachine::RemoteTxComplete(_)))
				// }
				ExSt::NegComp => {
					assert!(matches!(state, StateMachine::NegotiationComplete(_)))
				}
				ExSt::NegAb => {
					assert!(matches!(state, StateMachine::NegotiationAborted(_)))
				}
			}
		}
	}

	#[derive(Debug)]
	enum ExMsg {
		AddI, // TxAddInput
		AddO, // TxAddOutput
		Comp, // TxComplete
	}

	impl ExMsg {
		/// Verify the actual message against the expected.
		/// For messages with serialId, also verify the parity.
		fn match_msg(&self, msg: &Option<InteractiveTxMessageSend>, is_initiator: bool) {
			match msg.as_ref().unwrap() {
				InteractiveTxMessageSend::TxAddInput(txai) => {
					assert!(matches!(self, ExMsg::AddI));
					self.check_serial_id(txai.serial_id, is_initiator);
				}
				InteractiveTxMessageSend::TxAddOutput(txao) => {
					assert!(matches!(self, ExMsg::AddO));
					self.check_serial_id(txao.serial_id, is_initiator);
				}
				InteractiveTxMessageSend::TxComplete(_) => assert!(matches!(self, ExMsg::Comp)),
			}
		}

		/// Check for the parity of serialId: even for initiator, odd for acceptor
		fn check_serial_id(&self, serial_id: SerialId, is_initiator: bool) {
			if is_initiator {
				assert_eq!(serial_id % 2, 0);
			} else {
				assert_eq!(serial_id % 2, 1);
			}
		}
	}

	/// Use shortened names here, ExTx ExpectedTxParams
	#[derive(Debug)]
	struct ExTx {
		input_count: u16,
		output_count: u16,
	}

	impl ExTx {
		fn new(input_count: u16, output_count: u16) -> Self {
			ExTx { input_count, output_count }
		}

		fn match_tx(&self, tx: &Option<Transaction>) {
			assert_eq!(tx.as_ref().unwrap().input.len(), self.input_count as usize);
			assert_eq!(tx.as_ref().unwrap().output.len(), self.output_count as usize);
		}
	}

	/// Use shortened names here, ExInvRes ExpectedInvokeResult
	#[derive(Debug)]
	struct ExInvRes {
		error_expected: Option<AbortReason>,
		state: ExSt,
		message: Option<ExMsg>,
		tx: Option<ExTx>,
	}

	impl ExInvRes {
		// ctor with success result
		fn ok(state: ExSt, message: Option<ExMsg>, tx: Option<ExTx>) -> Self {
			Self { error_expected: None, state, message, tx }
		}

		// ctor with error result
		fn error(error: AbortReason) -> Self {
			Self { error_expected: Some(error), state: ExSt::NegAb, message: None, tx: None }
		}

		fn match_state(&self, state: &StateMachine) {
			self.state.match_state(state);
		}

		fn match_msg(&self, msg: &Option<InteractiveTxMessageSend>, is_initiator: bool) {
			if let Some(m) = &self.message {
				m.match_msg(msg, is_initiator);
			} else {
				assert!(msg.is_none());
			}
		}

		fn match_tx(&self, tx: &Option<Transaction>) {
			if let Some(txp) = &self.tx {
				txp.match_tx(tx);
			} else {
				assert!(tx.is_none());
			}
		}
	}

	/// InvokeStep, shortened name Invoke
	#[derive(Debug)]
	struct Invoke {
		invoke: InvHM,
		expected_state: ExInvRes,
	}

	// Test helper: create an InteractiveTxConstructor, and perform a number of steps, and check results after each.
	fn run_interactive_tx(
		channel_id: ChannelId, is_initiator: bool, local_inputs: Vec<(TxIn, Transaction)>, local_outputs: Vec<TxOut>,
		expected_initial_state: ExInvRes, invocations: Vec<Invoke>,
	) {
		let entropy_source = TestEntropySource::new();
		let (mut interact, msg) = InteractiveTxConstructor::new(
			&&entropy_source,
			channel_id,
			FEERATE_FLOOR_SATS_PER_KW,
			is_initiator,
			PackedLockTime::ZERO,
			local_inputs,
			local_outputs,
		);

		expected_initial_state.match_state(&interact.get_state_machine());
		expected_initial_state.match_msg(&msg, is_initiator);

		// Process invocations
		for i in invocations {
			println!("Invoking {:?} ...", i);
			let invoke_res = i.invoke.do_invoke(&mut interact);
			// check post state
			i.expected_state.match_state(&interact.get_state_machine());
			if let Err(err_act) = invoke_res {
				if let Some(err_exp) = i.expected_state.error_expected {
					// Expected error, got error
					if err_exp != err_act {
						panic!(
							"Got different error than expected, exp {:?} act {:?} inv {:?}",
							err_exp, err_act, i.invoke
						);
					}
				} else {
					panic!("Unexpected error invoking, {:?} {:?}", err_act, i.invoke);
				}
			} else {
				if let Some(err_exp) = i.expected_state.error_expected {
					panic!("Invocation OK but expected error, {:?} {:?}", err_exp, i.invoke);
				} else {
					// OK
					i.expected_state.match_msg(&invoke_res.as_ref().unwrap().0, is_initiator);
					i.expected_state.match_tx(&invoke_res.as_ref().unwrap().1);
				}
			}
		}
	}

	// Test cases
	//
	// A note on naming of the tests cases:
	// - 'init' is short for initiator
	// - 'noni' is short for noninitiator
	// The follows a sequence of one-letter codes indicating added inputs and outputs, as follows:
	// - 'I': for local-added input
	// - 'O': for local-added output
	// - 'j': for remote-added input (letter j is somewhat similar to i)
	// - 'u': for remote-added output (letter u is somewhat similar to o, also second letter in out)
	// They are listed in the order they are added, e.g.: _IjOjjju_

	#[test]
	fn test_interact_tx_noni_construct() {
		let channel_id = get_sample_channel_id();
		run_interactive_tx(channel_id, false, vec![], vec![], ExInvRes::ok(ExSt::LocalCh, None, None), vec![]);
	}

	#[test]
	fn test_interact_tx_init_construct() {
		let channel_id = get_sample_channel_id();
		run_interactive_tx(
			channel_id,
			true,
			vec![],
			vec![],
			ExInvRes::ok(ExSt::LocalComp, Some(ExMsg::Comp), None),
			vec![],
		);
	}

	#[test]
	fn test_interact_tx_noni_ju_complete() {
		let channel_id = get_sample_channel_id();
		run_interactive_tx(
			channel_id,
			false,
			vec![],
			vec![],
			ExInvRes::ok(ExSt::LocalCh, None, None),
			vec![
				Invoke {
					invoke: InvHM::AddI(get_sample_tx_add_input(123002, channel_id)),
					expected_state: ExInvRes::ok(ExSt::LocalComp, Some(ExMsg::Comp), None),
				},
				Invoke {
					invoke: InvHM::AddO(get_sample_tx_add_output(123004, channel_id)),
					expected_state: ExInvRes::ok(ExSt::LocalComp, Some(ExMsg::Comp), None),
				},
				Invoke {
					invoke: InvHM::Comp(channel_id),
					expected_state: ExInvRes::ok(ExSt::NegComp, None, Some(ExTx::new(1, 1))),
				},
			],
		);
	}

	#[test]
	#[allow(non_snake_case)]
	fn test_interact_tx_init_IO_complete() {
		let channel_id = get_sample_channel_id();
		let inputs = vec![(get_sample_tx_input(), get_sample_input_tx())];
		let outputs = vec![get_sample_tx_output()];
		run_interactive_tx(
			channel_id,
			true,
			inputs,
			outputs,
			ExInvRes::ok(ExSt::LocalCh, Some(ExMsg::AddI), None),
			vec![
				Invoke {
					invoke: InvHM::Comp(channel_id),
					expected_state: ExInvRes::ok(ExSt::LocalCh, Some(ExMsg::AddO), None),
				},
				Invoke {
					invoke: InvHM::Comp(channel_id),
					expected_state: ExInvRes::ok(ExSt::NegComp, Some(ExMsg::Comp), Some(ExTx::new(1, 1))),
				},
			],
		);
	}

	#[test]
	#[allow(non_snake_case)]
	fn test_interact_tx_noni_IO_complete() {
		let channel_id = get_sample_channel_id();
		let inputs = vec![(get_sample_tx_input(), get_sample_input_tx())];
		let outputs = vec![get_sample_tx_output()];
		run_interactive_tx(
			channel_id,
			false,
			inputs,
			outputs,
			ExInvRes::ok(ExSt::LocalCh, None, None),
			vec![
				Invoke {
					invoke: InvHM::Comp(channel_id),
					expected_state: ExInvRes::ok(ExSt::LocalCh, Some(ExMsg::AddI), None),
				},
				Invoke {
					invoke: InvHM::Comp(channel_id),
					expected_state: ExInvRes::ok(ExSt::LocalCh, Some(ExMsg::AddO), None),
				},
				// Error because the initiator is expected to pay fee for common fields, they contributed 0, which is insufficient
				Invoke {
					invoke: InvHM::Comp(channel_id),
					expected_state: ExInvRes::error(AbortReason::InsufficientFees),
				},
			],
		);
	}

	#[test]
	fn test_interact_tx_init_ju_complete() {
		let channel_id = get_sample_channel_id();
		run_interactive_tx(
			channel_id,
			true,
			vec![],
			vec![],
			ExInvRes::ok(ExSt::LocalComp, Some(ExMsg::Comp), None),
			vec![
				Invoke {
					invoke: InvHM::AddI(get_sample_tx_add_input(123001, channel_id)),
					expected_state: ExInvRes::ok(ExSt::LocalComp, Some(ExMsg::Comp), None),
				},
				Invoke {
					invoke: InvHM::AddO(get_sample_tx_add_output(123003, channel_id)),
					expected_state: ExInvRes::ok(ExSt::LocalComp, Some(ExMsg::Comp), None),
				},
				Invoke {
					invoke: InvHM::Comp(channel_id),
					expected_state: ExInvRes::ok(ExSt::NegComp, None, Some(ExTx::new(1, 1))),
				},
			],
		);
	}

	#[test]
	fn test_interact_tx_noni_empty_complete() {
		let channel_id = get_sample_channel_id();
		run_interactive_tx(
			channel_id,
			false,
			vec![],
			vec![],
			ExInvRes::ok(ExSt::LocalCh, None, None),
			vec![
				// Error because the initiator is expected to pay fee for common fields, they contributed 0, which is insufficient
				Invoke {
					invoke: InvHM::Comp(channel_id),
					expected_state: ExInvRes::error(AbortReason::InsufficientFees),
				},
			],
		);
	}

	#[test]
	fn test_interact_tx_init_empty_complete() {
		let channel_id = get_sample_channel_id();
		run_interactive_tx(
			channel_id,
			true,
			vec![],
			vec![],
			ExInvRes::ok(ExSt::LocalComp, Some(ExMsg::Comp), None),
			vec![
				// Empty inputs accepted here (counterparty fee check is OK)
				Invoke {
					invoke: InvHM::Comp(channel_id),
					expected_state: ExInvRes::ok(ExSt::NegComp, None, Some(ExTx::new(0, 0))),
				},
			],
		);
	}

	// Both parties contribute
	#[test]
	#[allow(non_snake_case)]
	fn test_interact_tx_init_IjOu_complete() {
		let channel_id = get_sample_channel_id();
		let inputs = vec![(get_sample_tx_input(), get_sample_input_tx())];
		let outputs = vec![get_sample_tx_output()];
		run_interactive_tx(
			channel_id,
			true,
			inputs,
			outputs,
			ExInvRes::ok(ExSt::LocalCh, Some(ExMsg::AddI), None),
			vec![
				Invoke {
					invoke: InvHM::AddI(get_sample_tx_add_input_2(123001, channel_id)),
					expected_state: ExInvRes::ok(ExSt::LocalCh, Some(ExMsg::AddO), None),
				},
				Invoke {
					invoke: InvHM::AddO(get_sample_tx_add_output_2(123003, channel_id)),
					expected_state: ExInvRes::ok(ExSt::LocalComp, Some(ExMsg::Comp), None),
				},
				Invoke {
					invoke: InvHM::Comp(channel_id),
					expected_state: ExInvRes::ok(ExSt::NegComp, None, Some(ExTx::new(2, 2))),
				},
			],
		);
	}

	#[test]
	#[allow(non_snake_case)]
	fn test_interact_tx_noni_jIuO_complete() {
		let channel_id = get_sample_channel_id();
		let inputs = vec![(get_sample_tx_input(), get_sample_input_tx())];
		let outputs = vec![get_sample_tx_output()];
		run_interactive_tx(
			channel_id,
			false,
			inputs,
			outputs,
			ExInvRes::ok(ExSt::LocalCh, None, None),
			vec![
				Invoke {
					invoke: InvHM::AddI(get_sample_tx_add_input_2(123002, channel_id)),
					expected_state: ExInvRes::ok(ExSt::LocalCh, Some(ExMsg::AddI), None),
				},
				Invoke {
					invoke: InvHM::AddO(get_sample_tx_add_output_2(123004, channel_id)),
					expected_state: ExInvRes::ok(ExSt::LocalCh, Some(ExMsg::AddO), None),
				},
				Invoke {
					invoke: InvHM::Comp(channel_id),
					expected_state: ExInvRes::ok(ExSt::NegComp, Some(ExMsg::Comp), Some(ExTx::new(2, 2))),
				},
			],
		);
	}

	#[test]
	#[allow(non_snake_case)]
	fn test_interact_tx_noni_jIO_complete() {
		let channel_id = get_sample_channel_id();
		let inputs = vec![(get_sample_tx_input(), get_sample_input_tx())];
		let outputs = vec![get_sample_tx_output()];
		run_interactive_tx(
			channel_id,
			false,
			inputs,
			outputs,
			ExInvRes::ok(ExSt::LocalCh, None, None),
			vec![
				Invoke {
					invoke: InvHM::AddI(get_sample_tx_add_input_2(123002, channel_id)),
					expected_state: ExInvRes::ok(ExSt::LocalCh, Some(ExMsg::AddI), None),
				},
				Invoke {
					invoke: InvHM::Comp(channel_id),
					expected_state: ExInvRes::ok(ExSt::LocalCh, Some(ExMsg::AddO), None),
				},
				Invoke {
					invoke: InvHM::Comp(channel_id),
					expected_state: ExInvRes::ok(ExSt::NegComp, Some(ExMsg::Comp), Some(ExTx::new(2, 1))),
				},
			],
		);
	}

	#[test]
	fn test_interact_tx_noni_jjuu_complete() {
		let channel_id = get_sample_channel_id();
		run_interactive_tx(
			channel_id,
			false,
			vec![],
			vec![],
			ExInvRes::ok(ExSt::LocalCh, None, None),
			vec![
				Invoke {
					invoke: InvHM::AddI(get_sample_tx_add_input(123002, channel_id)),
					expected_state: ExInvRes::ok(ExSt::LocalComp, Some(ExMsg::Comp), None),
				},
				Invoke {
					invoke: InvHM::AddI(get_sample_tx_add_input_2(123004, channel_id)),
					expected_state: ExInvRes::ok(ExSt::LocalComp, Some(ExMsg::Comp), None),
				},
				Invoke {
					invoke: InvHM::AddO(get_sample_tx_add_output(123006, channel_id)),
					expected_state: ExInvRes::ok(ExSt::LocalComp, Some(ExMsg::Comp), None),
				},
				Invoke {
					invoke: InvHM::AddO(get_sample_tx_add_output_2(123008, channel_id)),
					expected_state: ExInvRes::ok(ExSt::LocalComp, Some(ExMsg::Comp), None),
				},
				Invoke {
					invoke: InvHM::Comp(channel_id),
					expected_state: ExInvRes::ok(ExSt::NegComp, None, Some(ExTx::new(2, 2))),
				},
			],
		);
	}

	#[test]
	fn test_interact_tx_noni_juju_complete() {
		let channel_id = get_sample_channel_id();
		run_interactive_tx(
			channel_id,
			false,
			vec![],
			vec![],
			ExInvRes::ok(ExSt::LocalCh, None, None),
			vec![
				Invoke {
					invoke: InvHM::AddI(get_sample_tx_add_input(123002, channel_id)),
					expected_state: ExInvRes::ok(ExSt::LocalComp, Some(ExMsg::Comp), None),
				},
				Invoke {
					invoke: InvHM::AddO(get_sample_tx_add_output(123006, channel_id)),
					expected_state: ExInvRes::ok(ExSt::LocalComp, Some(ExMsg::Comp), None),
				},
				Invoke {
					invoke: InvHM::AddI(get_sample_tx_add_input_2(123004, channel_id)),
					expected_state: ExInvRes::ok(ExSt::LocalComp, Some(ExMsg::Comp), None),
				},
				Invoke {
					invoke: InvHM::AddO(get_sample_tx_add_output_2(123008, channel_id)),
					expected_state: ExInvRes::ok(ExSt::LocalComp, Some(ExMsg::Comp), None),
				},
				Invoke {
					invoke: InvHM::Comp(channel_id),
					expected_state: ExInvRes::ok(ExSt::NegComp, None, Some(ExTx::new(2, 2))),
				},
			],
		);
	}

	#[test]
	#[allow(non_snake_case)]
	fn test_interact_tx_init_IIOO_complete() {
		let channel_id = get_sample_channel_id();
		let inputs =
			vec![(get_sample_tx_input(), get_sample_input_tx()), (get_sample_tx_input_2(), get_sample_input_tx_2())];
		let outputs = vec![get_sample_tx_output(), get_sample_tx_output_2()];
		run_interactive_tx(
			channel_id,
			true,
			inputs,
			outputs,
			ExInvRes::ok(ExSt::LocalCh, Some(ExMsg::AddI), None),
			vec![
				Invoke {
					invoke: InvHM::Comp(channel_id),
					expected_state: ExInvRes::ok(ExSt::LocalCh, Some(ExMsg::AddI), None),
				},
				Invoke {
					invoke: InvHM::Comp(channel_id),
					expected_state: ExInvRes::ok(ExSt::LocalCh, Some(ExMsg::AddO), None),
				},
				Invoke {
					invoke: InvHM::Comp(channel_id),
					expected_state: ExInvRes::ok(ExSt::LocalCh, Some(ExMsg::AddO), None),
				},
				Invoke {
					invoke: InvHM::Comp(channel_id),
					expected_state: ExInvRes::ok(ExSt::NegComp, Some(ExMsg::Comp), Some(ExTx::new(2, 2))),
				},
			],
		);
	}

	#[test]
	fn test_interact_tx_noni_uj_complete() {
		let channel_id = get_sample_channel_id();
		run_interactive_tx(
			channel_id,
			false,
			vec![],
			vec![],
			ExInvRes::ok(ExSt::LocalCh, None, None),
			vec![
				Invoke {
					invoke: InvHM::AddO(get_sample_tx_add_output(123004, channel_id)),
					expected_state: ExInvRes::ok(ExSt::LocalComp, Some(ExMsg::Comp), None),
				},
				Invoke {
					invoke: InvHM::AddI(get_sample_tx_add_input(123002, channel_id)),
					expected_state: ExInvRes::ok(ExSt::LocalComp, Some(ExMsg::Comp), None),
				},
				Invoke {
					invoke: InvHM::Comp(channel_id),
					expected_state: ExInvRes::ok(ExSt::NegComp, None, Some(ExTx::new(1, 1))),
				},
			],
		);
	}

	#[test]
	#[allow(non_snake_case)]
	fn test_interact_tx_init_IuOjj_complete() {
		let channel_id = get_sample_channel_id();
		let inputs = vec![(get_sample_tx_input(), get_sample_input_tx())];
		let outputs = vec![get_sample_tx_output()];
		run_interactive_tx(
			channel_id,
			true,
			inputs,
			outputs,
			ExInvRes::ok(ExSt::LocalCh, Some(ExMsg::AddI), None),
			vec![
				Invoke {
					invoke: InvHM::AddO(get_sample_tx_add_output_2(123001, channel_id)),
					expected_state: ExInvRes::ok(ExSt::LocalCh, Some(ExMsg::AddO), None),
				},
				Invoke {
					invoke: InvHM::AddI(get_sample_tx_add_input_2(123003, channel_id)),
					expected_state: ExInvRes::ok(ExSt::LocalComp, Some(ExMsg::Comp), None),
				},
				Invoke {
					invoke: InvHM::AddI(get_sample_tx_add_input_3(123005, channel_id)),
					expected_state: ExInvRes::ok(ExSt::LocalComp, Some(ExMsg::Comp), None),
				},
				Invoke {
					invoke: InvHM::Comp(channel_id),
					expected_state: ExInvRes::ok(ExSt::NegComp, None, Some(ExTx::new(3, 2))),
				},
			],
		);
	}

	#[test]
	fn test_interact_tx_error_wrong_serial_id_parity_noni() {
		let channel_id = get_sample_channel_id();
		run_interactive_tx(
			channel_id,
			false,
			vec![],
			vec![],
			ExInvRes::ok(ExSt::LocalCh, None, None),
			// Remote serialID should be even
			vec![Invoke {
				invoke: InvHM::AddI(get_sample_tx_add_input(123001, channel_id)),
				expected_state: ExInvRes::error(AbortReason::IncorrectSerialIdParity),
			}],
		);
	}

	#[test]
	fn test_interact_tx_error_duplicate_serial_id_noni() {
		let channel_id = get_sample_channel_id();
		run_interactive_tx(
			channel_id,
			false,
			vec![],
			vec![],
			ExInvRes::ok(ExSt::LocalCh, None, None),
			vec![
				Invoke {
					invoke: InvHM::AddI(get_sample_tx_add_input(123002, channel_id)),
					expected_state: ExInvRes::ok(ExSt::LocalComp, Some(ExMsg::Comp), None),
				},
				Invoke {
					invoke: InvHM::AddI(get_sample_tx_add_input_2(123002, channel_id)),
					expected_state: ExInvRes::error(AbortReason::DuplicateSerialId),
				},
			],
		);
	}

	#[test]
	fn test_interact_tx_error_complete_complete_noni() {
		let channel_id = get_sample_channel_id();
		run_interactive_tx(
			channel_id,
			false,
			vec![],
			vec![],
			ExInvRes::ok(ExSt::LocalCh, None, None),
			vec![
				Invoke {
					invoke: InvHM::AddI(get_sample_tx_add_input(123002, channel_id)),
					expected_state: ExInvRes::ok(ExSt::LocalComp, Some(ExMsg::Comp), None),
				},
				Invoke {
					invoke: InvHM::AddO(get_sample_tx_add_output(123004, channel_id)),
					expected_state: ExInvRes::ok(ExSt::LocalComp, Some(ExMsg::Comp), None),
				},
				Invoke {
					invoke: InvHM::Comp(channel_id),
					expected_state: ExInvRes::ok(ExSt::NegComp, None, Some(ExTx::new(1, 1))),
				},
				Invoke {
					invoke: InvHM::Comp(channel_id),
					expected_state: ExInvRes::error(AbortReason::UnexpectedCounterpartyMessage),
				},
			],
		);
	}

	#[test]
	fn test_interact_tx_noni_jju_remove_input() {
		let channel_id = get_sample_channel_id();
		run_interactive_tx(
			channel_id,
			false,
			vec![],
			vec![],
			ExInvRes::ok(ExSt::LocalCh, None, None),
			vec![
				Invoke {
					invoke: InvHM::AddI(get_sample_tx_add_input(123002, channel_id)),
					expected_state: ExInvRes::ok(ExSt::LocalComp, Some(ExMsg::Comp), None),
				},
				Invoke {
					invoke: InvHM::AddI(get_sample_tx_add_input_2(123004, channel_id)),
					expected_state: ExInvRes::ok(ExSt::LocalComp, Some(ExMsg::Comp), None),
				},
				Invoke {
					invoke: InvHM::AddO(get_sample_tx_add_output(123006, channel_id)),
					expected_state: ExInvRes::ok(ExSt::LocalComp, Some(ExMsg::Comp), None),
				},
				Invoke {
					invoke: InvHM::RemI(TxRemoveInput { channel_id, serial_id: 123002 }),
					expected_state: ExInvRes::ok(ExSt::LocalComp, Some(ExMsg::Comp), None),
				},
				Invoke {
					invoke: InvHM::Comp(channel_id),
					expected_state: ExInvRes::ok(ExSt::NegComp, None, Some(ExTx::new(1, 1))),
				},
			],
		);
	}

	#[test]
	fn test_interact_tx_noni_juu_remove_output() {
		let channel_id = get_sample_channel_id();
		run_interactive_tx(
			channel_id,
			false,
			vec![],
			vec![],
			ExInvRes::ok(ExSt::LocalCh, None, None),
			vec![
				Invoke {
					invoke: InvHM::AddI(get_sample_tx_add_input(123002, channel_id)),
					expected_state: ExInvRes::ok(ExSt::LocalComp, Some(ExMsg::Comp), None),
				},
				Invoke {
					invoke: InvHM::AddO(get_sample_tx_add_output(123004, channel_id)),
					expected_state: ExInvRes::ok(ExSt::LocalComp, Some(ExMsg::Comp), None),
				},
				Invoke {
					invoke: InvHM::AddO(get_sample_tx_add_output_2(123006, channel_id)),
					expected_state: ExInvRes::ok(ExSt::LocalComp, Some(ExMsg::Comp), None),
				},
				Invoke {
					invoke: InvHM::RemO(TxRemoveOutput { channel_id, serial_id: 123004 }),
					expected_state: ExInvRes::ok(ExSt::LocalComp, Some(ExMsg::Comp), None),
				},
				Invoke {
					invoke: InvHM::Comp(channel_id),
					expected_state: ExInvRes::ok(ExSt::NegComp, None, Some(ExTx::new(1, 1))),
				},
			],
		);
	}

	#[test]
	fn test_interact_tx_error_remove_serial_id_unknown_noni_j() {
		let channel_id = get_sample_channel_id();
		run_interactive_tx(
			channel_id,
			false,
			vec![],
			vec![],
			ExInvRes::ok(ExSt::LocalCh, None, None),
			vec![
				Invoke {
					invoke: InvHM::AddI(get_sample_tx_add_input(123002, channel_id)),
					expected_state: ExInvRes::ok(ExSt::LocalComp, Some(ExMsg::Comp), None),
				},
				Invoke {
					invoke: InvHM::RemI(TxRemoveInput { channel_id, serial_id: 123004 }),
					expected_state: ExInvRes::error(AbortReason::SerialIdUnknown),
				},
			],
		);
	}

	/// Dummy entropy source, returns all zeroes
	struct DummyEntropySource {}

	impl EntropySource for DummyEntropySource {
		fn get_secure_random_bytes(&self) -> [u8; 32] {
			[0; 32]
		}
	}

	/// If the provided entropy is trivially wrong, we may generate events with duplicate serialIds, which is up to the counterparty to reject
	#[test]
	fn test_interact_tx_error_dummy_entropy() {
		let channel_id = get_sample_channel_id();
		let local_inputs =
			vec![(get_sample_tx_input(), get_sample_input_tx()), (get_sample_tx_input_2(), get_sample_input_tx_2())];
		let local_outputs = vec![get_sample_tx_output(), get_sample_tx_output_2()];
		let dummy_entropy_source = DummyEntropySource {};
		let (mut interact, msg) = InteractiveTxConstructor::new(
			&&dummy_entropy_source,
			channel_id,
			FEERATE_FLOOR_SATS_PER_KW,
			true,
			PackedLockTime::ZERO,
			local_inputs,
			local_outputs,
		);
		let expected_serial_id = 0;
		assert!(matches!(msg, Some(InteractiveTxMessageSend::TxAddInput(add)) if add.serial_id == expected_serial_id));
		let (msg, _tx) = interact.handle_tx_complete(&TxComplete { channel_id }).unwrap();
		assert!(matches!(msg, Some(InteractiveTxMessageSend::TxAddInput(add)) if add.serial_id == expected_serial_id));
	}
}
