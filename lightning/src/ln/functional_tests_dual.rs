// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Tests that test standing up a network of ChannelManagers, creating channels, sending
//! payments/messages between them, and often checking the resulting ChannelMonitors are able to
//! claim outputs on-chain.

use crate::events::{MessageSendEvent, MessageSendEventsProvider};
use crate::ln::msgs::{ChannelMessageHandler, CommonOpenChannelFields};
use crate::ln::features::ChannelTypeFeatures;
use crate::ln::functional_test_utils::*;
use crate::ln::types::ChannelId;
use crate::ln::msgs::OpenChannelV2;
use bitcoin::constants::ChainHash;
use bitcoin::network::Network;
use bitcoin::secp256k1::PublicKey;

// use bitcoin::secp256k1::{Keypair, PublicKey, Secp256k1, SecretKey};
// use crate::chain::chaininterface::ConfirmationTarget;

fn dummy_pubkey(_val: u8) -> PublicKey {
	let mut bytes = vec![2; 33];
	// println!("bytes {} {:?}", (&bytes[..]).len(), &bytes[..]);
	PublicKey::from_slice(&bytes[..]).unwrap()
}

#[test]
fn do_test_v2_channel_acceptance() {
	let channel_contribution_initiator = 100_000;

	let temporary_channel_id = ChannelId::from_bytes([5; 32]);
	// let secp_ctx = Secp256k1::new();
	// let initiator_keys = Keypair::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap());
	let initiator_pubkey = dummy_pubkey(2);
	let revocation_basepoint = dummy_pubkey(3);
	let payment_basepoint = dummy_pubkey(4);
	let delayed_payment_basepoint = dummy_pubkey(5);
	let htlc_basepoint = dummy_pubkey(6);
	let first_per_commitment_point = dummy_pubkey(7);

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	// let acceptor_config = if acceptor_will_fund {
	// 	let mut acceptor_config = test_default_channel_config();
	// 	acceptor_config.manually_accept_inbound_channels = true;
	// 	Some(acceptor_config)
	// } else {
	// 	None
	// };
	let acceptor_config = None;
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, acceptor_config]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// // Create a funding input for the new channel along with its previous transaction.
	// let initiator_funding_inputs = create_dual_funding_utxos_with_prev_txs(&nodes[0], &[channel_contribution_initiator]);

	// Alice creates a dual-funded channel as initiator.
	// nodes[0].node.create_dual_funded_channel( ...

	let mut channel_type = ChannelTypeFeatures::empty();
	channel_type.set_static_remote_key_required();
	let common_fields = CommonOpenChannelFields {
		chain_hash: ChainHash::using_genesis_block(Network::Testnet),
		temporary_channel_id,
		funding_satoshis: channel_contribution_initiator,
		dust_limit_satoshis: 500, // TODO
		max_htlc_value_in_flight_msat: 2536655962884945560, // TODO
		htlc_minimum_msat: 1_000, // TODO
		commitment_feerate_sat_per_1000_weight: 300,
		to_self_delay: 144, // TODO
		max_accepted_htlcs: 100, // TODO
		funding_pubkey: initiator_pubkey,
		revocation_basepoint,
		payment_basepoint,
		delayed_payment_basepoint,
		htlc_basepoint,
		first_per_commitment_point,
		channel_flags: 0, // TODO
		shutdown_scriptpubkey: None, // TODO
		channel_type: Some(channel_type),
	};

	let open_channel_msg = OpenChannelV2 {
		common_fields,
		funding_feerate_sat_per_1000_weight: 4, // TODO
		locktime: 0, // TODO
		second_per_commitment_point: dummy_pubkey(8),
		require_confirmed_inputs: None,
	};

	// Simulate open_channel_v2 from node[0]
	nodes[1].node.handle_open_channel_v2(&nodes[0].node.get_our_node_id(), &open_channel_msg);

	let accept_channel_v2_msg = get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannelV2, nodes[0].node.get_our_node_id());
	assert_eq!(accept_channel_v2_msg.funding_satoshis, 0);
	// second_per_commitment_point
	assert!(accept_channel_v2_msg.require_confirmed_inputs.is_none());
	assert_eq!(accept_channel_v2_msg.common_fields.temporary_channel_id, temporary_channel_id);
	assert_eq!(accept_channel_v2_msg.common_fields.dust_limit_satoshis, 0);
	assert_eq!(accept_channel_v2_msg.common_fields.max_htlc_value_in_flight_msat, 0);
	assert_eq!(accept_channel_v2_msg.common_fields.htlc_minimum_msat, 0);

	assert_eq!(accept_channel_v2_msg.common_fields.minimum_depth, 0);
	assert_eq!(accept_channel_v2_msg.common_fields.to_self_delay, 0);
	assert_eq!(accept_channel_v2_msg.common_fields.max_accepted_htlcs, 0);
	assert_eq!(accept_channel_v2_msg.common_fields.funding_pubkey, nodes[1].node.get_our_node_id());
	assert_eq!(accept_channel_v2_msg.common_fields.revocation_basepoint, revocation_basepoint);
	assert_eq!(accept_channel_v2_msg.common_fields.payment_basepoint, payment_basepoint);
	assert_eq!(accept_channel_v2_msg.common_fields.delayed_payment_basepoint, delayed_payment_basepoint);
	assert_eq!(accept_channel_v2_msg.common_fields.htlc_basepoint, htlc_basepoint);
	assert_eq!(accept_channel_v2_msg.common_fields.first_per_commitment_point, first_per_commitment_point);
	assert!(accept_channel_v2_msg.common_fields.shutdown_scriptpubkey.is_none());
	assert!(accept_channel_v2_msg.common_fields.channel_type.is_none());
}

/*
struct V2ChannelEstablishmentTestSession {
	initiator_input_value_satoshis: u64,
	acceptor_input_value_satoshis: u64,
}

#[test]
fn do_test_v2_channel_establishment(_session: V2ChannelEstablishmentTestSession) {
	let acceptor_will_fund = session.acceptor_input_value_satoshis > 0;

	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let acceptor_config = if acceptor_will_fund {
		let mut acceptor_config = test_default_channel_config();
		acceptor_config.manually_accept_inbound_channels = true;
		Some(acceptor_config)
	} else {
		None
	};
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, acceptor_config]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

	// Create a funding input for the new channel along with its previous transaction.
	let initiator_funding_inputs = create_dual_funding_utxos_with_prev_txs(&nodes[0], &[session.initiator_input_value_satoshis]);

	// Alice creates a dual-funded channel as initiator.
	nodes[0].node.create_dual_funded_channel(
		nodes[1].node.get_our_node_id(), initiator_funding_inputs,
		Some(ConfirmationTarget::NonAnchorChannelFee), 42, None,
	).unwrap();
	let open_channel_v2_msg = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannelV2, nodes[1].node.get_our_node_id());

	assert_eq!(nodes[0].node.list_channels().len(), 1);

	nodes[1].node.handle_open_channel_v2(&nodes[0].node.get_our_node_id(), &open_channel_v2_msg);

	if acceptor_will_fund {
		// Since `manually_accept_inbound_channels` is set to true for Bob's node, he can contribute to
		// the dual-funded channel.
		let temporary_channel_id = if let Event::OpenChannelRequest {
			temporary_channel_id,
			counterparty_node_id,
			acceptor_funds,
			..
		} = get_event!(nodes[1], Event::OpenChannelRequest) {
			assert_eq!(counterparty_node_id, nodes[0].node.get_our_node_id());
			assert!(matches!(acceptor_funds, InboundChannelFunds::DualFunded));
			temporary_channel_id
		} else { panic!(); };

		// Bob contributes to the channel providing an input.
		let acceptor_funding_inputs = create_dual_funding_utxos_with_prev_txs(&nodes[1], &[session.acceptor_input_value_satoshis]);

		nodes[1].node.accept_inbound_channel_with_contribution(
			&temporary_channel_id, &nodes[0].node.get_our_node_id(), 1337, acceptor_funding_inputs
		).unwrap();
	}

	let accept_channel_v2_msg = get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannelV2, nodes[0].node.get_our_node_id());

	nodes[0].node.handle_accept_channel_v2(&nodes[1].node.get_our_node_id(), &accept_channel_v2_msg);

	let tx_add_input_msg = get_event_msg!(&nodes[0], MessageSendEvent::SendTxAddInput, nodes[1].node.get_our_node_id());
	let input_value = tx_add_input_msg.prevtx.as_transaction().output[tx_add_input_msg.prevtx_out as usize].value;
	assert_eq!(input_value.to_sat(), session.initiator_input_value_satoshis);

	nodes[1].node.handle_tx_add_input(&nodes[0].node.get_our_node_id(), &tx_add_input_msg);

	if acceptor_will_fund {
		let tx_add_input_msg = get_event_msg!(nodes[1], MessageSendEvent::SendTxAddInput, nodes[0].node.get_our_node_id());
		let input_value = tx_add_input_msg.prevtx.as_transaction().output[tx_add_input_msg.prevtx_out as usize].value;
		assert_eq!(input_value.to_sat(), session.acceptor_input_value_satoshis);
		nodes[0].node.handle_tx_add_input(&nodes[1].node.get_our_node_id(), &tx_add_input_msg);
	} else {
		let tx_complete_msg = get_event_msg!(nodes[1], MessageSendEvent::SendTxComplete, nodes[0].node.get_our_node_id());
		nodes[0].node.handle_tx_complete(&nodes[1].node.get_our_node_id(), &tx_complete_msg);
	};

	let tx_add_output_msg = get_event_msg!(&nodes[0], MessageSendEvent::SendTxAddOutput, nodes[1].node.get_our_node_id());
	nodes[1].node.handle_tx_add_output(&nodes[0].node.get_our_node_id(), &tx_add_output_msg);

	let tx_complete_msg = get_event_msg!(nodes[1], MessageSendEvent::SendTxComplete, nodes[0].node.get_our_node_id());
	nodes[0].node.handle_tx_complete(&nodes[1].node.get_our_node_id(), &tx_complete_msg);

	let msg_events = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 2);
	let tx_complete_msg = match msg_events[0] {
		MessageSendEvent::SendTxComplete { ref node_id, ref msg } => {
			assert_eq!(*node_id, nodes[1].node.get_our_node_id());
			(*msg).clone()
		},
		_ => panic!("Unexpected event"),
	};
	let msg_commitment_signed_from_0 = match msg_events[1] {
		MessageSendEvent::UpdateHTLCs { ref node_id, ref updates } => {
			assert_eq!(*node_id, nodes[1].node.get_our_node_id());
			updates.commitment_signed.clone()
		},
		_ => panic!("Unexpected event"),
	};
	// if let Event::FundingTransactionReadyForSigning {
	// 	channel_id,
	// 	counterparty_node_id,
	// 	mut unsigned_transaction,
	// 	..
	// } = get_event!(nodes[0], Event::FundingTransactionReadyForSigning) {
	// 	assert_eq!(counterparty_node_id, nodes[1].node.get_our_node_id());

	// 	let mut witness = Witness::new();
	// 	witness.push(vec![0]);
	// 	unsigned_transaction.input[0].witness = witness;

	// 	nodes[0].node.funding_transaction_signed(&channel_id, &counterparty_node_id, unsigned_transaction).unwrap();
	// } else { panic!(); }

	nodes[1].node.handle_tx_complete(&nodes[0].node.get_our_node_id(), &tx_complete_msg);
	let msg_events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(msg_events.len(), 1);
	let msg_commitment_signed_from_1 = match msg_events[0] {
		MessageSendEvent::UpdateHTLCs { ref node_id, ref updates } => {
			assert_eq!(*node_id, nodes[0].node.get_our_node_id());
			updates.commitment_signed.clone()
		},
		_ => panic!("Unexpected event"),
	};

	if acceptor_will_fund {
		// if let Event::FundingTransactionReadyForSigning {
		// 	channel_id,
		// 	counterparty_node_id,
		// 	mut unsigned_transaction,
		// 	..
		// } = get_event!(nodes[1], Event::FundingTransactionReadyForSigning) {
		// 	assert_eq!(counterparty_node_id, nodes[0].node.get_our_node_id());

		// 	let mut witness = Witness::new();
		// 	witness.push(vec![0]);
		// 	unsigned_transaction.input[0].witness = witness;

		// 	nodes[1].node.funding_transaction_signed(&channel_id, &counterparty_node_id, unsigned_transaction).unwrap();
		// } else { panic!(); }
	}

	// Handle the initial commitment_signed exchange. Order is not important here.
	nodes[1].node.handle_commitment_signed(&nodes[0].node.get_our_node_id(), &msg_commitment_signed_from_0);
	nodes[0].node.handle_commitment_signed(&nodes[1].node.get_our_node_id(), &msg_commitment_signed_from_1);
	check_added_monitors(&nodes[0], 1);
	check_added_monitors(&nodes[1], 1);

	let tx_signatures_exchange = |first: usize, second: usize| {
		let msg_events = nodes[second].node.get_and_clear_pending_msg_events();
		assert!(msg_events.is_empty());
		let tx_signatures_from_first = get_event_msg!(nodes[first], MessageSendEvent::SendTxSignatures, nodes[second].node.get_our_node_id());

		nodes[second].node.handle_tx_signatures(&nodes[first].node.get_our_node_id(), &tx_signatures_from_first);
		let events_0 = nodes[second].node.get_and_clear_pending_events();
		assert_eq!(events_0.len(), 1);
		match events_0[0] {
			Event::ChannelPending{ ref counterparty_node_id, .. } => {
				assert_eq!(*counterparty_node_id, nodes[first].node.get_our_node_id());
			},
			_ => panic!("Unexpected event"),
		}
		let tx_signatures_from_second = get_event_msg!(nodes[second], MessageSendEvent::SendTxSignatures, nodes[first].node.get_our_node_id());
		nodes[first].node.handle_tx_signatures(&nodes[second].node.get_our_node_id(), &tx_signatures_from_second);
		let events_1 = nodes[first].node.get_and_clear_pending_events();
		assert_eq!(events_1.len(), 1);
		match events_1[0] {
			Event::ChannelPending{ ref counterparty_node_id, .. } => {
				assert_eq!(*counterparty_node_id, nodes[second].node.get_our_node_id());
			},
			_ => panic!("Unexpected event"),
		}
	};

	if session.initiator_input_value_satoshis < session.acceptor_input_value_satoshis
		|| session.initiator_input_value_satoshis == session.acceptor_input_value_satoshis
		&& nodes[0].node.get_our_node_id().serialize() < nodes[1].node.get_our_node_id().serialize() {
		// Alice contributed less input value than Bob so he should send tx_signatures only after
		// receiving tx_signatures from Alice.
		tx_signatures_exchange(0, 1);
	} else {
		// Alice contributed more input value than Bob so she should send tx_signatures only after
		// receiving tx_signatures from Bob.
		tx_signatures_exchange(1, 0);
	}

	let tx = {
		let tx_0 = &nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap()[0];
		let tx_1 = &nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap()[0];
		assert_eq!(tx_0, tx_1);
		tx_0.clone()
	};

	let (channel_ready, _) = create_chan_between_nodes_with_value_confirm(&nodes[0], &nodes[1], &tx);
	let (announcement, nodes_0_update, nodes_1_update) = create_chan_between_nodes_with_value_b(&nodes[0], &nodes[1], &channel_ready);
	update_nodes_with_chan_announce(&nodes, 0, 1, &announcement, &nodes_0_update, &nodes_1_update);
}

#[test]
fn test_v2_channel_establishment() {
	// Only initiator contributes
	do_test_v2_channel_establishment(V2ChannelEstablishmentTestSession {
		initiator_input_value_satoshis: 100_000,
		acceptor_input_value_satoshis: 0,
	});

	// Both peers contribute but initiator contributes more input value
	do_test_v2_channel_establishment(V2ChannelEstablishmentTestSession {
		initiator_input_value_satoshis: 100_000,
		acceptor_input_value_satoshis: 80_000,
	});

	// Both peers contribute but acceptor contributes more input value
	do_test_v2_channel_establishment(V2ChannelEstablishmentTestSession {
		initiator_input_value_satoshis: 80_000,
		acceptor_input_value_satoshis: 100_000,
	});

	// Both peers contribute the same input value
	do_test_v2_channel_establishment(V2ChannelEstablishmentTestSession {
		initiator_input_value_satoshis: 80_000,
		acceptor_input_value_satoshis: 80_000,
	});
}
*/
