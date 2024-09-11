use bitcoin::Witness;
// use bitcoin::hashes::Hash;
// use bitcoin::hashes::sha256::Hash as Sha256;
// use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
// use core::sync::atomic::Ordering;
use crate::chain::chaininterface::ConfirmationTarget;
use crate::events::{Event, MessageSendEvent, MessageSendEventsProvider}; // HTLCDestination ClosureReason
// use crate::events::InboundChannelFunds;
// use crate::ln::ChannelId;
// use crate::ln::types::{ChannelId, PaymentPreimage, PaymentHash, PaymentSecret};
// use crate::ln::channelmanager::{HTLCForwardInfo, PaymentId, PaymentSendFailure, RecipientOnionFields, InterceptId};
use crate::ln::functional_test_utils::*;
// use crate::ln::msgs::{self, ErrorAction};
use crate::ln::msgs::ChannelMessageHandler;
use crate::prelude::*;

#[test]
fn test_v2_channel_establishment_with_rbf() {
    // let acceptor_will_fund = false;
    let initiator_input_value_satoshis = 100_000;
    let expected_temp_channel_id = "b1a3942f261316385476c86d7f454062ceb06d2e37675f08c2fac76b8c3ddc5e";
    let expected_funded_channel_id = "0df1425050bb045209e23459ebb5f9c8f6f219dafb85e2ec59d5fe841f1c4463";

    let chanmon_cfgs = create_chanmon_cfgs(2);
    let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
    // let acceptor_config = if acceptor_will_fund {
    //     let mut acceptor_config = test_default_channel_config();
    //     acceptor_config.manually_accept_inbound_channels = true;
    //     Some(acceptor_config)
    // } else {
    //     None
    // };
    let acceptor_config = None;
    let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, acceptor_config]);
    let nodes = create_network(2, &node_cfgs, &node_chanmgrs);

    // Create a funding input for the new channel along with its previous transaction.
    let initiator_funding_inputs = create_dual_funding_utxos_with_prev_txs(&nodes[0], &[initiator_input_value_satoshis]);

    // Alice creates a dual-funded channel as initiator.
    let res_channel_id = nodes[0].node.create_dual_funded_channel(
        nodes[1].node.get_our_node_id(), initiator_funding_inputs.clone(),
        Some(ConfirmationTarget::AnchorChannelFee), 42, None,
    ).unwrap();
    assert_eq!(res_channel_id.to_string(), expected_temp_channel_id);
    let open_channel_v2_msg = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannelV2, nodes[1].node.get_our_node_id());

    assert_eq!(nodes[0].node.list_channels().len(), 1);
    assert_eq!(nodes[0].node.list_channels()[0].channel_id.to_string(), expected_temp_channel_id);

    nodes[1].node.handle_open_channel_v2(&nodes[0].node.get_our_node_id(), &open_channel_v2_msg);

    /*
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
    */

    let accept_channel_v2_msg = get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannelV2, nodes[0].node.get_our_node_id());
    assert_eq!(accept_channel_v2_msg.common_fields.temporary_channel_id.to_string(), "b1a3942f261316385476c86d7f454062ceb06d2e37675f08c2fac76b8c3ddc5e");
    let temporary_channel_id = accept_channel_v2_msg.common_fields.temporary_channel_id;

    nodes[0].node.handle_accept_channel_v2(&nodes[1].node.get_our_node_id(), &accept_channel_v2_msg);

    let tx_add_input_msg = get_event_msg!(&nodes[0], MessageSendEvent::SendTxAddInput, nodes[1].node.get_our_node_id());
    let input_value = tx_add_input_msg.prevtx.as_transaction().output[tx_add_input_msg.prevtx_out as usize].value;
    assert_eq!(input_value.to_sat(), initiator_input_value_satoshis);

    nodes[1].node.handle_tx_add_input(&nodes[0].node.get_our_node_id(), &tx_add_input_msg);

    /*
    if acceptor_will_fund {
        let tx_add_input_msg = get_event_msg!(nodes[1], MessageSendEvent::SendTxAddInput, nodes[0].node.get_our_node_id());
        let input_value = tx_add_input_msg.prevtx.as_transaction().output[tx_add_input_msg.prevtx_out as usize].value;
        assert_eq!(input_value.to_sat(), session.acceptor_input_value_satoshis);
        nodes[0].node.handle_tx_add_input(&nodes[1].node.get_our_node_id(), &tx_add_input_msg);
    } else {
    */
        let tx_complete_msg = get_event_msg!(nodes[1], MessageSendEvent::SendTxComplete, nodes[0].node.get_our_node_id());
        assert_eq!(tx_complete_msg.channel_id.to_string(), "0df1425050bb045209e23459ebb5f9c8f6f219dafb85e2ec59d5fe841f1c4463");
        let channel_id = tx_complete_msg.channel_id;

        nodes[0].node.handle_tx_complete(&nodes[1].node.get_our_node_id(), &tx_complete_msg);
    // };

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
    if let Event::FundingTransactionReadyForSigning {
        channel_id,
        counterparty_node_id,
        mut unsigned_transaction,
        ..
    } = get_event!(nodes[0], Event::FundingTransactionReadyForSigning) {
        assert_eq!(counterparty_node_id, nodes[1].node.get_our_node_id());
        assert_eq!(channel_id.to_string(), expected_funded_channel_id);

        let mut witness = Witness::new();
        witness.push(vec![0]);
        unsigned_transaction.input[0].witness = witness;

        nodes[0].node.funding_transaction_signed(&channel_id, &counterparty_node_id, unsigned_transaction).unwrap();
    } else { panic!(); }

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

    /*
    if acceptor_will_fund {
        if let Event::FundingTransactionReadyForSigning {
            channel_id,
            counterparty_node_id,
            mut unsigned_transaction,
            ..
        } = get_event!(nodes[1], Event::FundingTransactionReadyForSigning) {
            assert_eq!(counterparty_node_id, nodes[0].node.get_our_node_id());

            let mut witness = Witness::new();
            witness.push(vec![0]);
            unsigned_transaction.input[0].witness = witness;

            nodes[1].node.funding_transaction_signed(&channel_id, &counterparty_node_id, unsigned_transaction).unwrap();
        } else { panic!(); }
    }
    */

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

    /*
    if session.initiator_input_value_satoshis < session.acceptor_input_value_satoshis
        || session.initiator_input_value_satoshis == session.acceptor_input_value_satoshis
        && nodes[0].node.our_network_pubkey.serialize() < nodes[1].node.our_network_pubkey.serialize() {
        // Alice contributed less input value than Bob so he should send tx_signatures only after
        // receiving tx_signatures from Alice.
        tx_signatures_exchange(0, 1);
    } else {
        // Alice contributed more input value than Bob so she should send tx_signatures only after
        // receiving tx_signatures from Bob.
        tx_signatures_exchange(1, 0);
    }
    */
    tx_signatures_exchange(1, 0);

    let tx_1 = {
        let tx_0 = &nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap()[0];
        let tx_1 = &nodes[1].tx_broadcaster.txn_broadcasted.lock().unwrap()[0];
        assert_eq!(tx_0, tx_1);
        tx_0.clone()
    };

    // Initiator sends an RBF
    let rbf_2nd_rate = 700;
    let res_channel_id = nodes[0].node.rbf_pending_v2_channel_open(
        nodes[1].node.get_our_node_id(),
        channel_id,
        initiator_funding_inputs,
        rbf_2nd_rate,
        42,
        None,
    ).unwrap();
    assert_eq!(res_channel_id.to_string(), expected_funded_channel_id);

    let rbf_msg = get_event_msg!(nodes[0], MessageSendEvent::SendTxInitRbf, nodes[1].node.get_our_node_id());

    assert_eq!(nodes[0].node.list_channels().len(), 1);

    // handle init_rbf on acceptor side
    let _res = nodes[1].node.handle_tx_init_rbf(&nodes[0].node.get_our_node_id(), &rbf_msg);

    // Confirm 1st tx
    let (channel_ready, _) = create_chan_between_nodes_with_value_confirm(&nodes[0], &nodes[1], &tx_1);
    let (announcement, nodes_0_update, nodes_1_update) = create_chan_between_nodes_with_value_b(&nodes[0], &nodes[1], &channel_ready);
    update_nodes_with_chan_announce(&nodes, 0, 1, &announcement, &nodes_0_update, &nodes_1_update);

    panic!("OK, panic just for logs"); // TODO remove
}
