use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, traits::Identity};
use ed25519_dalek::{Signature, Signer, SigningKey};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use upspa_quorum_bench::crypto;
use upspa_quorum_bench::crypto::CtBlob;
use upspa_quorum_bench::protocols::messages::{
    encode_roupspa_account_record, encode_roupspa_identification_record, ProtocolStage, WaitPolicy,
    ACCOUNT_PLAINTEXT_LEN, IDENTIFICATION_PLAINTEXT_LEN,
};
use upspa_quorum_bench::protocols::provider::{
    ProviderError, ReplicaStatus, RoUpSpaProvider, SignedAccountRecord, SignedIdentificationRecord,
};
use upspa_quorum_bench::protocols::roupspa::{
    minimum_quorum_size, validate_thresholds, InFlightOperation, PhaseError, PhaseResult, RoUpSpaSystem,
};

fn seed(value: u8) -> [u8; 32] {
    [value; 32]
}

fn assert_completed(result: &PhaseResult) {
    assert!(matches!(result, PhaseResult::Completed { .. }), "{result:?}");
}

fn setup_system(nsp: usize, tsp: usize, qsp: usize) -> RoUpSpaSystem {
    let mut system = RoUpSpaSystem::new(nsp, tsp, qsp, seed(nsp as u8)).unwrap();
    assert_completed(&system.setup());
    system
}

fn blob<const N: usize>(byte: u8) -> CtBlob<N> {
    CtBlob {
        nonce: [byte; 24],
        ct: [byte.wrapping_add(1); N],
        tag: [byte.wrapping_add(2); 16],
    }
}

fn standalone_provider() -> (RoUpSpaProvider, Vec<u8>, SigningKey) {
    let uid = b"variable-length-user".to_vec();
    let signing_key = SigningKey::from_bytes(&seed(91));
    let setup = SignedIdentificationRecord {
        cid: blob::<IDENTIFICATION_PLAINTEXT_LEN>(1),
        ctrid: 0,
        signature: None,
    };
    let mut provider = RoUpSpaProvider::new(1);
    provider
        .install_setup(&uid, signing_key.verifying_key(), setup, Scalar::from(7_u64))
        .unwrap();
    (provider, uid, signing_key)
}

fn signed_account(
    signing_key: &SigningKey,
    uid: &[u8],
    suid: [u8; 32],
    ctr: u64,
    marker: u8,
) -> SignedAccountRecord {
    let cj = blob::<ACCOUNT_PLAINTEXT_LEN>(marker);
    let signature = signing_key.sign(&encode_roupspa_account_record(uid, &suid, &cj, ctr));
    SignedAccountRecord {
        uid: uid.to_vec(),
        suid,
        cj,
        ctr,
        signature,
    }
}

fn recover_setup_state(system: &RoUpSpaSystem) -> (SigningKey, [u8; 32], [u8; 32], [u8; 32]) {
    let ids: Vec<u32> = system
        .providers
        .iter()
        .take(system.tsp)
        .map(|provider| provider.id)
        .collect();
    let lambdas = crypto::lagrange_coeffs_at_zero(&ids);
    let top_key = system
        .providers
        .iter()
        .take(system.tsp)
        .zip(lambdas)
        .fold(Scalar::ZERO, |sum, (provider, lambda)| {
            sum + provider.share(&system.uid).unwrap() * lambda
        });
    let state_key = crypto::oprf_finalize(
        &system.password,
        &(crypto::hash_to_point(&system.password) * top_key),
    );
    let mut aad = system.uid.clone();
    aad.extend_from_slice(b"|cipherid");
    let current = &system.providers[0].identifications[&system.uid].current;
    let plaintext = crypto::xchacha_decrypt_detached(&state_key, &aad, &current.cid).unwrap();
    let mut ssk_bytes = [0; 32];
    ssk_bytes.copy_from_slice(&plaintext[0..32]);
    let mut rsp = [0; 32];
    rsp.copy_from_slice(&plaintext[32..64]);
    let mut k0 = [0; 32];
    k0.copy_from_slice(&plaintext[64..96]);
    (SigningKey::from_bytes(&ssk_bytes), rsp, k0, state_key)
}

fn identification_plaintext(
    signing_key: &SigningKey,
    rsp: &[u8; 32],
    k0: &[u8; 32],
    counter: u64,
) -> [u8; IDENTIFICATION_PLAINTEXT_LEN] {
    let mut plaintext = [0; IDENTIFICATION_PLAINTEXT_LEN];
    plaintext[0..32].copy_from_slice(&signing_key.to_bytes());
    plaintext[32..64].copy_from_slice(rsp);
    plaintext[64..96].copy_from_slice(k0);
    plaintext[96..104].copy_from_slice(&counter.to_le_bytes());
    plaintext
}

#[test]
fn threshold_validation_uses_strict_intersection_without_majority_tsp() {
    assert!(validate_thresholds(7, 2, 5).is_ok());
    assert!(validate_thresholds(7, 2, 4).is_err());
    assert!(validate_thresholds(5, 1, 3).is_ok());
    assert_eq!(minimum_quorum_size(7, 2).unwrap(), 5);
    assert!(validate_thresholds(5, 3, 2).is_err());
}

#[test]
fn setup_requires_all_and_duplicate_is_rejected() {
    let mut unavailable = RoUpSpaSystem::new(3, 2, 3, seed(1)).unwrap();
    unavailable.providers[2].reachable = false;
    assert!(matches!(
        unavailable.setup(),
        PhaseResult::Aborted {
            error: PhaseError::SetupRequiresAllProviders,
            ..
        }
    ));
    assert!(unavailable
        .providers
        .iter()
        .all(|provider| { !provider.identifications.contains_key(&unavailable.uid) }));

    let mut system = setup_system(3, 2, 3);
    for provider in &system.providers {
        let replica = provider.identifications.get(&system.uid).unwrap();
        assert_eq!(replica.current.ctrid, 0);
        assert_eq!(replica.status, ReplicaStatus::Active);
        assert!(replica.current.signature.is_none());
    }
    assert!(matches!(
        system.setup(),
        PhaseResult::Aborted {
            error: PhaseError::DuplicateSetup,
            ..
        }
    ));
}

#[test]
fn account_signatures_bind_every_field_and_counters_are_exact() {
    let (mut provider, uid, signing_key) = standalone_provider();
    let suid = [4; 32];
    let registration = signed_account(&signing_key, &uid, suid, 0, 10);
    provider
        .accept_registration_account(registration.clone())
        .unwrap();
    provider
        .accept_registration_account(registration.clone())
        .unwrap();

    let conflicting = signed_account(&signing_key, &uid, suid, 0, 11);
    assert_eq!(
        provider.accept_registration_account(conflicting),
        Err(ProviderError::ConflictingRecord)
    );
    let nonzero_registration = signed_account(&signing_key, &uid, [5; 32], 1, 12);
    assert!(matches!(
        provider.accept_registration_account(nonzero_registration),
        Err(ProviderError::WrongCounter {
            expected: 0,
            received: 1
        })
    ));

    let update = signed_account(&signing_key, &uid, suid, 1, 13);
    provider.accept_secret_update_account(update.clone()).unwrap();
    provider.accept_secret_update_account(update.clone()).unwrap();
    let skipped = signed_account(&signing_key, &uid, suid, 3, 14);
    assert!(matches!(
        provider.accept_secret_update_account(skipped),
        Err(ProviderError::WrongCounter {
            expected: 2,
            received: 3
        })
    ));
    let lower = signed_account(&signing_key, &uid, suid, 0, 15);
    assert!(matches!(
        provider.accept_secret_update_account(lower),
        Err(ProviderError::WrongCounter {
            expected: 2,
            received: 0
        })
    ));

    let mut tampered_uid = update.clone();
    tampered_uid.uid.push(0);
    assert!(matches!(
        provider.accept_secret_update_account(tampered_uid),
        Err(ProviderError::MissingIdentification | ProviderError::InvalidSignature)
    ));
    let mut tampered_suid = update.clone();
    tampered_suid.suid[0] ^= 1;
    assert_eq!(
        provider.accept_secret_update_account(tampered_suid),
        Err(ProviderError::InvalidSignature)
    );
    let mut tampered_ciphertext = update.clone();
    tampered_ciphertext.cj.ct[0] ^= 1;
    assert_eq!(
        provider.accept_secret_update_account(tampered_ciphertext),
        Err(ProviderError::InvalidSignature)
    );
    let mut tampered_counter = update;
    tampered_counter.ctr = 2;
    assert_eq!(
        provider.accept_secret_update_account(tampered_counter),
        Err(ProviderError::InvalidSignature)
    );
}

#[test]
fn tentative_identification_is_hidden_and_store_keeps_share() {
    let (mut provider, uid, signing_key) = standalone_provider();
    let old_share = provider.share(&uid).unwrap().to_bytes();
    let setup_record = provider.identifications[&uid].current.clone();
    let cid = blob::<IDENTIFICATION_PLAINTEXT_LEN>(31);
    let signature = signing_key.sign(&encode_roupspa_identification_record(&uid, &cid, 1));
    let update = SignedIdentificationRecord {
        cid,
        ctrid: 1,
        signature: Some(signature),
    };
    assert!(matches!(
        provider.accept_tentative_identification(&uid, setup_record),
        Err(ProviderError::WrongCounter {
            expected: 1,
            received: 0
        })
    ));
    provider.identifications.get_mut(&uid).unwrap().status = ReplicaStatus::Stale;
    assert_eq!(
        provider.accept_tentative_identification(&uid, update.clone()),
        Err(ProviderError::Stale)
    );
    provider.identifications.get_mut(&uid).unwrap().status = ReplicaStatus::Active;
    provider
        .accept_tentative_identification(&uid, update.clone())
        .unwrap();
    provider
        .accept_tentative_identification(&uid, update.clone())
        .unwrap();
    let response = provider
        .identification_response(&uid, Some(&RistrettoPoint::identity()))
        .unwrap();
    assert_eq!(response.current.ctrid, 0);
    provider.store_tentative_identification(&uid, &update).unwrap();
    assert_eq!(provider.identifications[&uid].current, update);
    assert_eq!(provider.share(&uid).unwrap().to_bytes(), old_share);
    let committed = provider.identifications[&uid].current.clone();
    assert!(matches!(
        provider.accept_tentative_identification(&uid, committed),
        Err(ProviderError::WrongCounter {
            expected: 2,
            received: 1
        })
    ));
}

#[test]
fn account_step_targets_are_nonempty_deduplicated_and_prevalidated() {
    let mut system = setup_system(5, 2, 4);
    let key = system.begin_registration().unwrap();
    let prepared = system.account_operation_state(&key);
    let trace = system.last_trace.clone();
    let accounts = system
        .providers
        .iter()
        .map(|provider| provider.accounts.clone())
        .collect::<Vec<_>>();

    assert_eq!(
        system.attempt_registration_write(&key, &[]),
        Err(PhaseError::EmptyProviderTargets)
    );
    assert_eq!(system.account_operation_state(&key), prepared);
    assert_eq!(system.last_trace, trace);
    assert_eq!(
        system
            .providers
            .iter()
            .map(|provider| provider.accounts.clone())
            .collect::<Vec<_>>(),
        accounts
    );

    let invalid = system.providers.len();
    assert_eq!(
        system.attempt_registration_write(&key, &[0, invalid]),
        Err(PhaseError::InvalidProviderIndex(invalid))
    );
    assert_eq!(system.account_operation_state(&key), prepared);
    assert_eq!(system.last_trace, trace);
    assert_eq!(
        system
            .providers
            .iter()
            .map(|provider| provider.accounts.clone())
            .collect::<Vec<_>>(),
        accounts
    );

    let ready = system
        .attempt_registration_write(&key, &[0, 0, 1, 2, 3, 3])
        .unwrap();
    assert!(matches!(
        ready,
        PhaseResult::ReadyForTerminalStore {
            acknowledgements: 4,
            ..
        }
    ));
    let write = ready
        .trace()
        .events
        .iter()
        .find(|event| event.stage == ProtocolStage::ProviderQuorumWrite)
        .unwrap();
    assert_eq!(write.recipient_count, 4);
    assert_eq!(write.acknowledgements, 4);
}

#[test]
fn password_step_targets_are_nonempty_and_prevalidated() {
    let mut system = setup_system(5, 2, 4);
    system.begin_password_update().unwrap();
    let prepared = system.identification_operation_state();
    let trace = system.last_trace.clone();
    let identifications = system
        .providers
        .iter()
        .map(|provider| provider.identifications.clone())
        .collect::<Vec<_>>();

    assert_eq!(
        system.attempt_password_update_write(&[]),
        Err(PhaseError::EmptyProviderTargets)
    );
    assert_eq!(system.identification_operation_state(), prepared);
    assert_eq!(system.last_trace, trace);

    let invalid = system.providers.len();
    assert_eq!(
        system.attempt_password_update_write(&[0, invalid]),
        Err(PhaseError::InvalidProviderIndex(invalid))
    );
    assert_eq!(system.identification_operation_state(), prepared);
    assert_eq!(system.last_trace, trace);
    assert_eq!(
        system
            .providers
            .iter()
            .map(|provider| provider.identifications.clone())
            .collect::<Vec<_>>(),
        identifications
    );

    assert!(matches!(
        system.attempt_password_update_write(&[0, 0, 1, 2, 3, 3]).unwrap(),
        PhaseResult::ReadyForTerminalStore {
            acknowledgements: 4,
            ..
        }
    ));
}

#[test]
fn registration_order_shared_suid_and_terminal_is_one_way() {
    let mut system = setup_system(5, 2, 4);
    let result = system.registration();
    assert_completed(&result);
    assert_eq!(
        result.trace().stages(),
        vec![
            ProtocolStage::Identification,
            ProtocolStage::LsPrepare,
            ProtocolStage::ProviderQuorumWrite,
            ProtocolStage::LsTerminalDelivery,
        ]
    );
    assert!(result.trace().terminal_events_have_no_response());
    let keys: Vec<_> = system
        .providers
        .iter()
        .flat_map(|provider| provider.accounts.keys())
        .collect();
    assert!(!keys.is_empty());
    assert!(keys.iter().all(|key| key.suid == keys[0].suid));
    assert!(system.authenticate().unwrap());
}

#[test]
fn ls_prepare_rejection_precedes_and_prevents_provider_writes() {
    let mut system = setup_system(5, 2, 4);
    system.login_server.current.insert(system.uid.clone(), [99; 32]);
    assert!(matches!(
        system.registration(),
        PhaseResult::Aborted {
            error: PhaseError::LoginServerRejected(_),
            ..
        }
    ));
    assert!(system
        .providers
        .iter()
        .all(|provider| provider.accounts.is_empty()));
}

#[test]
fn partial_write_is_unresolved_frozen_and_blocks_family() {
    let mut system = setup_system(5, 2, 4);
    system.providers[0].reachable = false;
    system.providers[1].reachable = false;
    let result = system.registration();
    let (digest, acknowledgements) = match result {
        PhaseResult::Unresolved {
            record_digest,
            acknowledgements,
            required: 4,
            ..
        } => (record_digest, acknowledgements),
        other => panic!("expected unresolved, got {other:?}"),
    };
    assert_eq!(acknowledgements, 3);
    let key = system.any_account_family().unwrap();
    assert!(matches!(
        system.account_operation_state(&key),
        InFlightOperation::ProviderWriteStarted { .. }
    ));
    assert_eq!(
        system.abort_account_before_write(&key),
        Err(PhaseError::DiscardForbidden)
    );
    assert_eq!(system.authenticate(), Err(PhaseError::OperationInFlight));
    assert_eq!(
        system.synchronize_account(&system.uid.clone(), key.suid, 0),
        Err(PhaseError::OperationInFlight)
    );

    system.providers[0].reachable = true;
    let retried = system.retry_inflight_account_write(&key, &[0]).unwrap();
    assert!(matches!(
        retried,
        PhaseResult::ReadyForTerminalStore {
            record_digest,
            acknowledgements: 4,
            ..
        } if record_digest == digest
    ));
    let write_events = retried
        .trace()
        .events
        .iter()
        .filter(|event| event.stage == ProtocolStage::ProviderQuorumWrite)
        .collect::<Vec<_>>();
    assert_eq!(write_events.len(), 2);
    assert_eq!(
        write_events
            .iter()
            .map(|event| event.acknowledgements)
            .collect::<Vec<_>>(),
        vec![3, 1]
    );
    assert!(write_events
        .iter()
        .all(|event| event.wait_policy == WaitPolicy::Quorum(4)));
    assert_eq!(retried.trace().acknowledgement_count(), 2 + 1 + 3 + 1);
    assert_completed(&system.deliver_account_store(&key).unwrap());
    assert_eq!(
        system.providers[1].account_status(&key),
        Some(ReplicaStatus::Stale)
    );
}

#[test]
fn prewrite_account_abort_discards_only_ls_prepare() {
    let mut system = setup_system(5, 2, 4);
    let key = system.begin_registration().unwrap();
    assert!(system.login_server.pending.contains_key(&system.uid));
    system.abort_account_before_write(&key).unwrap();
    assert!(!system.login_server.pending.contains_key(&system.uid));
    assert!(!system.login_server.current.contains_key(&system.uid));
    assert!(system
        .providers
        .iter()
        .all(|provider| provider.accounts.is_empty()));
}

#[test]
fn unresolved_password_write_blocks_and_retries_identical_tuple() {
    let mut system = setup_system(5, 2, 4);
    let shares = system.provider_share_bytes();
    system.providers[0].reachable = false;
    system.providers[1].reachable = false;
    let result = system.password_update();
    assert!(matches!(
        result,
        PhaseResult::Unresolved {
            acknowledgements: 3,
            required: 4,
            ..
        }
    ));
    assert_eq!(
        system.abort_password_update_before_write(),
        Err(PhaseError::DiscardForbidden)
    );
    assert_eq!(system.authenticate(), Err(PhaseError::OperationInFlight));
    assert_eq!(
        system.synchronize_identification(0),
        Err(PhaseError::OperationInFlight)
    );
    system.providers[0].reachable = true;
    let retried = system.retry_inflight_password_write(&[0]).unwrap();
    assert!(matches!(
        retried,
        PhaseResult::ReadyForTerminalStore {
            acknowledgements: 4,
            ..
        }
    ));
    let write_events = retried
        .trace()
        .events
        .iter()
        .filter(|event| event.stage == ProtocolStage::QuorumTentativeWrites)
        .collect::<Vec<_>>();
    assert_eq!(
        write_events
            .iter()
            .map(|event| event.acknowledgements)
            .collect::<Vec<_>>(),
        vec![3, 1]
    );
    assert!(write_events
        .iter()
        .all(|event| event.wait_policy == WaitPolicy::Quorum(4)));
    assert_eq!(retried.trace().acknowledgement_count(), 2 + 2 + 3 + 1);
    assert_completed(&system.deliver_password_update_store().unwrap());
    assert_eq!(shares, system.provider_share_bytes());
}

#[test]
fn secret_update_is_direct_but_ls_old_verifier_stays_current_until_store() {
    let mut system = setup_system(5, 2, 4);
    assert_completed(&system.registration());
    let old_vinfo = system.login_server.current_verifier(&system.uid).unwrap();
    let key = system.begin_secret_update().unwrap();
    assert_eq!(system.login_server.current_verifier(&system.uid), Some(old_vinfo));
    let old_record = system.providers[0].accounts[&key].current.clone().unwrap();
    let ready = system.attempt_secret_update_write(&key, &[0, 1, 2, 3]).unwrap();
    assert!(matches!(ready, PhaseResult::ReadyForTerminalStore { .. }));
    let new_record = system.providers[0].accounts[&key].current.clone().unwrap();
    assert_eq!(new_record.ctr, old_record.ctr + 1);
    assert_ne!(new_record, old_record);
    assert_eq!(system.login_server.current_verifier(&system.uid), Some(old_vinfo));
    assert_completed(&system.deliver_account_store(&key).unwrap());
    assert_ne!(system.login_server.current_verifier(&system.uid), Some(old_vinfo));
}

#[test]
fn password_update_uses_same_shares_and_has_no_final_ack() {
    let mut system = setup_system(5, 2, 4);
    let old_shares = system.provider_share_bytes();
    let result = system.password_update();
    assert_completed(&result);
    assert_eq!(old_shares, system.provider_share_bytes());
    assert_eq!(
        result.trace().stages(),
        vec![
            ProtocolStage::IdentificationOld,
            ProtocolStage::ToprfNewSameShares,
            ProtocolStage::QuorumTentativeWrites,
            ProtocolStage::OneWayProviderStore,
        ]
    );
    assert!(result.trace().terminal_events_have_no_response());
    assert!(system.providers.iter().all(|provider| {
        provider.identifications[&system.uid]
            .tentative_identification
            .is_none()
    }));
}

#[test]
fn authentication_needs_tsp_active_valid_accounts_without_writeback() {
    let mut system = setup_system(5, 2, 4);
    assert_completed(&system.registration());
    let before: Vec<_> = system
        .providers
        .iter()
        .map(|provider| provider.accounts.clone())
        .collect();
    system.providers[0].reachable = false;
    system.providers[1].reachable = false;
    system.providers[2].reachable = false;
    assert!(system.authenticate().unwrap());
    assert_eq!(
        before,
        system
            .providers
            .iter()
            .map(|provider| provider.accounts.clone())
            .collect::<Vec<_>>()
    );
    system.providers[3].reachable = false;
    assert!(matches!(
        system.authenticate(),
        Err(PhaseError::NotEnoughValidResponses {
            valid: 1,
            required: 2
        })
    ));
}

#[test]
fn synchronization_counts_valid_records_and_preserves_share() {
    let mut system = setup_system(7, 2, 5);
    system.providers[5].reachable = false;
    system.providers[6].reachable = false;
    assert_completed(&system.registration());
    let key = system.any_account_family().unwrap();
    system.providers[5].reachable = true;
    let share_before = system.providers[5].share(&system.uid).unwrap().to_bytes();

    let original_signature = system.providers[0].accounts[&key]
        .current
        .as_ref()
        .unwrap()
        .signature;
    system.providers[0]
        .accounts
        .get_mut(&key)
        .unwrap()
        .current
        .as_mut()
        .unwrap()
        .signature = Signature::from_bytes(&[0; 64]);
    assert!(matches!(
        system.synchronize_account(&system.uid.clone(), key.suid, 5),
        Err(PhaseError::NotEnoughValidResponses {
            valid: 4,
            required: 5
        })
    ));
    assert_eq!(
        system.providers[5].account_status(&key),
        Some(ReplicaStatus::Stale)
    );
    system.providers[0]
        .accounts
        .get_mut(&key)
        .unwrap()
        .current
        .as_mut()
        .unwrap()
        .signature = original_signature;
    let outcome = system
        .synchronize_account(&system.uid.clone(), key.suid, 5)
        .unwrap();
    assert_eq!(outcome.valid_responses, 5);
    assert_eq!(
        system.providers[5].account_status(&key),
        Some(ReplicaStatus::Active)
    );
    assert_eq!(
        system.providers[5].share(&system.uid).unwrap().to_bytes(),
        share_before
    );
}

#[test]
fn chained_seven_two_five_account_recovery_uses_repaired_replica() {
    let mut system = setup_system(7, 2, 5);
    system.providers[5].reachable = false;
    system.providers[6].reachable = false;
    assert_completed(&system.registration());
    let key = system.any_account_family().unwrap();
    system.providers[5].reachable = true;
    system
        .synchronize_account(&system.uid.clone(), key.suid, 5)
        .unwrap();
    let recovered_six = system.providers[5].accounts[&key].current.clone().unwrap();

    system.providers[0].reachable = false;
    system.providers[6].reachable = true;
    system
        .synchronize_account(&system.uid.clone(), key.suid, 6)
        .unwrap();
    let recovered_seven = system.providers[6].accounts[&key].current.clone().unwrap();
    assert_eq!(recovered_six, recovered_seven);
    assert_eq!(
        system.providers[5].account_status(&key),
        Some(ReplicaStatus::Active)
    );
    assert_eq!(
        system.providers[6].account_status(&key),
        Some(ReplicaStatus::Active)
    );
}

#[test]
fn identification_synchronization_verifies_positive_counter_and_keeps_share() {
    let mut system = setup_system(7, 2, 5);
    system.providers[5].reachable = false;
    system.providers[6].reachable = false;
    assert_completed(&system.password_update());
    system.providers[5].reachable = true;
    let share = system.providers[5].share(&system.uid).unwrap().to_bytes();
    let outcome = system.synchronize_identification(5).unwrap();
    assert_eq!(outcome.installed_counter, 1);
    assert_eq!(
        system.providers[5].identification_status(&system.uid),
        Some(ReplicaStatus::Active)
    );
    assert_eq!(system.providers[5].share(&system.uid).unwrap().to_bytes(), share);
}

#[test]
fn synchronization_requires_the_recovering_provider_to_be_reachable() {
    let mut system = setup_system(7, 2, 5);
    assert_completed(&system.registration());
    let key = system.any_account_family().unwrap();
    system.providers[6].reachable = false;

    assert_eq!(
        system.synchronize_identification(6),
        Err(PhaseError::ProviderRejected(ProviderError::Unreachable))
    );
    assert_eq!(
        system.synchronize_account(&system.uid.clone(), key.suid, 6),
        Err(PhaseError::ProviderRejected(ProviderError::Unreachable))
    );
}

#[test]
fn identification_synchronization_can_restore_a_missing_root_without_changing_its_share() {
    let mut system = setup_system(7, 2, 5);
    system.providers[5].reachable = false;
    system.providers[6].reachable = false;
    assert_completed(&system.password_update());

    system.providers[5].reachable = true;
    let share = system.providers[5].share(&system.uid).unwrap().to_bytes();
    assert!(system.providers[5].identifications.remove(&system.uid).is_some());
    assert!(!system.providers[5].identifications.contains_key(&system.uid));

    let outcome = system.synchronize_identification(5).unwrap();
    assert_eq!(outcome.installed_counter, 1);
    assert_eq!(
        system.providers[5].identification_status(&system.uid),
        Some(ReplicaStatus::Active)
    );
    assert_eq!(system.providers[5].share(&system.uid).unwrap().to_bytes(), share);
}

#[test]
fn identification_rejects_internal_counter_mismatch_and_tied_maximum() {
    let mut system = setup_system(4, 2, 3);
    let (signing_key, rsp, k0, state_key) = recover_setup_state(&system);
    let mut rng = ChaCha20Rng::from_seed(seed(77));
    let mut aad = system.uid.clone();
    aad.extend_from_slice(b"|cipherid");

    let mismatched_plaintext = identification_plaintext(&signing_key, &rsp, &k0, 9);
    let mismatched_cid = crypto::xchacha_encrypt_detached(&state_key, &aad, &mismatched_plaintext, &mut rng);
    let mismatched_signature = signing_key.sign(&encode_roupspa_identification_record(
        &system.uid,
        &mismatched_cid,
        1,
    ));
    let mismatched = SignedIdentificationRecord {
        cid: mismatched_cid,
        ctrid: 1,
        signature: Some(mismatched_signature),
    };
    for provider in &mut system.providers {
        provider.identifications.get_mut(&system.uid).unwrap().current = mismatched.clone();
    }
    assert_eq!(
        system.authenticate(),
        Err(PhaseError::ExternalInternalCounterMismatch {
            external: 1,
            internal: 9
        })
    );

    let make_record = |rng: &mut ChaCha20Rng| {
        let plaintext = identification_plaintext(&signing_key, &rsp, &k0, 1);
        let cid = crypto::xchacha_encrypt_detached(&state_key, &aad, &plaintext, rng);
        let signature = signing_key.sign(&encode_roupspa_identification_record(&system.uid, &cid, 1));
        SignedIdentificationRecord {
            cid,
            ctrid: 1,
            signature: Some(signature),
        }
    };
    let first = make_record(&mut rng);
    let second = make_record(&mut rng);
    for provider in &mut system.providers[..2] {
        provider.identifications.get_mut(&system.uid).unwrap().current = first.clone();
    }
    for provider in &mut system.providers[2..] {
        provider.identifications.get_mut(&system.uid).unwrap().current = second.clone();
    }
    assert_eq!(
        system.authenticate(),
        Err(PhaseError::ConflictingMaximum {
            family: "identification",
            counter: 1
        })
    );
}

#[test]
fn account_read_rejects_tied_maximum_and_internal_counter_mismatch() {
    let mut system = setup_system(4, 2, 3);
    assert_completed(&system.registration());
    let key = system.any_account_family().unwrap();
    let (signing_key, _rsp, k0, _state_key) = recover_setup_state(&system);
    let mut aad = system.uid.clone();
    aad.extend_from_slice(b"|ciphersp");
    let mut rng = ChaCha20Rng::from_seed(seed(78));
    let make_record = |rlsj: [u8; 32], internal: u64, external: u64, rng: &mut ChaCha20Rng| {
        let mut plaintext = [0; ACCOUNT_PLAINTEXT_LEN];
        plaintext[0..32].copy_from_slice(&rlsj);
        plaintext[32..40].copy_from_slice(&internal.to_le_bytes());
        let cj = crypto::xchacha_encrypt_detached(&k0, &aad, &plaintext, rng);
        let signature = signing_key.sign(&encode_roupspa_account_record(
            &system.uid,
            &key.suid,
            &cj,
            external,
        ));
        SignedAccountRecord {
            uid: system.uid.clone(),
            suid: key.suid,
            cj,
            ctr: external,
            signature,
        }
    };

    let mismatched = make_record([1; 32], 7, 1, &mut rng);
    for provider in &mut system.providers {
        provider.accept_secret_update_account(mismatched.clone()).unwrap();
    }
    assert!(matches!(
        system.authenticate(),
        Err(PhaseError::NotEnoughValidResponses {
            valid: 0,
            required: 2
        })
    ));

    // Use a fresh fixture to install two distinct valid ctr=1 records.
    let mut fresh = setup_system(4, 2, 3);
    assert_completed(&fresh.registration());
    let fresh_key = fresh.any_account_family().unwrap();
    let old = fresh.providers[0].accounts[&fresh_key].current.clone().unwrap();
    let (fresh_signing_key, _, fresh_k0, _) = recover_setup_state(&fresh);
    let mut fresh_aad = fresh.uid.clone();
    fresh_aad.extend_from_slice(b"|ciphersp");
    let make_fresh = |rlsj: [u8; 32], rng: &mut ChaCha20Rng| {
        let mut plaintext = [0; ACCOUNT_PLAINTEXT_LEN];
        plaintext[0..32].copy_from_slice(&rlsj);
        plaintext[32..40].copy_from_slice(&1_u64.to_le_bytes());
        let cj = crypto::xchacha_encrypt_detached(&fresh_k0, &fresh_aad, &plaintext, rng);
        let signature = fresh_signing_key.sign(&encode_roupspa_account_record(
            &fresh.uid,
            &fresh_key.suid,
            &cj,
            1,
        ));
        SignedAccountRecord {
            uid: fresh.uid.clone(),
            suid: fresh_key.suid,
            cj,
            ctr: 1,
            signature,
        }
    };
    let first = make_fresh([3; 32], &mut rng);
    let second = make_fresh([4; 32], &mut rng);
    for provider in &mut fresh.providers[..2] {
        provider.accounts.get_mut(&fresh_key).unwrap().current = Some(old.clone());
        provider.accept_secret_update_account(first.clone()).unwrap();
    }
    for provider in &mut fresh.providers[2..] {
        provider.accounts.get_mut(&fresh_key).unwrap().current = Some(old.clone());
        provider.accept_secret_update_account(second.clone()).unwrap();
    }
    assert_eq!(
        fresh.authenticate(),
        Err(PhaseError::ConflictingMaximum {
            family: "account",
            counter: 1
        })
    );
}

#[test]
fn canonical_uid_encoding_is_unambiguous() {
    let cj = blob::<ACCOUNT_PLAINTEXT_LEN>(1);
    let one = encode_roupspa_account_record(b"a", &[0; 32], &cj, 0);
    let two = encode_roupspa_account_record(b"a\0", &[0; 32], &cj, 0);
    assert_ne!(one, two);
    assert_eq!(&one[..4], &1_u32.to_le_bytes());
    assert_eq!(&two[..4], &2_u32.to_le_bytes());
}
