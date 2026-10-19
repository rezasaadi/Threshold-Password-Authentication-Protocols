//! These passing tests reproduce limitations of the protocol and baseline implementation.
//! They deliberately preserve the prescribed t-only read threshold. They are
//! evidence for PROTOCOL_GAPS.md, not assertions that these outcomes are safe.

use upspa_quorum_bench::protocols::provider::ReplicaStatus;
use upspa_quorum_bench::protocols::roupspa::{PhaseError, PhaseResult, RoUpSpaSystem};

fn fixture() -> RoUpSpaSystem {
    let mut system = RoUpSpaSystem::new(7, 2, 5, [48; 32]).unwrap();
    assert!(system.setup().is_completed());
    assert!(system.registration().is_completed());
    system
}

#[test]
fn undetected_missed_password_write_allows_old_password_threshold_authentication() {
    let mut system = fixture();
    let old_password = system.password.clone();
    // Real independent endpoints 6 and 7 receive no application write or Store,
    // and have no local outage indication. Preserve their own prior states.
    let missed = system.providers[5..].to_vec();
    system.begin_password_update().unwrap();
    assert!(matches!(
        system.attempt_password_update_write(&[0, 1, 2, 3, 4]).unwrap(),
        PhaseResult::ReadyForTerminalStore {
            acknowledgements: 5,
            ..
        }
    ));
    assert!(system.deliver_password_update_store().unwrap().is_completed());
    assert_eq!(
        system.providers[5].identification_status(&system.uid),
        Some(ReplicaStatus::Stale)
    );
    // The centralized status assignment above cannot reach a provider which
    // received no message. Restore exactly what those endpoints actually hold.
    for (provider, own_state) in system.providers[5..].iter_mut().zip(missed) {
        *provider = own_state;
    }
    for provider in &mut system.providers[..5] {
        provider.reachable = false;
    }
    assert_eq!(system.providers[5].identifications[&system.uid].current.ctrid, 0);
    assert_eq!(
        system.providers[5].identification_status(&system.uid),
        Some(ReplicaStatus::Active)
    );
    system.password = old_password;
    assert_eq!(
        system.authenticate(),
        Ok(true),
        "old password succeeds against the missed threshold"
    );
    system.password = system.new_password.clone();
    assert_eq!(system.authenticate(), Err(PhaseError::DecryptFailed));
}

#[test]
fn undetected_missed_secret_write_selects_old_account_and_login_server_rejects() {
    let mut system = fixture();
    let missed = system.providers[5..].to_vec();
    let key = system.begin_secret_update().unwrap();
    assert!(matches!(
        system
            .attempt_secret_update_write(&key, &[0, 1, 2, 3, 4])
            .unwrap(),
        PhaseResult::ReadyForTerminalStore {
            acknowledgements: 5,
            ..
        }
    ));
    assert!(system.deliver_account_store(&key).unwrap().is_completed());
    for (provider, own_state) in system.providers[5..].iter_mut().zip(missed) {
        *provider = own_state;
    }
    for provider in &mut system.providers[..5] {
        provider.reachable = false;
    }
    assert_eq!(
        system.providers[5].accounts[&key].current.as_ref().unwrap().ctr,
        0
    );
    // This exposes stale record selection, but does not claim that the old
    // login verifier is accepted after a completed Secret Update.
    assert_eq!(system.authenticate(), Ok(false));
}

#[test]
fn independent_synchronization_can_install_direct_write_before_login_server_store() {
    let mut writer = fixture();
    let old_verifier = writer.login_server.current_verifier(&writer.uid).unwrap();
    let key = writer.begin_secret_update().unwrap();
    assert!(matches!(
        writer.attempt_secret_update_write(&key, &[0]).unwrap(),
        PhaseResult::Unresolved {
            acknowledgements: 1,
            required: 5,
            ..
        }
    ));
    let uncommitted = writer.providers[0].accounts[&key].current.clone().unwrap();
    assert_eq!(uncommitted.ctr, 1);
    assert_eq!(
        writer.login_server.current_verifier(&writer.uid),
        Some(old_verifier)
    );
    // The writer knows that this family is unresolved and refuses sync.
    assert_eq!(
        writer.synchronize_account(&writer.uid.clone(), key.suid, 6),
        Err(PhaseError::OperationInFlight)
    );
    // An independent recovering process has no access to the writer's private
    // operation map. Copy endpoint state only, preserving each own TOPRF share.
    let mut independent = fixture();
    independent.providers = writer.providers.clone();
    independent.login_server = writer.login_server.clone();
    independent.providers[6].mark_account_status(&key, ReplicaStatus::Stale);
    let share_before = independent.providers[6]
        .share(&independent.uid)
        .unwrap()
        .to_bytes();
    let outcome = independent
        .synchronize_account(&independent.uid.clone(), key.suid, 6)
        .unwrap();
    assert!(outcome.valid_responses >= 5);
    assert_eq!(outcome.installed_counter, 1);
    assert_eq!(
        independent.providers[6].accounts[&key].current.as_ref(),
        Some(&uncommitted)
    );
    assert_eq!(
        independent.login_server.current_verifier(&independent.uid),
        Some(old_verifier)
    );
    assert!(independent.login_server.pending.contains_key(&independent.uid));
    assert_eq!(
        independent.providers[6]
            .share(&independent.uid)
            .unwrap()
            .to_bytes(),
        share_before
    );
}

#[test]
fn full_write_quorum_does_not_allow_recovery_from_other_providers() {
    let mut system = RoUpSpaSystem::new(3, 2, 3, [49; 32]).unwrap();
    assert!(system.setup().is_completed());
    assert!(system.registration().is_completed());
    let key = system.any_account_family().unwrap();
    system.providers[2].mark_account_status(&key, ReplicaStatus::Stale);
    assert!(matches!(
        system.synchronize_account(&system.uid.clone(), key.suid, 2),
        Err(PhaseError::NotEnoughValidResponses {
            valid: 2,
            required: 3
        })
    ));
}
