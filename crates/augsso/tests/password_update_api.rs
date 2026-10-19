use augsso_bench::{benchmark as u, protocols::augsso as a};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

#[test]
fn exposed_password_update_authenticates_old_password_and_changes_server_key() {
    let mut rng = ChaCha20Rng::from_seed([93; 32]);
    let fx = a::make_fixture(3, 2);
    let old = b"correct horse battery staple";
    let new = b"independent network client new password";
    let (st, req) = u::password_update_request_for(fx.c, 3, &[1, 2], old, new, &mut rng);
    let mut servers = fx.servers.clone();
    let mut first = Vec::new();
    let mut sessions = Vec::new();
    for server in &servers {
        let (resp, sess) = u::password_update_respond1(server, &req, &mut rng).unwrap();
        first.push(resp);
        sessions.push(sess);
    }
    let phase = u::password_update_client_phase1(&st, &req, &first, &fx.pk_shares, None, &mut rng).unwrap();
    let mut second = Vec::new();
    for (server, sess) in servers.iter_mut().zip(&sessions) {
        let ct = &phase.ct_ch.iter().find(|(id, _)| *id == server.id).unwrap().1;
        let resp = u::password_update_respond2(server, sess, ct).unwrap();
        let sk_i = server.get_record(fx.c).unwrap().sk_i;
        server.store(
            fx.c,
            &a::RegistrationMsg {
                server_id: server.id,
                sk_i,
                rpk: resp.new_rpk,
            },
        );
        second.push(resp);
    }
    let phi: Vec<_> = servers
        .iter()
        .map(|server| (server.id, server.phi_pub_i))
        .collect();
    assert!(u::password_update_client_finalize(&st, &req, &second, &phi).is_some());
    for (password, expected) in [(old.as_slice(), false), (new.as_slice(), true)] {
        let (auth_st, auth_req) = a::request(password, fx.pld, &[1, 2], &mut rng);
        let replies: Vec<_> = servers[..2]
            .iter()
            .map(|server| a::respond1(server, &auth_req, &mut rng).unwrap().0)
            .collect();
        assert_eq!(
            a::client_phase1(&auth_st, &auth_req, &replies, &fx.pk_shares, None, &mut rng).is_some(),
            expected
        );
    }
    let (bad_st, bad_req) =
        u::password_update_request_for(fx.c, 3, &[1, 2], b"wrong password", b"another", &mut rng);
    let bad_responses: Vec<_> = servers
        .iter()
        .map(|server| u::password_update_respond1(server, &bad_req, &mut rng).unwrap().0)
        .collect();
    assert!(u::password_update_client_phase1(
        &bad_st,
        &bad_req,
        &bad_responses,
        &fx.pk_shares,
        None,
        &mut rng
    )
    .is_none());
}
