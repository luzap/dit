use super::utils::Config;
use crate::channel;
use crate::channel::Errors;
use crate::protocol::PartyKeyPair;
use std::time;

use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::orchestrate::{
    keygen_stage1, keygen_stage2, keygen_stage3, keygen_stage4, KeyGenStage1Input,
    KeyGenStage2Input, KeyGenStage3Input, KeyGenStage4Input,
};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i::{
    KeyGenBroadcastMessage1, KeyGenDecommitMessage1, Parameters,
};

use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::secp256_k1::{FE, GE};
use paillier::EncryptionKey;
use zk_paillier::zkproofs::DLogStatement;

pub fn distributed_keygen(config: Config) -> Result<PartyKeyPair, Errors> {
    let params = Parameters {
        threshold: 2,
        share_count: 4,
    };
    let mut channel = channel::Channel::new(format!(
        "http://{}:{}",
        config.server.address, config.server.port
    ));

    let party_num_int = match channel.signup_keygen() {
        Ok(i) => i,
        Err(_) => return Err(Errors::Response),
    };

    let input_stage1 = KeyGenStage1Input {
        index: (party_num_int - 1) as usize,
    };

    let res_stage1 = keygen_stage1(&input_stage1);

    match channel.broadcast(
        party_num_int,
        "round1",
        serde_json::to_string(&res_stage1.bc_com1_l).unwrap(),
    ) {
        Ok(()) => {}
        Err(()) => return Err(Errors::Send),
    };

    let round1_ans_vec =
        channel.poll_for_broadcasts(party_num_int, params.share_count, "round1");
    let mut bc1_vec = round1_ans_vec
        .iter()
        .map(|m| serde_json::from_str::<KeyGenBroadcastMessage1>(m).unwrap())
        .collect::<Vec<_>>();

    bc1_vec.insert(party_num_int as usize - 1, res_stage1.bc_com1_l);

    match channel.broadcast(
        party_num_int,
        "round2",
        serde_json::to_string(&res_stage1.decom1_l).unwrap(),
    ) {
        Ok(()) => {}
        Err(()) => return Err(Errors::Send),
    };

    let round2_ans_vec =
        channel.poll_for_broadcasts(party_num_int, params.share_count, "round2");

    let mut decom1_vec = round2_ans_vec
        .iter()
        .map(|m| serde_json::from_str::<KeyGenDecommitMessage1>(m).unwrap())
        .collect::<Vec<_>>();

    decom1_vec.insert(party_num_int as usize - 1, res_stage1.decom1_l);

    let input_stage2 = KeyGenStage2Input {
        index: (party_num_int - 1) as usize,
        params_s: params.clone(),
        party_keys_s: res_stage1.party_keys_l.clone(),
        decom1_vec_s: decom1_vec.clone(),
        bc1_vec_s: bc1_vec.clone(),
    };

    let res_stage2 = keygen_stage2(&input_stage2).expect("keygen stage 2 failed.");

    let mut point_vec: Vec<GE> = Vec::new();
    for i in 1..=params.share_count {
        point_vec.push(decom1_vec[(i - 1) as usize].y_i);
    }

    // TODO Can we do split first?
    let (head, tail) = point_vec.split_at(1);
    let y_sum = tail.iter().fold(head[0], |acc, x| acc + x);

    for (k, i) in (1..=params.share_count).enumerate() {
        if i != party_num_int {
            assert!(channel
                .sendp2p(
                    party_num_int,
                    i,
                    "round3",
                    serde_json::to_string(&res_stage2.secret_shares_s[k]).unwrap(),
                )
                .is_ok());
        }
    }
    // get shares from other parties.
    let round3_ans_vec = channel.poll_for_p2p(party_num_int, params.share_count, "round3");

    // decrypt shares from other parties.
    let mut j = 0;
    let mut party_shares: Vec<FE> = Vec::new();
    for i in 1..=params.share_count {
        if i == party_num_int {
            party_shares.push(res_stage2.secret_shares_s[(i - 1) as usize]);
        } else {
            party_shares.push(serde_json::from_str(&round3_ans_vec[j]).unwrap());
            j += 1;
        }
    }

    assert!(channel
        .broadcast(
            party_num_int,
            "round4",
            serde_json::to_string(&res_stage2.vss_scheme_s).unwrap(),
        )
        .is_ok());

    //get vss_scheme for others.
    let round4_ans_vec =
        channel.poll_for_broadcasts(party_num_int, params.share_count, "round4");

    let mut j = 0;
    let mut vss_scheme_vec: Vec<VerifiableSS<GE>> = Vec::new();
    for i in 1..=params.share_count {
        if i == party_num_int {
            vss_scheme_vec.push(res_stage2.vss_scheme_s.clone());
        } else {
            let vss_scheme_j: VerifiableSS<GE> = serde_json::from_str(&round4_ans_vec[j]).unwrap();
            vss_scheme_vec.push(vss_scheme_j);
            j += 1;
        }
    }
    let input_stage3 = KeyGenStage3Input {
        party_keys_s: res_stage1.party_keys_l.clone(),
        vss_scheme_vec_s: vss_scheme_vec.clone(),
        secret_shares_vec_s: party_shares,
        y_vec_s: point_vec.clone(),
        index_s: (party_num_int - 1) as usize,
        params_s: params.clone(),
    };
    let res_stage3 = keygen_stage3(&input_stage3).expect("stage 3 keygen failed.");
    // round 5: send dlog proof
    assert!(channel
        .broadcast(
            party_num_int,
            "round5",
            serde_json::to_string(&res_stage3.dlog_proof_s).unwrap(),
        )
        .is_ok());
    let round5_ans_vec =
        channel.poll_for_broadcasts(party_num_int, params.share_count, "round5");

    let mut j = 0;
    let mut dlog_proof_vec: Vec<DLogProof<GE>> = Vec::new();
    for i in 1..=params.share_count {
        if i == party_num_int {
            dlog_proof_vec.push(res_stage3.dlog_proof_s.clone());
        } else {
            let dlog_proof_j: DLogProof<GE> = serde_json::from_str(&round5_ans_vec[j]).unwrap();
            dlog_proof_vec.push(dlog_proof_j);
            j += 1;
        }
    }

    let input_stage4 = KeyGenStage4Input {
        params_s: params.clone(),
        dlog_proof_vec_s: dlog_proof_vec,
        y_vec_s: point_vec.clone(),
    };

    let _ = keygen_stage4(&input_stage4).expect("keygen stage4 failed.");

    let paillier_key_vec = (0..params.share_count)
        .map(|i| bc1_vec[i as usize].e.clone())
        .collect::<Vec<EncryptionKey>>();
    let h1_h2_N_tilde_vec = bc1_vec
        .iter()
        .map(|bc1| bc1.dlog_statement.clone())
        .collect::<Vec<DLogStatement>>();

    Ok(PartyKeyPair {
        party_keys_s: res_stage1.party_keys_l,
        shared_keys: res_stage3.shared_keys_s,
        party_num_int_s: party_num_int,
        vss_scheme_vec_s: vss_scheme_vec,
        paillier_key_vec_s: paillier_key_vec,
        y_sum_s: y_sum,
        h1_h2_N_tilde_vec_s: h1_h2_N_tilde_vec,
    })
}
