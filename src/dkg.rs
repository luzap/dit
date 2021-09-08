use crate::comm::{Channel, PartyKeyPair};

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

pub fn distributed_keygen(channel: &mut Channel) -> std::result::Result<PartyKeyPair, ()> {
    // TODO Get rid of this -> this should be completely encapsulated in the operation
    let params = Parameters {
        threshold: 2,
        share_count: 4,
    };
    let party_num_int = channel.signup_keygen().unwrap();

    let input_stage1 = KeyGenStage1Input {
        index: party_num_int as usize,
    };

    let res_stage1 = keygen_stage1(&input_stage1);

    channel
        .broadcast(
            party_num_int,
            "dkg-round1",
            serde_json::to_string(&res_stage1.bc_com1_l).unwrap(),
        )
        .unwrap();

    let round1_ans_vec = channel.poll_for_broadcasts(party_num_int, params.share_count, "dkg-round1");

    let bc1_vec = round1_ans_vec
        .iter()
        .map(|m| serde_json::from_str::<KeyGenBroadcastMessage1>(m).unwrap())
        .collect::<Vec<_>>();

    channel
        .broadcast(
            party_num_int,
            "dkg-round2",
            serde_json::to_string(&res_stage1.decom1_l).unwrap(),
        )
        .unwrap();

    let round2_ans_vec = channel.poll_for_broadcasts(party_num_int, params.share_count, "dkg-round2");

    let decom1_vec = round2_ans_vec
        .iter()
        .map(|m| serde_json::from_str::<KeyGenDecommitMessage1>(m).unwrap())
        .collect::<Vec<_>>();

    let input_stage2 = KeyGenStage2Input {
        index: party_num_int as usize,
        params_s: params.clone(),
        party_keys_s: res_stage1.party_keys_l.clone(),
        decom1_vec_s: decom1_vec.clone(),
        bc1_vec_s: bc1_vec.clone(),
    };

    let res_stage2 = keygen_stage2(&input_stage2).expect("keygen stage 2 failed.");

    let mut point_vec: Vec<GE> = Vec::new();
    for i in 0..params.share_count {
        point_vec.push(decom1_vec[i as usize].y_i);
    }

    // TODO Can we do split first?
    let (head, tail) = point_vec.split_at(1);
    let y_sum = tail.iter().fold(head[0], |acc, x| acc + x);

    for (k, i) in (0..params.share_count).enumerate() {
        channel
            .sendp2p(
                party_num_int,
                i,
                "dkg-round3",
                serde_json::to_string(&res_stage2.secret_shares_s[k]).unwrap(),
            )
            .unwrap();
    }

    // get shares from other parties.
    let round3_ans_vec = channel.poll_for_p2p(party_num_int, params.share_count, "dkg-round3");

    let party_shares = round3_ans_vec
        .iter()
        .map(|m| serde_json::from_str::<FE>(&m).unwrap())
        .collect::<Vec<_>>();

    channel
        .broadcast(
            party_num_int,
            "dkg-round4",
            serde_json::to_string(&res_stage2.vss_scheme_s).unwrap(),
        )
        .unwrap();

    //get vss_scheme for others.
    let round4_ans_vec = channel.poll_for_broadcasts(party_num_int, params.share_count, "dkg-round4");

    let vss_scheme_vec = round4_ans_vec
        .iter()
        .map(|m| serde_json::from_str::<VerifiableSS<GE>>(&m).unwrap())
        .collect::<Vec<_>>();

    let input_stage3 = KeyGenStage3Input {
        party_keys_s: res_stage1.party_keys_l.clone(),
        vss_scheme_vec_s: vss_scheme_vec.clone(),
        secret_shares_vec_s: party_shares,
        y_vec_s: point_vec.clone(),
        index_s: party_num_int as usize,
        params_s: params.clone(),
    };
    let res_stage3 = keygen_stage3(&input_stage3).expect("stage 3 keygen failed.");
    channel
        .broadcast(
            party_num_int,
            "dkg-round5",
            serde_json::to_string(&res_stage3.dlog_proof_s).unwrap(),
        )
        .unwrap();

    let round5_ans_vec = channel.poll_for_broadcasts(party_num_int, params.share_count, "dkg-round5");

    let dlog_proof_vec = round5_ans_vec
        .iter()
        .map(|m| serde_json::from_str::<DLogProof<GE>>(&m).unwrap())
        .collect::<Vec<_>>();

    let input_stage4 = KeyGenStage4Input {
        params_s: params.clone(),
        dlog_proof_vec_s: dlog_proof_vec,
        y_vec_s: point_vec.clone(),
    };

    let _ = keygen_stage4(&input_stage4).expect("keygen stage4 failed.");

    let paillier_key_vec = (0..params.share_count)
        .map(|i| bc1_vec[i as usize].e.clone())
        .collect::<Vec<EncryptionKey>>();
    let h1h2ntilde = bc1_vec
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
        h1_h2_N_tilde_vec_s: h1h2ntilde,
    })
}
