use crate::comm::PartyKeyPair;
use curv::arithmetic::Converter;
use curv::{
    cryptographic_primitives::{hashing::hash_sha256::HSha256, hashing::traits::Hash},
    elliptic::curves::secp256_k1::{FE, GE},
};

use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i::{
    LocalSignature, Parameters, SignBroadcastPhase1, SignDecommitPhase1, SignKeys, SignatureRecid,
};

use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::orchestrate::*;
use multi_party_ecdsa::utilities::mta::{MessageA, MessageB};

use paillier::*;

use crate::comm::Channel;
// use crate::errors::Result;

// TODO Change all of the operations to also send the data

// TODO Use the operation to get the number of participants
pub fn distributed_sign(
    channel: &Channel,
    message: &[u8],
    keypair: PartyKeyPair,
) -> Result<SignatureRecid, ()> {
    let params = Parameters {
        threshold: 2,
        share_count: 4,
    };

    let party_num_int = channel.signup_sign().unwrap();

    channel
        .broadcast(
            party_num_int,
            "sign-round0",
            serde_json::to_string(&keypair.party_num_int_s).unwrap(),
        )
        .unwrap();

    let round0_ans_vec =
        channel.poll_for_broadcasts(party_num_int, params.threshold + 1, "sign-round0");

    let mut signers_vec: Vec<usize> = Vec::new();
    let signers: Vec<usize> = round0_ans_vec
        .iter()
        .map(|e| serde_json::from_str(&e).unwrap())
        .collect();

    for i in 0..=params.threshold {
        let signer_j: u16 = serde_json::from_str(&round0_ans_vec[i as usize]).unwrap();
        signers_vec.push(signer_j as usize);
    }

    // TODO Remove this
    assert_eq!(signers_vec, signers);

    let input_stage1 = SignStage1Input {
        vss_scheme: keypair.vss_scheme_vec_s[signers_vec[party_num_int as usize]].clone(),
        index: signers_vec[party_num_int as usize],
        s_l: signers_vec.clone(),
        party_keys: keypair.party_keys_s.clone(),
        shared_keys: keypair.shared_keys,
    };

    let res_stage1 = sign_stage1(&input_stage1);

    channel
        .broadcast(
            party_num_int,
            "sign-round1",
            serde_json::to_string(&(
                res_stage1.bc1.clone(),
                res_stage1.m_a.0.clone(),
                res_stage1.sign_keys.g_w_i,
            ))
            .unwrap(),
        )
        .unwrap();

    // TODO Is the length correct here?
    let round1_ans_vec =
        channel.poll_for_broadcasts(party_num_int, params.threshold + 1, "sign-round1");

    let mut bc1s: Vec<SignBroadcastPhase1> = Vec::new();
    let mut mas: Vec<MessageA> = Vec::new();
    let mut gwis: Vec<GE> = vec![];

    for ans in round1_ans_vec.iter() {
        let (bc1_j, m_a_party_j, g_w_i): (SignBroadcastPhase1, MessageA, GE) =
            serde_json::from_str(&ans).unwrap();
        bc1s.push(bc1_j);
        gwis.push(g_w_i);
        mas.push(m_a_party_j);
    }

    let input_stage2 = SignStage2Input {
        m_a_vec: mas,
        gamma_i: res_stage1.sign_keys.gamma_i,
        w_i: res_stage1.sign_keys.w_i,
        ek_vec: keypair.paillier_key_vec_s.clone(),
        index: party_num_int as usize,
        l_ttag: signers_vec.len() as usize,
        l_s: signers_vec.clone(),
    };

    let mut beta_vec: Vec<FE> = vec![];
    let mut ni_vec: Vec<FE> = vec![];
    // TODO add
    let res_stage2 = sign_stage2(&input_stage2).expect("sign stage2 failed.");
    // Send out MessageB, beta, ni to other signers so that they can calculate their alpha values.
    let mut j = 0;

    for i in 0..params.threshold + 1 {
        if i != party_num_int {
            // private values that should never be sent out
            beta_vec.push(res_stage2.gamma_i_vec[j].1);
            ni_vec.push(res_stage2.w_i_vec[j].1);

            // Below two are the C_b messages on page 11 https://eprint.iacr.org/2020/540.pdf
            // paillier encrypted values and are thus safe to send as is.
            let c_b_messageb_gammai = res_stage2.gamma_i_vec[j].0.clone();
            let c_b_messageb_wi = res_stage2.w_i_vec[j].0.clone();

            // If this client were implementing blame(Identifiable abort) then this message should have been broadcast.
            // For the current implementation p2p send is also fine.
            channel
                .sendp2p(
                    party_num_int,
                    i,
                    "sign-round2",
                    serde_json::to_string(&(c_b_messageb_gammai, c_b_messageb_wi)).unwrap(),
                )
                .unwrap();

            j += 1;
        }
    }

    // TODO I think I'm actually stuck here
    let round2_ans_vec = channel.poll_for_p2p(party_num_int, params.threshold, "sign-round2");

    let mut m_b_gamma_rec_vec: Vec<MessageB> = Vec::new();
    let mut m_b_w_rec_vec: Vec<MessageB> = Vec::new();

    for ans in round2_ans_vec.iter() {
        let (l_mb_gamma, l_mb_w): (MessageB, MessageB) = serde_json::from_str(&ans).unwrap();
        m_b_gamma_rec_vec.push(l_mb_gamma);
        m_b_w_rec_vec.push(l_mb_w);
    }

    let input_stage3 = SignStage3Input {
        dk_s: keypair.party_keys_s.dk.clone(),
        k_i_s: res_stage1.sign_keys.k_i,
        m_b_gamma_s: m_b_gamma_rec_vec.clone(),
        m_b_w_s: m_b_w_rec_vec,
        index_s: party_num_int as usize,
        ttag_s: signers_vec.len(),
        g_w_i_s: gwis,
    };

    let res_stage3 = sign_stage3(&input_stage3).expect("Sign stage 3 failed.");

    let mut alpha_vec = vec![];
    let mut miu_vec = vec![];

    // TODO This has to be sent to other signers -> what do we do?
    // Send out alpha, miu to other signers.
    let mut j = 0;
    for i in 1..params.threshold + 2 {
        if i != party_num_int {
            alpha_vec.push(res_stage3.alpha_vec_gamma[j]);
            miu_vec.push(res_stage3.alpha_vec_w[j]);
            j += 1;
        }
    }

    let input_stage4 = SignStage4Input {
        alpha_vec_s: alpha_vec,
        beta_vec_s: beta_vec,
        miu_vec_s: miu_vec,
        ni_vec_s: ni_vec,
        sign_keys_s: res_stage1.sign_keys.clone(),
    };

    let res_stage4 = sign_stage4(&input_stage4).expect("Sign Stage4 failed.");

    //broadcast decommitment from stage1 and delta_i
    channel
        .broadcast(
            party_num_int,
            "sign-round4",
            serde_json::to_string(&(res_stage1.decom1.clone(), res_stage4.delta_i)).unwrap(),
        )
        .unwrap();

    let round4_ans_vec =
        channel.poll_for_broadcasts(party_num_int, params.threshold + 1, "sign-round4");

    /* let mut delta_i_vec = vec![];
    let mut decom1_vec = vec![];
    let mut j = 0;
    for i in 1..params.threshold + 2 {
        if i == party_num_int {
            delta_i_vec.push(res_stage4.delta_i);
            decom1_vec.push(res_stage1.decom1.clone());
        } else {
            let (decom_l, delta_l): (SignDecommitPhase1, FE) =
                serde_json::from_str(&round4_ans_vec[j]).unwrap();
            delta_i_vec.push(delta_l);
            decom1_vec.push(decom_l);
            j += 1;
        }
    } */

    let mut delta_i_vec = vec![];
    let mut decom1_vec = vec![];
    for ans in round4_ans_vec.iter() {
        let (decom_l, delta_l): (SignDecommitPhase1, FE) = serde_json::from_str(&ans).unwrap();
        delta_i_vec.push(delta_l);
        decom1_vec.push(decom_l);
    }

    let delta_inv_l = SignKeys::phase3_reconstruct_delta(&delta_i_vec);
    let input_stage5 = SignStage5Input {
        m_b_gamma_vec: m_b_gamma_rec_vec,
        delta_inv: delta_inv_l,
        decom_vec1: decom1_vec,
        bc1_vec: bc1s.clone(),
        index: party_num_int as usize,
        sign_keys: res_stage1.sign_keys.clone(),
        s_ttag: signers_vec.len(),
    };
    let res_stage5 = sign_stage5(&input_stage5).expect("Sign Stage 5 failed.");
    channel
        .broadcast(
            party_num_int,
            "sign-round5",
            serde_json::to_string(&(res_stage5.R_dash, res_stage5.R)).unwrap(),
        )
        .unwrap();

    let round5_ans_vec = channel.poll_for_broadcasts(party_num_int, params.threshold + 1, "round5");

    // TODO Anything we can do here?
    let mut rs = vec![];
    let mut rdashes = vec![];
    for ans in round5_ans_vec.iter() {
        let (rdash, r): (GE, GE) = serde_json::from_str(&ans).unwrap();
        rs.push(r);
        rdashes.push(rdash);
    }

    let message = HSha256::create_hash(&[&BigInt::from_bytes(message)]);

    let input_stage6 = SignStage6Input {
        R_dash_vec: rdashes,
        R: res_stage5.R,
        m_a: res_stage1.m_a.0.clone(),
        e_k: keypair.paillier_key_vec_s[signers_vec[party_num_int as usize] as usize].clone(),
        k_i: res_stage1.sign_keys.k_i,
        randomness: res_stage1.m_a.1.clone(),
        party_keys: keypair.party_keys_s.clone(),
        h1_h2_N_tilde_vec: keypair.h1_h2_N_tilde_vec_s.clone(),
        index: party_num_int as usize,
        s: signers_vec.clone(),
        sigma: res_stage4.sigma_i,
        ysum: keypair.y_sum_s,
        sign_key: res_stage1.sign_keys,
        message_bn: message.clone(),
    };

    let res_stage6 = sign_stage6(&input_stage6).expect("stage6 sign failed.");
    channel
        .broadcast(
            party_num_int,
            "sign-round6",
            serde_json::to_string(&res_stage6.local_sig).unwrap(),
        )
        .unwrap();

    let round6_ans_vec =
        channel.poll_for_broadcasts(party_num_int, params.threshold + 1, "sign-round6");

    let local_sig_vec: Vec<LocalSignature> = round6_ans_vec
        .iter()
        .map(|msg| serde_json::from_str(&msg).unwrap())
        .collect();

    /* let mut local_sig_vec = vec![];
    let mut j = 0;
    for i in 0..params.threshold + 1 {
        if i == party_num_int {
            local_sig_vec.push(res_stage6.local_sig.clone());
        } else {
            let local_sig: LocalSignature = serde_json::from_str(&round6_ans_vec[j]).unwrap();
            local_sig_vec.push(local_sig.clone());
            j += 1;
        }
    } */

    let input_stage7 = SignStage7Input {
        local_sig_vec: local_sig_vec,
        ysum: keypair.y_sum_s.clone(),
    };

    let res_stage7 = sign_stage7(&input_stage7).expect("sign stage 7 failed");

    // TODO Remove this in the release version
    check_sig(
        &res_stage7.local_sig.r,
        &res_stage7.local_sig.s,
        &message,
        &keypair.y_sum_s,
    );

    Ok(res_stage7.local_sig)
}
