use crate::protocol::PartyKeyPair;
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

use crate::channel;
use crate::channel::Errors;

use super::utils::Config;

pub fn distributed_sign(
    hash: String,
    config: Config,
    keypair: PartyKeyPair,
) -> Result<SignatureRecid, Errors> {
    let params = Parameters {
        threshold: 2,
        share_count: 4,
    };

    let mut channel = channel::Channel::new(format!(
        "http://{}:{}",
        config.server.address, config.server.port
    ));

    let THRESHOLD = params.threshold;

    let message = match hex::decode(hash.clone()) {
        Ok(x) => x,
        Err(_e) => hash.as_bytes().to_vec(),
    };
    let message = &message[..];

    let party_num_int = match channel.signup_sign() {
        Ok(i) => i,
        Err(_) => return Err(Errors::Response),
    };

    // round 0: collect signers IDs
    assert!(channel
        .broadcast(
            party_num_int,
            "round0",
            serde_json::to_string(&keypair.party_num_int_s).unwrap(),
        )
        .is_ok());

    let round0_ans_vec = channel.poll_for_broadcasts(party_num_int, THRESHOLD + 1, "round0");

    let mut j = 0;
    //0 indexed vec containing ids of the signing parties.
    let mut signers_vec: Vec<usize> = Vec::new();
    for i in 1..=THRESHOLD + 1 {
        if i == party_num_int {
            signers_vec.push((keypair.party_num_int_s - 1) as usize);
        } else {
            let signer_j: u16 = serde_json::from_str(&round0_ans_vec[j]).unwrap();
            signers_vec.push((signer_j - 1) as usize);
            j += 1;
        }
    }

    let input_stage1 = SignStage1Input {
        vss_scheme: keypair.vss_scheme_vec_s[signers_vec[(party_num_int - 1) as usize]].clone(),
        index: signers_vec[(party_num_int - 1) as usize],
        s_l: signers_vec.clone(),
        party_keys: keypair.party_keys_s.clone(),
        shared_keys: keypair.shared_keys,
    };
    let res_stage1 = sign_stage1(&input_stage1);
    // publish message A  and Commitment and then gather responses from other parties.
    assert!(channel
        .broadcast(
            party_num_int,
            "round1",
            serde_json::to_string(&(
                res_stage1.bc1.clone(),
                res_stage1.m_a.0.clone(),
                res_stage1.sign_keys.g_w_i
            ))
            .unwrap(),
        )
        .is_ok());
    let round1_ans_vec = channel.poll_for_broadcasts(party_num_int, THRESHOLD + 1, "round1");

    let mut j = 0;
    let mut bc1_vec: Vec<SignBroadcastPhase1> = Vec::new();
    let mut m_a_vec: Vec<MessageA> = Vec::new();
    let mut g_w_i_vec: Vec<GE> = vec![];

    for i in 1..THRESHOLD + 2 {
        if i == party_num_int {
            bc1_vec.push(res_stage1.bc1.clone());
            g_w_i_vec.push(res_stage1.sign_keys.g_w_i);
            m_a_vec.push(res_stage1.m_a.0.clone());
        } else {
            let (bc1_j, m_a_party_j, g_w_i): (SignBroadcastPhase1, MessageA, GE) =
                serde_json::from_str(&round1_ans_vec[j]).unwrap();
            bc1_vec.push(bc1_j);
            g_w_i_vec.push(g_w_i);
            m_a_vec.push(m_a_party_j);

            j += 1;
        }
    }
    assert_eq!(signers_vec.len(), bc1_vec.len());

    let input_stage2 = SignStage2Input {
        m_a_vec: m_a_vec,
        gamma_i: res_stage1.sign_keys.gamma_i,
        w_i: res_stage1.sign_keys.w_i,
        ek_vec: keypair.paillier_key_vec_s.clone(),
        index: (party_num_int - 1) as usize,
        l_ttag: signers_vec.len() as usize,
        l_s: signers_vec.clone(),
    };

    let mut beta_vec: Vec<FE> = vec![];
    let mut ni_vec: Vec<FE> = vec![];
    let res_stage2 = sign_stage2(&input_stage2).expect("sign stage2 failed.");
    // Send out MessageB, beta, ni to other signers so that they can calculate there alpha values.
    let mut j = 0;
    for i in 1..THRESHOLD + 2 {
        if i != party_num_int {
            // private values and they should never be sent out.
            beta_vec.push(res_stage2.gamma_i_vec[j].1);
            ni_vec.push(res_stage2.w_i_vec[j].1);
            // Below two are the C_b messages on page 11 https://eprint.iacr.org/2020/540.pdf
            // paillier encrypted values and are thus safe to send as is.
            let c_b_messageb_gammai = res_stage2.gamma_i_vec[j].0.clone();
            let c_b_messageb_wi = res_stage2.w_i_vec[j].0.clone();

            // If this client were implementing blame(Identifiable abort) then this message should have been broadcast.
            // For the current implementation p2p send is also fine.
            assert!(channel
                .sendp2p(
                    party_num_int,
                    i,
                    "round2",
                    serde_json::to_string(&(c_b_messageb_gammai, c_b_messageb_wi,)).unwrap(),
                )
                .is_ok());

            j += 1;
        }
    }

    let round2_ans_vec = channel.poll_for_p2p(party_num_int, THRESHOLD + 1, "round2");

    let mut m_b_gamma_rec_vec: Vec<MessageB> = Vec::new();
    let mut m_b_w_rec_vec: Vec<MessageB> = Vec::new();

    for i in 0..THRESHOLD {
        let (l_mb_gamma, l_mb_w): (MessageB, MessageB) =
            serde_json::from_str(&round2_ans_vec[i as usize]).unwrap();
        m_b_gamma_rec_vec.push(l_mb_gamma);
        m_b_w_rec_vec.push(l_mb_w);
    }

    let input_stage3 = SignStage3Input {
        dk_s: keypair.party_keys_s.dk.clone(),
        k_i_s: res_stage1.sign_keys.k_i,
        m_b_gamma_s: m_b_gamma_rec_vec.clone(),
        m_b_w_s: m_b_w_rec_vec,
        index_s: (party_num_int - 1) as usize,
        ttag_s: signers_vec.len(),
        g_w_i_s: g_w_i_vec,
    };

    let res_stage3 = sign_stage3(&input_stage3).expect("Sign stage 3 failed.");
    let mut alpha_vec = vec![];
    let mut miu_vec = vec![];
    // Send out alpha, miu to other signers.
    let mut j = 0;
    for i in 1..THRESHOLD + 2 {
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
    assert!(channel
        .broadcast(
            party_num_int,
            "round4",
            serde_json::to_string(&(res_stage1.decom1.clone(), res_stage4.delta_i,)).unwrap(),
        )
        .is_ok());

    let round4_ans_vec = channel.poll_for_broadcasts(party_num_int, THRESHOLD + 1, "round4");

    let mut delta_i_vec = vec![];
    let mut decom1_vec = vec![];
    let mut j = 0;
    for i in 1..THRESHOLD + 2 {
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
    }

    let delta_inv_l = SignKeys::phase3_reconstruct_delta(&delta_i_vec);
    let input_stage5 = SignStage5Input {
        m_b_gamma_vec: m_b_gamma_rec_vec,
        delta_inv: delta_inv_l,
        decom_vec1: decom1_vec,
        bc1_vec: bc1_vec.clone(),
        index: (party_num_int - 1) as usize,
        sign_keys: res_stage1.sign_keys.clone(),
        s_ttag: signers_vec.len(),
    };
    let res_stage5 = sign_stage5(&input_stage5).expect("Sign Stage 5 failed.");
    assert!(channel
        .broadcast(
            party_num_int,
            "round5",
            serde_json::to_string(&(res_stage5.R_dash, res_stage5.R,)).unwrap(),
        )
        .is_ok());

    let round5_ans_vec = channel.poll_for_broadcasts(party_num_int, THRESHOLD + 1, "round5");

    let mut R_vec = vec![];
    let mut R_dash_vec = vec![];
    let mut j = 0;
    for i in 1..THRESHOLD + 2 {
        if i == party_num_int {
            R_vec.push(res_stage5.R);
            R_dash_vec.push(res_stage5.R_dash);
        } else {
            let (R_dash, R): (GE, GE) = serde_json::from_str(&round5_ans_vec[j]).unwrap();
            R_vec.push(R);
            R_dash_vec.push(R_dash);
            j += 1;
        }
    }

    let message_bn = HSha256::create_hash(&[&BigInt::from_bytes(message)]);
    let input_stage6 = SignStage6Input {
        R_dash_vec,
        R: res_stage5.R,
        m_a: res_stage1.m_a.0.clone(),
        e_k: keypair.paillier_key_vec_s[signers_vec[(party_num_int - 1) as usize] as usize].clone(),
        k_i: res_stage1.sign_keys.k_i,
        randomness: res_stage1.m_a.1.clone(),
        party_keys: keypair.party_keys_s.clone(),
        h1_h2_N_tilde_vec: keypair.h1_h2_N_tilde_vec_s.clone(),
        index: (party_num_int - 1) as usize,
        s: signers_vec.clone(),
        sigma: res_stage4.sigma_i,
        ysum: keypair.y_sum_s,
        sign_key: res_stage1.sign_keys,
        message_bn: message_bn.clone(),
    };
    let res_stage6 = sign_stage6(&input_stage6).expect("stage6 sign failed.");
    assert!(channel
        .broadcast(
            party_num_int,
            "round6",
            serde_json::to_string(&res_stage6.local_sig).unwrap(),
        )
        .is_ok());
    let round6_ans_vec = channel.poll_for_broadcasts(party_num_int, THRESHOLD + 1, "round6");

    let mut local_sig_vec = vec![];
    let mut j = 0;
    for i in 1..THRESHOLD + 2 {
        if i == party_num_int {
            local_sig_vec.push(res_stage6.local_sig.clone());
        } else {
            let local_sig: LocalSignature = serde_json::from_str(&round6_ans_vec[j]).unwrap();
            local_sig_vec.push(local_sig.clone());
            j += 1;
        }
    }
    let input_stage7 = SignStage7Input {
        local_sig_vec: local_sig_vec,
        ysum: keypair.y_sum_s.clone(),
    };
    let res_stage7 = sign_stage7(&input_stage7).expect("sign stage 7 failed");

    check_sig(
        &res_stage7.local_sig.r,
        &res_stage7.local_sig.s,
        &message_bn,
        &keypair.y_sum_s,
    );
    Ok(res_stage7.local_sig)
}
