use curv::arithmetic::Converter;
use curv::{
    cryptographic_primitives::{
        proofs::sigma_dlog::DLogProof, secret_sharing::feldman_vss::VerifiableSS,
        hashing::hash_sha256::HSha256, hashing::traits::Hash
    },
    elliptic::curves::{
         secp256_k1::{
            FE, GE
        },
    },
    elliptic::curves::traits::*
};

use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i::{
    KeyGenBroadcastMessage1, KeyGenDecommitMessage1, Parameters, SharedKeys,
    Keys, SignBroadcastPhase1, SignDecommitPhase1, SignKeys, LocalSignature
};

use multi_party_ecdsa::utilities::mta::{MessageA, MessageB};

use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::orchestrate::*;

use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::ErrorType;

use paillier::*;
use zk_paillier::zkproofs::DLogStatement;

use std::time::Duration;
use reqwest::Client;

use serde::{Serialize, Deserialize};

pub fn poll_for_broadcasts(    
    _client: &Client,
    _party_num: u16,
    _n: u16,
    _delay: Duration,
    _round: &str,
    _sender_uuid: &String) -> Vec<String> {
        vec![String::from("hello")]
    
}

// TODO Are we using channel to map between indices and UUIDs or are we using something
// else?
// TODO We assume that channel will take care of retransmits and lost packages
// If that is the case, what are the error conditions that we could want?
// We need polling functionality of some sort, and then some way to make sure that the right
// message is connnected. I propose a fairly simple state machine design, where if the messages
// from the previous round can be parsed correctly, we then move onto the next one 
//
//
pub trait Channel {
    fn send_to_peer() -> Result<(), ()>;
    fn broadcast() -> Result<(), ()>;
    fn receive_single() -> Result<(), ()>;
    fn receive_broadcast() -> Result<(), ()>;
}


pub fn sendp2p(
    _client: &Client,
    _party_from: u16,
    _party_to: u16,
    _round: &str,
    _data: String,
    _sender_uuid: &str,
) -> Result<(), ()> {
    Ok(())
}

pub fn broadcast(
    _client: &Client,
    _party_num: u16,
    _round: &str,
    _data: String,
    _sender_uuid: &str,
) -> Result<(), ()> {
    Ok(())
}

pub fn poll_for_p2p(
    _client: &Client,
    _party_num: u16,
    _n: u16,
    _delay: Duration,
    _round: &str,
    _sender_uuid: &str,
) -> Vec<String> {
    vec![String::from("hello")]
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartyKeyPair {
    pub party_keys_s: Keys,
    pub shared_keys: SharedKeys,
    pub party_num_int_s: u16,
    pub vss_scheme_vec_s: Vec<VerifiableSS<GE>>,
    pub paillier_key_vec_s: Vec<EncryptionKey>,
    pub y_sum_s: GE,
    pub h1_h2_N_tilde: Vec<DLogStatement>,
}

pub fn extract<'a, T: Deserialize<'a>>(vals: &'a Vec< String>) -> Result<Vec<T>, ()> {
    let mut results: Vec<T> = Vec::with_capacity(vals.len());

    for str in vals {
        match serde_json::from_str::<'a, T>(&str) {
            Ok(val) => results.push(val),
            Err(_) => return Err(())
        }
    }

   Ok(results) 
}

pub struct Registration {
    uuid: String,
    index: usize
}

// TODO Any way to remove the params arg?
// TODO Remove the delay arg, which won't be necessary as soon as we move to an epoll-like
// interface
pub fn distributed_keygen(client: &Client, reg: Registration, params: &Parameters, delay: std::time::Duration) -> PartyKeyPair {
    
    let party = params.share_count;
    let input_stage1 = KeyGenStage1Input {
        index: (party - 1) as usize,
    };

    let res_stage1: KeyGenStage1Result = keygen_stage1(&input_stage1);
     
    broadcast(
        client,
        party,
        "round1",
        serde_json::to_string(&res_stage1.bc_com1_l).unwrap(),
        &reg.uuid
    );

    let round1_ans_vec = poll_for_broadcasts(
        client,
        party,
        params.threshold,
        delay,
        "round1",
        &reg.uuid,
    );
   
    let mut bc1_vec: Vec<KeyGenBroadcastMessage1> = match extract(&round1_ans_vec) {
        Ok(vec) => vec,
        Err(e) => panic!("Error!")
    };

    // TODO This does not need to be present
    bc1_vec.insert(party as usize - 1, res_stage1.bc_com1_l);

    broadcast(
        &client,
        party,
        "round2",
        serde_json::to_string(&res_stage1.decom1_l).unwrap(),
        &reg.uuid
    );
    
    // TODO Move this somewhere else
    let round2_ans_vec = poll_for_broadcasts(
        &client,
        party,
        params.share_count,
        delay,
        "round2",
        &reg.uuid,
    );

    let mut dec1_msg: Vec<KeyGenDecommitMessage1> = match extract(&round2_ans_vec) {
        Ok(vec) => vec,
        Err(e) => panic!("Error") 
    };

    // TODO Since all of these are just bandwidth questions, I should seriously
    // check if we're saving just about any bandwidth by not sending what can only 
    // be less than half of the data. We should instead worry about compression
    // and feel secure about sending the data
    dec1_msg.insert(party as usize - 1, res_stage1.decom1_l);

    // That index sort of scares me
    let input_stage2 = KeyGenStage2Input {
        index: (party - 1) as usize,
        params_s: params.clone(),
        party_keys_s: res_stage1.party_keys_l,
        decom1_vec_s: dec1_msg,
        bc1_vec_s: bc1_vec,
    };

    // TODO Use the ErrorType value, even if right now there's no way to access its fields
    let res_stage2 = match keygen_stage2(&input_stage2) {
        Ok(res) => res,
        Err(e) => panic!("Error {:?}", e)
    };


    let mut points: Vec<GE> = Vec::new();
    for i in 1..=params.share_count {
        points.push(dec1_msg[(i - 1) as usize].y_i);
    }


    let (head, tail) = points.split_at(1);
    let y_sum = tail.iter().fold(head[0], |acc, x| acc + x);

    for (k, i) in (1..=params.share_count).enumerate() {
        if i != party {
            sendp2p(
                &client,
                party,
                i,
                "round3",
                serde_json::to_string(&res_stage2.secret_shares_s[k]).unwrap(),
                &reg.uuid
            );
            
        }
    }

    // get shares from other parties.
    let round3_ans = poll_for_p2p(
        &client,
        party,
        params.share_count,
        delay,
        "round3",
        &reg.uuid,
    );

    // decrypt shares from other parties.
    let mut j = 0;
    let mut party_shares: Vec<FE> = Vec::new();
    for i in 1..=params.share_count {
        if i == party {
            party_shares.push(res_stage2.secret_shares_s[(i - 1) as usize]);
        } else {
            party_shares.push(serde_json::from_str(&round3_ans[j]).unwrap());
            j += 1;
        }
    }

    broadcast(
        &client,
        party,
        "round4",
        serde_json::to_string(&res_stage2.vss_scheme_s).unwrap(),
        &reg.uuid
    );
    

    //get vss_scheme for others.
    let round4_ans_vec = poll_for_broadcasts(
        &client,
        party,
        params.share_count,
        delay,
        "round4",
        &reg.uuid,
    );

    let round4_ans_vec2: Vec<VerifiableSS<GE>> = match extract(&round4_ans_vec) {
        Ok(vec) => vec,
        Err(_) => panic!("Could not convert toe verifiables!")
    };

    let mut j = 0;
    let mut vss_scheme_vec: Vec<VerifiableSS<GE>> = Vec::new();
    for i in 1..=params.share_count {
        if i == party {
            vss_scheme_vec.push(res_stage2.vss_scheme_s);
        } else {
            vss_scheme_vec.push(serde_json::from_str(&round4_ans_vec[j]).unwrap());
            j += 1;
        }
    }


    let input_stage3 = KeyGenStage3Input {
        party_keys_s: res_stage1.party_keys_l,
        vss_scheme_vec_s: vss_scheme_vec,
        secret_shares_vec_s: party_shares,
        y_vec_s: points,
        index_s: (party - 1) as usize,
        params_s: params.clone(),
    };

    let res_stage3 = match keygen_stage3(&input_stage3) {
        Ok(res) => res,
        Err(e) => panic!("Error: {:?}", e)
    };

    // round 5: send dlog proof
    broadcast(
        &client,
        party,
        "round5",
        serde_json::to_string(&res_stage3.dlog_proof_s).unwrap(),
        &reg.uuid
    );
    
    let round5_ans = poll_for_broadcasts(
        &client,
        party,
        params.share_count,
        delay,
        "round5",
        &reg.uuid,
    );


    let mut j = 0;
    let mut dlog_proof_vec: Vec<DLogProof<GE>> = Vec::new();
    for i in 1..=params.share_count {
        if i == party {
            dlog_proof_vec.push(res_stage3.dlog_proof_s);
        } else {
            dlog_proof_vec.push( serde_json::from_str(&round5_ans[j]).unwrap());
            j += 1;
        }
    }

    let input_stage4 = KeyGenStage4Input {
        params_s: params.clone(),
        dlog_proof_vec_s: dlog_proof_vec,
        y_vec_s: input_stage3.y_vec_s,
    };

    let res = match keygen_stage4(&input_stage4) {
        Ok(res) => res,
        Err(e) => println!("Error: {:?}", e)
    };

    let paillier_keys: Vec<EncryptionKey> = 
                Vec::with_capacity(params.share_count as usize);
    let h1h2N_tilde: Vec<DLogStatement> = Vec::with_capacity(bc1_vec.len());

    for entry in bc1_vec {
        paillier_keys.push(entry.e);
        h1h2N_tilde.push(entry.dlog_statement);
    };
        
    PartyKeyPair {
        party_keys_s: input_stage3.party_keys_s,
        shared_keys: res_stage3.shared_keys_s,
        party_num_int_s: party,
        vss_scheme_vec_s: vss_scheme_vec,
        paillier_key_vec_s: paillier_keys,
        y_sum_s: y_sum,
        h1_h2_N_tilde: h1h2N_tilde,
    }
}

pub fn distributed_sign(message: String, client: &Client, reg: Registration, delay: std::time::Duration,
    keypair: PartyKeyPair, params: Parameters) -> Result<(), ErrorType> {

    let THRESHOLD = params.threshold;
    let party_num_int = params.share_count;

    // round 0: collect signers IDs
    broadcast(
        &client,
        params.share_count,
        "round0",
        serde_json::to_string(&keypair.party_num_int_s).unwrap(),
        &reg.uuid
    );

    let round0_ans_vec = poll_for_broadcasts(
        &client,
        params.share_count,
        params.threshold + 1,
        delay,
        "round0",
        &reg.uuid,
    );

    let mut j = 0;
    //0 indexed vec containing ids of the signing parties.
    
    

    let mut signers_vec: Vec<usize> = 
        Vec::with_capacity((params.threshold + 1) as usize);

    /* let signers_vec: Vec<usize> = match extract(&round0_ans_vec) {
        Ok(vec) => vec,
        Err(_) => panic!("Error!")
    }; */


    for i in 1..=params.threshold + 1 {
        if i == params.share_count {
            signers_vec.push((keypair.party_num_int_s - 1) as usize);
        } else {
            let signer_j: u16 = serde_json::from_str(&round0_ans_vec[j]).unwrap();
            signers_vec.push((signer_j - 1) as usize);
            j += 1;
        }
    }

    let input_stage1 = SignStage1Input {
        vss_scheme: keypair.vss_scheme_vec_s[signers_vec[(params.share_count - 1) as usize]],
        index: signers_vec[(params.share_count - 1) as usize],
        s_l: signers_vec,
        party_keys: keypair.party_keys_s,
        shared_keys: keypair.shared_keys,
    };

    let res_stage1 = sign_stage1(&input_stage1);
    // publish message A  and Commitment and then gather responses from other parties.
    assert!(broadcast(
        &client,
        params.share_count,
        "round1",
        serde_json::to_string(&(
            res_stage1.bc1,
            res_stage1.m_a.0,
            res_stage1.sign_keys.g_w_i
        ))
        .unwrap(),
        &reg.uuid
    )
    .is_ok());
    let round1_ans_vec = poll_for_broadcasts(
        &client,
        params.share_count,
        params.threshold + 1,
        delay,
        "round1",
        &reg.uuid,
    );

    let mut j = 0;
    let mut bc1_vec: Vec<SignBroadcastPhase1> = Vec::new();
    let mut m_a_vec: Vec<MessageA> = Vec::new();
    let mut g_w_i_vec: Vec<GE> = vec![];

    for i in 1..THRESHOLD + 2 {
        if i == party_num_int {
            bc1_vec.push(res_stage1.bc1.clone());
            g_w_i_vec.push(res_stage1.sign_keys.g_w_i.clone());
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
        m_a_vec: m_a_vec.clone(),
        gamma_i: res_stage1.sign_keys.gamma_i.clone(),
        w_i: res_stage1.sign_keys.w_i.clone(),
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
            let c_b_messageb_gammai = res_stage2.gamma_i_vec[j].0;
            let c_b_messageb_wi = res_stage2.w_i_vec[j].0;

            // If this client were implementing blame(Identifiable abort) then this message should have been broadcast.
            // For the current implementation p2p send is also fine.
            sendp2p(
                &client,
                party_num_int,
                i,
                "round2",
                serde_json::to_string(&(c_b_messageb_gammai, c_b_messageb_wi,)).unwrap(),
                &reg.uuid
            );
            

            j += 1;
        }
    }

    let round2_ans_vec = poll_for_p2p(
        &client,
        party_num_int,
        THRESHOLD + 1,
        delay,
        "round2",
        &reg.uuid,
    );

    let mut m_b_gamma_rec_vec: Vec<MessageB> = Vec::new();
    let mut m_b_w_rec_vec: Vec<MessageB> = Vec::new();

    for i in 0..THRESHOLD {
        let (l_mb_gamma, l_mb_w): (MessageB, MessageB) =
            serde_json::from_str(&round2_ans_vec[i as usize]).unwrap();
        m_b_gamma_rec_vec.push(l_mb_gamma);
        m_b_w_rec_vec.push(l_mb_w);
    }

    let input_stage3 = SignStage3Input {
        dk_s: keypair.party_keys_s.dk,
        k_i_s: res_stage1.sign_keys.k_i,
        m_b_gamma_s: m_b_gamma_rec_vec,
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
        sign_keys_s: res_stage1.sign_keys,
    };
    let res_stage4 = sign_stage4(&input_stage4).expect("Sign Stage4 failed.");
    //broadcast decommitment from stage1 and delta_i
    broadcast(
        &client,
        party_num_int,
        "round4",
        serde_json::to_string(&(res_stage1.decom1, res_stage4.delta_i,)).unwrap(),
        &reg.uuid
    );
    
    let round4_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        THRESHOLD + 1,
        delay,
        "round4",
        &reg.uuid,
    );

    let mut delta_i_vec = vec![];
    let mut decom1_vec = vec![];
    let mut j = 0;
    for i in 1..params.threshold + 2 {
        if i == params.share_count {
            delta_i_vec.push(res_stage4.delta_i);
            decom1_vec.push(res_stage1.decom1);
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
        bc1_vec: bc1_vec,
        index: (params.share_count - 1) as usize,
        sign_keys: res_stage1.sign_keys,
        s_ttag: signers_vec.len(),
    };
    let res_stage5 = sign_stage5(&input_stage5).expect("Sign Stage 5 failed.");
    broadcast(
        &client,
        params.share_count,
        "round5",
        serde_json::to_string(&(res_stage5.R_dash, res_stage5.R,)).unwrap(),
        &reg.uuid
    );
    
    let round5_ans_vec = poll_for_broadcasts(
        &client,
        params.share_count,
        THRESHOLD + 1,
        delay,
        "round5",
        &reg.uuid,
    );

    let mut R_vec = vec![];
    let mut R_dash_vec = vec![];
    let mut j = 0;
    for i in 1..THRESHOLD + 2 {
        if i == party_num_int {
            R_vec.push(res_stage5.R.clone());
            R_dash_vec.push(res_stage5.R_dash.clone());
        } else {
            let (R_dash, R): (GE, GE) = serde_json::from_str(&round5_ans_vec[j]).unwrap();
            R_vec.push(R);
            R_dash_vec.push(R_dash);
            j += 1;
        }
    }

    let message_bn = HSha256::create_hash(&[&BigInt::from_bytes(message)]);
    let input_stage6 = SignStage6Input {
        R_dash_vec: R_dash_vec.clone(),
        R: res_stage5.R.clone(),
        m_a: res_stage1.m_a.0.clone(),
        e_k: keypair.paillier_key_vec_s[signers_vec[(party_num_int - 1) as usize] as usize].clone(),
        k_i: res_stage1.sign_keys.k_i.clone(),
        randomness: res_stage1.m_a.1.clone(),
        party_keys: keypair.party_keys_s.clone(),
        h1_h2_N_tilde_vec: keypair.h1_h2_N_tilde.clone(),
        index: (party_num_int - 1) as usize,
        s: signers_vec.clone(),
        sigma: res_stage4.sigma_i.clone(),
        ysum: keypair.y_sum_s.clone(),
        sign_key: res_stage1.sign_keys.clone(),
        message_bn: message_bn.clone(),
    };
    let res_stage6 = sign_stage6(&input_stage6).expect("stage6 sign failed.");
    broadcast(
        &client,
        party_num_int,
        "round6",
        serde_json::to_string(&res_stage6.local_sig.clone()).unwrap(),
        &reg.uuid
    );
    
    let round6_ans_vec = poll_for_broadcasts(
        &client,
        party_num_int,
        THRESHOLD + 1,
        delay,
        "round6",
        &reg.uuid,
    );

    let mut local_sig_vec = vec![];
    let mut j = 0;
    for i in 1..THRESHOLD + 2 {
        if i == party_num_int {
            local_sig_vec.push(res_stage6.local_sig.clone());
        } else {
            let local_sig: LocalSignature = serde_json::from_str(&round6_ans_vec[j]).unwrap();
            local_sig_vec.push(local_sig);
            j += 1;
        }
    }
    let input_stage7 = SignStage7Input {
        local_sig_vec: local_sig_vec,
        ysum: keypair.y_sum_s,
    };
    let res_stage7 = sign_stage7(&input_stage7).expect("sign stage 7 failed");
    let sig = res_stage7.local_sig;
    println!(
        "party {:?} Output Signature: \nR: {:?}\ns: {:?} \nrecid: {:?} \n",
        party_num_int,
        sig.r.get_element(),
        sig.s.get_element(),
        sig.recid
    );

    Ok(())
}
