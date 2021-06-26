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
    Keys, SignBroadcastPhase1, SignDecommitPhase1, SignKeys, SignatureRecid, 
    LocalSignature
};

use multi_party_ecdsa::utilities::mta::{MessageA, MessageB};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::orchestrate::*;


use paillier::*;
use zk_paillier::zkproofs::DLogStatement;

use std::time::Duration;
use reqwest;
use serde::{Serialize, Deserialize};
use std::{env, thread, time};
use std::fmt;


pub type Key = String;


#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct PartySignup {
    pub number: u16,
    pub uuid: String,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Index {
    pub key: Key,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Entry {
    pub key: Key,
    pub value: String,
}

#[derive(Serialize, Deserialize)]
pub struct Params {
    pub parties: String,
    pub threshold: String,
}

pub struct Channel {
    client: reqwest::Client,
    uuid: String
}

impl Channel {

    pub fn new() -> Channel {
        Channel {
            client: reqwest::Client::new(), 
            uuid: "".to_string()
        }
    }


    fn postb<T>(&self, path: &str, body: T) -> Option<String>
    where
        T: serde::ser::Serialize,
    {
        let addr = env::args()
            .nth(1)
            .unwrap_or_else(|| "http://localhost:8000".to_string());
        let retries = 3;
        let retry_delay = time::Duration::from_millis(250);
        for _i in 1..retries {
            let res = self.client
                .post(&format!("{}/{}", addr, path))
                .json(&body)
                .send();

            if let Ok(mut res) = res {
                return Some(res.text().unwrap());
            }
            thread::sleep(retry_delay);
        }
        None
    }

    pub fn broadcast(
        &self,
        party_num: u16,
        round: &str,
        data: String,
    ) -> Result<(), ()> {
        let key = format!("{}-{}-{}", party_num, round, self.uuid);
        let entry = Entry {
            key: key.clone(),
            value: data,
        };

        let res_body = self.postb("set", entry).unwrap();
        serde_json::from_str(&res_body).unwrap()
    }

    pub fn sendp2p(
        &self,
        party_from: u16,
        party_to: u16,
        round: &str,
        data: String,
    ) -> Result<(), ()> {
        let key = format!("{}-{}-{}-{}", party_from, party_to, round, self.uuid);

        let entry = Entry {
            key: key.clone(),
            value: data,
        };

        let res_body = self.postb("set", entry).unwrap();
        serde_json::from_str(&res_body).unwrap()
    }

    pub fn poll_for_broadcasts(
        &self,
        party_num: u16,
        n: u16,
        delay: Duration,
        round: &str,
    ) -> Vec<String> {
        let mut ans_vec = Vec::new();
        for i in 1..=n {
            if i != party_num {
                let key = format!("{}-{}-{}", i, round, self.uuid);
                let index = Index { key };
                loop {
                    // add delay to allow the server to process request:
                    thread::sleep(delay);
                    let res_body = self.postb("get", index.clone()).unwrap();
                    let answer: Result<Entry, ()> = serde_json::from_str(&res_body).unwrap();
                    if let Ok(answer) = answer {
                        ans_vec.push(answer.value);
                        println!("[{:?}] party {:?} => party {:?}", round, i, party_num);
                        break;
                    }
                }
            }
        }
        ans_vec
    }

    pub fn poll_for_p2p(
        &self,
        party_num: u16,
        n: u16,
        delay: Duration,
        round: &str,
    ) -> Vec<String> {
        let mut ans_vec = Vec::new();
        for i in 1..=n {
            if i != party_num {
                let key = format!("{}-{}-{}-{}", i, party_num, round, self.uuid);
                let index = Index { key };
                loop {
                    // add delay to allow the server to process request:
                    thread::sleep(delay);
                    let res_body = self.postb("get", index.clone()).unwrap();
                    let answer: Result<Entry, ()> = serde_json::from_str(&res_body).unwrap();
                    if let Ok(answer) = answer {
                        ans_vec.push(answer.value);
                        println!("[{:?}] party {:?} => party {:?}", round, i, party_num);
                        break;
                    }
                }
            }
        }
        ans_vec
    }

    pub fn signup_keygen(&mut self) -> Result<u16, Errors> {
        let key = "signup-keygen".to_string();

        let res_body: String = match self.postb("signupkeygen", key) {
            Some(res) => res,
            None => return Err(Errors::ResponseError)
        };

        match serde_json::from_str(&res_body) {
            Ok(PartySignup { uuid, number } ) => {
                self.uuid = uuid;
                return Ok(number)
            },
            Err(_) => return Err(Errors::DeserializationError)

        };
    }


    fn signup_sign(&mut self) -> Result<u16, Errors> {
        let key = "signup-sign".to_string();

        let res_body: String = match self.postb("signupsign", key) {
            Some(res) => res,
            None => return Err(Errors::ResponseError)
        };

        match serde_json::from_str(&res_body) {
            Ok(PartySignup { uuid, number } ) => {
                self.uuid = uuid;
                return Ok(number)
            },
            Err(_) => return Err(Errors::DeserializationError)
        };
    }
}

#[allow(dead_code)]
pub fn check_sig(r: &FE, s: &FE, msg: &BigInt, pk: &GE) {
    use secp256k1::{verify, Message, PublicKey, PublicKeyFormat, Signature};

    let raw_msg = BigInt::to_bytes(&msg);
    let mut msg: Vec<u8> = Vec::new(); // padding
    msg.extend(vec![0u8; 32 - raw_msg.len()]);
    msg.extend(raw_msg.iter());

    let msg = Message::parse_slice(msg.as_slice()).unwrap();
    let mut raw_pk = pk.pk_to_key_slice();
    if raw_pk.len() == 64 {
        raw_pk.insert(0, 4u8);
    }
    let pk = PublicKey::parse_slice(&raw_pk, Some(PublicKeyFormat::Full)).unwrap();

    let mut compact: Vec<u8> = Vec::new();
    let bytes_r = &r.get_element()[..];
    compact.extend(vec![0u8; 32 - bytes_r.len()]);
    compact.extend(bytes_r.iter());

    let bytes_s = &s.get_element()[..];
    compact.extend(vec![0u8; 32 - bytes_s.len()]);
    compact.extend(bytes_s.iter());

    let secp_sig = Signature::parse_slice(compact.as_slice()).unwrap();

    let is_correct = verify(&msg, &secp_sig, &pk);
    assert!(is_correct);
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartyKeyPair {
    pub party_keys_s: Keys,
    pub shared_keys: SharedKeys,
    pub party_num_int_s: u16,
    pub vss_scheme_vec_s: Vec<VerifiableSS<GE>>,
    pub paillier_key_vec_s: Vec<EncryptionKey>,
    pub y_sum_s: GE,
    pub h1_h2_N_tilde_vec_s: Vec<DLogStatement>,
}



pub fn extract<'a, T: Deserialize<'a>>(vals: &'a Vec< String>, size: usize) -> Result<Vec<T>, ()> {
    let mut results: Vec<T> = Vec::with_capacity(size);

    for (i, str) in vals.iter().enumerate() {
        match serde_json::from_str::<'a, T>(&str) {
            Ok(val) => results.insert(i, val),
            Err(_) => return Err(())
        }
    }

   Ok(results) 
}

impl From<Params> for Parameters {
    fn from(item: Params) -> Self {
        Parameters {
            share_count: item.parties.parse::<u16>().unwrap(),
            threshold: item.threshold.parse::<u16>().unwrap(),
        }
    }
}

#[derive(Debug)]
pub enum Errors {
    DeserializationError,
    ResponseError,
    SendError
}


pub fn distributed_keygen() -> Result<PartyKeyPair, Errors> {

    let params = Parameters { threshold: 2, share_count: 4 };
    let mut channel = Channel::new();
    let party_num_int = match channel.signup_keygen() {
        Ok(i) => i,
        Err(_) => return Err(Errors::ResponseError),
    };

    let delay = time::Duration::from_millis(25);
    let input_stage1 = KeyGenStage1Input {
        index: (party_num_int - 1) as usize,
    };

    let res_stage1: KeyGenStage1Result = keygen_stage1(&input_stage1);

    match channel.broadcast(
        party_num_int,
        "round1",
        serde_json::to_string(&res_stage1.bc_com1_l).unwrap(),
    ) {
            Ok(()) => {},
            Err(()) => return Err(Errors::SendError)
        };
    
    let round1_ans_vec = channel.poll_for_broadcasts(
        party_num_int,
        params.share_count,
        delay,
        "round1",
    );

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
            Ok(()) => {},
            Err(()) => return Err(Errors::SendError)
        };

    let round2_ans_vec = channel.poll_for_broadcasts(
        party_num_int,
        params.share_count,
        delay,
        "round2",
    );

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

    let (head, tail) = point_vec.split_at(1);
    let y_sum = tail.iter().fold(head[0], |acc, x| acc + x);

    for (k, i) in (1..=params.share_count).enumerate() {
        if i != party_num_int {
            assert!(channel.sendp2p(
                party_num_int,
                i,
                "round3",
                serde_json::to_string(&res_stage2.secret_shares_s[k]).unwrap(),
            )
            .is_ok());
        }
    }
    // get shares from other parties.
    let round3_ans_vec = channel.poll_for_p2p(
        party_num_int,
        params.share_count,
        delay,
        "round3",
    );

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

    assert!(channel.broadcast(party_num_int, "round4",
        serde_json::to_string(&res_stage2.vss_scheme_s).unwrap(),
    )
    .is_ok());

    //get vss_scheme for others.
    let round4_ans_vec = channel.poll_for_broadcasts(party_num_int, 
        params.share_count, delay, "round4"
    );

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
    assert!(channel.broadcast(
        party_num_int,
        "round5",
        serde_json::to_string(&res_stage3.dlog_proof_s).unwrap(),
    )
    .is_ok());
    let round5_ans_vec = channel.poll_for_broadcasts(
        party_num_int,
        params.share_count,
        delay,
        "round5",
    );

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
        dlog_proof_vec_s: dlog_proof_vec.clone(),
        y_vec_s: point_vec.clone(),
    };

    let _ = keygen_stage4(&input_stage4).expect("keygen stage4 failed.");
    //save key to file:
    let paillier_key_vec = (0..params.share_count)
        .map(|i| bc1_vec[i as usize].e.clone())
        .collect::<Vec<EncryptionKey>>();
    let h1_h2_N_tilde_vec = bc1_vec
        .iter()
        .map(|bc1| bc1.dlog_statement.clone())
        .collect::<Vec<DLogStatement>>();

    Ok(PartyKeyPair {
        party_keys_s: res_stage1.party_keys_l.clone(),
        shared_keys: res_stage3.shared_keys_s.clone(),
        party_num_int_s: party_num_int,
        vss_scheme_vec_s: vss_scheme_vec.clone(),
        paillier_key_vec_s: paillier_key_vec,
        y_sum_s: y_sum,
        h1_h2_N_tilde_vec_s: h1_h2_N_tilde_vec,
    })
}

pub fn distributed_sign(message_str: String, keypair: PartyKeyPair) -> Result<SignatureRecid, Errors> {

    let params = Parameters { threshold: 2, share_count: 4 };
    let mut channel = Channel::new();
    // delay:
    let delay = time::Duration::from_millis(25);

    let THRESHOLD = params.threshold;

    let message = match hex::decode(message_str.clone()) {
        Ok(x) => x,
        Err(_e) => message_str.as_bytes().to_vec(),
    };
    let message = &message[..];

    let party_num_int = match channel.signup_sign() {
        Ok(i) => i,
        Err(_) => return Err(Errors::ResponseError),
    };

    // round 0: collect signers IDs
    assert!(channel.broadcast(
        party_num_int,
        "round0",
        serde_json::to_string(&keypair.party_num_int_s).unwrap(),
    )
    .is_ok());

    let round0_ans_vec = channel.poll_for_broadcasts(
        party_num_int,
        THRESHOLD + 1,
        delay,
        "round0",
    );

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
    assert!(channel.broadcast(
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
    let round1_ans_vec = channel.poll_for_broadcasts(
        party_num_int,
        THRESHOLD + 1,
        delay,
        "round1",
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
            let c_b_messageb_gammai = res_stage2.gamma_i_vec[j].0.clone();
            let c_b_messageb_wi = res_stage2.w_i_vec[j].0.clone();

            // If this client were implementing blame(Identifiable abort) then this message should have been broadcast.
            // For the current implementation p2p send is also fine.
            assert!(channel.sendp2p(
                party_num_int,
                i,
                "round2",
                serde_json::to_string(&(c_b_messageb_gammai, c_b_messageb_wi,)).unwrap(),
            )
            .is_ok());

            j += 1;
        }
    }

    let round2_ans_vec = channel.poll_for_p2p( party_num_int, THRESHOLD + 1, 
        delay, "round2"
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
        dk_s: keypair.party_keys_s.dk.clone(),
        k_i_s: res_stage1.sign_keys.k_i.clone(),
        m_b_gamma_s: m_b_gamma_rec_vec.clone(),
        m_b_w_s: m_b_w_rec_vec.clone(),
        index_s: (party_num_int - 1) as usize,
        ttag_s: signers_vec.len(),
        g_w_i_s: g_w_i_vec.clone(),
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
        alpha_vec_s: alpha_vec.clone(),
        beta_vec_s: beta_vec.clone(),
        miu_vec_s: miu_vec.clone(),
        ni_vec_s: ni_vec.clone(),
        sign_keys_s: res_stage1.sign_keys.clone(),
    };
    let res_stage4 = sign_stage4(&input_stage4).expect("Sign Stage4 failed.");
    //broadcast decommitment from stage1 and delta_i
    assert!(channel.broadcast(
        party_num_int,
        "round4",
        serde_json::to_string(&(res_stage1.decom1.clone(), res_stage4.delta_i,)).unwrap(),
    )
    .is_ok());

    let round4_ans_vec = channel.poll_for_broadcasts(
        party_num_int,
        THRESHOLD + 1,
        delay,
        "round4",
    );

    let mut delta_i_vec = vec![];
    let mut decom1_vec = vec![];
    let mut j = 0;
    for i in 1..THRESHOLD + 2 {
        if i == party_num_int {
            delta_i_vec.push(res_stage4.delta_i.clone());
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
        m_b_gamma_vec: m_b_gamma_rec_vec.clone(),
        delta_inv: delta_inv_l.clone(),
        decom_vec1: decom1_vec.clone(),
        bc1_vec: bc1_vec.clone(),
        index: (party_num_int - 1) as usize,
        sign_keys: res_stage1.sign_keys.clone(),
        s_ttag: signers_vec.len(),
    };
    let res_stage5 = sign_stage5(&input_stage5).expect("Sign Stage 5 failed.");
    assert!(channel.broadcast(
        party_num_int,
        "round5",
        serde_json::to_string(&(res_stage5.R_dash.clone(), res_stage5.R.clone(),)).unwrap(),
    )
    .is_ok());

    let round5_ans_vec = channel.poll_for_broadcasts(
        party_num_int,
        THRESHOLD + 1,
        delay,
        "round5",
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
        h1_h2_N_tilde_vec: keypair.h1_h2_N_tilde_vec_s.clone(),
        index: (party_num_int - 1) as usize,
        s: signers_vec.clone(),
        sigma: res_stage4.sigma_i.clone(),
        ysum: keypair.y_sum_s.clone(),
        sign_key: res_stage1.sign_keys.clone(),
        message_bn: message_bn.clone(),
    };
    let res_stage6 = sign_stage6(&input_stage6).expect("stage6 sign failed.");
    assert!(channel.broadcast(
        party_num_int,
        "round6",
        serde_json::to_string(&res_stage6.local_sig.clone()).unwrap(),
    )
    .is_ok());
    let round6_ans_vec = channel.poll_for_broadcasts(
        party_num_int,
        THRESHOLD + 1,
        delay,
        "round6",
    );

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
        local_sig_vec: local_sig_vec.clone(),
        ysum: keypair.y_sum_s.clone(),
    };
    let res_stage7 = sign_stage7(&input_stage7).expect("sign stage 7 failed");

    check_sig(&res_stage7.local_sig.r, &res_stage7.local_sig.s, &message_bn, &keypair.y_sum_s);
    Ok(res_stage7.local_sig)
}
