use curv::{
    cryptographic_primitives::{
        proofs::sigma_dlog::DLogProof, secret_sharing::feldman_vss::VerifiableSS,
    },
    elliptic::curves::{
         secp256_k1::{
            FE, GE
        }
    }
};

use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i::{
    KeyGenBroadcastMessage1, KeyGenDecommitMessage1, Parameters, SharedKeys,
    Keys
};
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::orchestrate::*;

use paillier::*;
use zk_paillier::zkproofs::DLogStatement;

use std::time::Duration;
use reqwest::Client;

use serde::{Serialize, Deserialize};

fn poll_for_broadcasts(    
    _client: &Client,
    _party_num: u16,
    _n: u16,
    _delay: Duration,
    _round: &str,
    _sender_uuid: String) -> Vec<String> {
        vec![String::from("hello")]
    
}

#[allow(dead_code)]
enum Message {
    Round1(KeyGenStage1Result),
    Round2(KeyGenStage2Result),
    Round3(KeyGenStage3Result),
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
trait Channel {
    fn send_to_peer() -> Result<(), ()>;
    fn broadcast() -> Result<(), ()>;
    fn receive_single() -> Result<Message, ()>;
    fn receive_broadcast() -> Result<Vec<Message>, ()>;
}



pub fn sendp2p(
    _client: &Client,
    _party_from: u16,
    _party_to: u16,
    _round: &str,
    _data: String,
    _sender_uuid: String,
) -> Result<(), ()> {
    Ok(())
}

pub fn broadcast(
    _client: &Client,
    _party_num: u16,
    _round: &str,
    _data: String,
    _sender_uuid: String,
) -> Result<(), ()> {
    Ok(())
}

pub fn poll_for_p2p(
    _client: &Client,
    _party_num: u16,
    _n: u16,
    _delay: Duration,
    _round: &str,
    _sender_uuid: String,
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

fn extract<'a, T: Deserialize<'a>>(vals: &'a Vec< String>) -> Result<Vec<T>, ()> {
    let mut results: Vec<T> = Vec::with_capacity(vals.len());

    for str in vals {
        match serde_json::from_str::<'a, T>(&str) {
            Ok(val) => results.push(val),
            Err(_) => return Err(())
        }
    }

   Ok(results) 
}


#[allow(unused_variables)]
fn main() {

    let params = Parameters { share_count: 3, threshold: 2};

    let party = params.share_count;

    let delay = Duration::from_millis(25);
    let input_stage1 = KeyGenStage1Input {
        index: (party - 1) as usize,
    };

    let uuid = String::from("Hello");

    let client = Client::new();

    let res_stage1: KeyGenStage1Result = keygen_stage1(&input_stage1);
     
    assert!(broadcast(
        &client,
        party,
        "round1",
        serde_json::to_string(&res_stage1.bc_com1_l).unwrap(),
        uuid.clone()
    )
    .is_ok());


    let round1_ans_vec = poll_for_broadcasts(
        &client,
        party,
        params.threshold,
        delay,
        "round1",
        uuid.clone(),
    );
   
    
    let mut bc1_vec = round1_ans_vec
        .iter()
        .map(|m| serde_json::from_str::<KeyGenBroadcastMessage1>(m).unwrap())
        .collect::<Vec<_>>();

    bc1_vec.insert(party as usize - 1, res_stage1.bc_com1_l);
    assert!(broadcast(
        &client,
        party,
        "round2",
        serde_json::to_string(&res_stage1.decom1_l).unwrap(),
        uuid.clone()
    )
    .is_ok());
    
    let round2_ans_vec = poll_for_broadcasts(
        &client,
        party,
        params.share_count,
        delay,
        "round2",
        uuid.clone(),
    );


    // TODO Is there anything we can do to move this into a function?
    let mut decom1_vec = round2_ans_vec
        .iter()
        .map(|m| serde_json::from_str::<KeyGenDecommitMessage1>(m).unwrap())
        .collect::<Vec<_>>();

    decom1_vec.insert(party as usize - 1, res_stage1.decom1_l);
    let input_stage2 = KeyGenStage2Input {
        index: (party - 1) as usize,
        params_s: params.clone(),
        party_keys_s: res_stage1.party_keys_l.clone(),
        decom1_vec_s: decom1_vec.clone(),
        bc1_vec_s: bc1_vec.clone(),
    };

    // TODO Use the ErrorType value, even if right now there's no way to access its fields
    let res_stage2 = match keygen_stage2(&input_stage2) {
        Ok(res) => res,
        Err(e) => panic!("Error {:?}", e)
    };


    let mut points: Vec<GE> = Vec::new();
    for i in 1..=params.share_count {
        points.push(decom1_vec[(i - 1) as usize].y_i);
    }

    let (head, tail) = points.split_at(1);
    let y_sum = tail.iter().fold(head[0], |acc, x| acc + x);

    for (k, i) in (1..=params.share_count).enumerate() {
        if i != party {
            assert!(sendp2p(
                &client,
                party,
                i,
                "round3",
                serde_json::to_string(&res_stage2.secret_shares_s[k]).unwrap(),
                uuid.clone()
            )
            .is_ok());
        }
    }

    // get shares from other parties.
    let round3_ans_vec = poll_for_p2p(
        &client,
        party,
        params.share_count,
        delay,
        "round3",
        uuid.clone(),
    );
    // decrypt shares from other parties.
    let mut j = 0;
    let mut party_shares: Vec<FE> = Vec::new();
    for i in 1..=params.share_count {
        if i == party {
            party_shares.push(res_stage2.secret_shares_s[(i - 1) as usize]);
        } else {
            party_shares.push(serde_json::from_str(&round3_ans_vec[j]).unwrap());
            j += 1;
        }
    }
    assert!(broadcast(
        &client,
        party,
        "round4",
        serde_json::to_string(&res_stage2.vss_scheme_s).unwrap(),
        uuid.clone()
    )
    .is_ok());

    //get vss_scheme for others.
    let round4_ans_vec = poll_for_broadcasts(
        &client,
        party,
        params.share_count,
        delay,
        "round4",
        uuid.clone(),
    );

    let round4_ans_vec2: Vec<VerifiableSS<GE>> = match extract(&round4_ans_vec) {
        Ok(vec) => vec,
        Err(_) => panic!("Could not convert toe verifiables!")
    };

    let mut j = 0;
    let mut vss_scheme_vec: Vec<VerifiableSS<GE>> = Vec::new();
    for i in 1..=params.share_count {
        if i == party {
            vss_scheme_vec.push(res_stage2.vss_scheme_s.clone());
        } else {
            vss_scheme_vec.push(serde_json::from_str(&round4_ans_vec[j]).unwrap());
            j += 1;
        }
    }


    let input_stage3 = KeyGenStage3Input {
        party_keys_s: res_stage1.party_keys_l,
        vss_scheme_vec_s: vss_scheme_vec.clone(),
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
    assert!(broadcast(
        &client,
        party,
        "round5",
        serde_json::to_string(&res_stage3.dlog_proof_s).unwrap(),
        uuid.clone()
    )
    .is_ok());

    let round5_ans = poll_for_broadcasts(
        &client,
        party,
        params.share_count,
        delay,
        "round5",
        uuid.clone(),
    );

    let mut j = 0;
    let mut dlog_proof_vec: Vec<DLogProof<GE>> = Vec::new();
    for i in 1..=params.share_count {
        if i == party {
            dlog_proof_vec.push(res_stage3.dlog_proof_s.clone());
        } else {
            dlog_proof_vec.push( serde_json::from_str(&round5_ans[j]).unwrap());
            j += 1;
        }
    }

    let input_stage4 = KeyGenStage4Input {
        params_s: params.clone(),
        dlog_proof_vec_s: dlog_proof_vec.clone(),
        y_vec_s: input_stage3.y_vec_s,
    };
    let res = match keygen_stage4(&input_stage4) {
        Ok(res) => res,
        Err(e) => println!("Error: {:?}", e)
    };

    let paillier_key_vec = (0..params.share_count)
        .map(|i| bc1_vec[i as usize].e.clone())
        .collect::<Vec<EncryptionKey>>();

    let h1_h2_N_tilde = bc1_vec
        .iter()
        .map(|bc1| bc1.dlog_statement.clone())
        .collect::<Vec<DLogStatement>>();
        
    let party_key_pair = PartyKeyPair {
        party_keys_s: input_stage3.party_keys_s,
        shared_keys: res_stage3.shared_keys_s.clone(),
        party_num_int_s: party,
        vss_scheme_vec_s: vss_scheme_vec.clone(),
        paillier_key_vec_s: paillier_key_vec,
        y_sum_s: y_sum,
        h1_h2_N_tilde: h1_h2_N_tilde,
    };
}
