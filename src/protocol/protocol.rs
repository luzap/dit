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


use paillier::*;
use zk_paillier::zkproofs::DLogStatement;

use std::time::Duration;
use reqwest;
use serde::{Serialize, Deserialize};
use std::{env, thread, time};
use std::fmt;


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

