use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i::{SharedKeys, Keys};
use curv::elliptic::curves::secp256_k1::{GE};
use paillier::EncryptionKey;
use zk_paillier::zkproofs::DLogStatement;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;

use serde::{Serialize, Deserialize};

pub mod dkg;
pub mod signing;
use super::utils;

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

