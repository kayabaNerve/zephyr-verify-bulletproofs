use serde::Deserialize;
use serde_json::json;

use monero_rpc::Rpc;
use monero_serai::{
  io::*,
  ringct::{clsag::Clsag, bulletproofs::Bulletproof},
};

use curve25519_dalek::{EdwardsPoint, Scalar, constants::ED25519_BASEPOINT_POINT};
use sha3::*;


#[tokio::main]
async fn main() {

  let H: EdwardsPoint = decompress_point(Keccak256::digest(&ED25519_BASEPOINT_POINT.compress().to_bytes()).into())
  .unwrap()
  .mul_by_cofactor();

  let tx_hashes = [
    // The transactions alleged to have invalid Bulletproofs
    "b17ef3d2e65ab980c8bd6cbe3210a8b3c9e417fb9621209380f7c1f756fcb2ed",
    "4e7ea2cc5484508bd17ff43f3fb8fbd69a22062f24a869794c513d89aee3eb6d",
    "d3abcf2bc0a173d6d8af19d88b2d7d610385abf258590d24ca82fc586017c6dd",
    // A transaction made earlier on the same day, which also isn't a conversion, not alleged to
    // have invalid Bulletproofs
    "784d3e756aed645606f74aa3519ecf96e137a025c22c9cc585a6d4ec0fdb651a",
    // A transaction made later on the same day, which also isn't a conversion, not alleged to have
    // invalid Bulletproofs
    "98b7180424495e3388c11b0ee9b4218018b06096b03ebde61467a4e9a49ddc79",
  ];

  let txs: Vec<Vec<u8>> = {
    let rpc =
      monero_simple_request_rpc::SimpleRequestRpc::new("http://node.zeph.network".to_string())
        .await
        .unwrap();

    #[derive(Debug, Deserialize)]
    struct TransactionResponse {
      tx_hash: String,
      as_hex: String,
    }
    #[derive(Debug, Deserialize)]
    struct TransactionsResponse {
      #[serde(default)]
      missed_tx: Vec<String>,
      txs: Vec<TransactionResponse>,
    }
    let txs: TransactionsResponse = rpc
      .rpc_call(
        "get_transactions",
        Some(json!({
        "txs_hashes": tx_hashes,
        })),
      )
      .await
      .unwrap();
    assert!(txs.missed_tx.is_empty());

    txs
      .txs
      .into_iter()
      .enumerate()
      .map(|(i, tx)| {
        assert_eq!(tx_hashes[i], tx.tx_hash);
        hex::decode(&tx.as_hex).unwrap()
      })
      .collect()
  };

  for (tx_hash, tx) in tx_hashes.into_iter().zip(txs) {
    let mut tx = tx.as_slice();
    let tx = &mut tx;

    // Prefix:
    // - version
    // - unlock_time
    // - vin
    // - vout
    // - extra
    // - pricing_record_height (varint)
    // - amount_burnt (varint)
    // - amount_minted (varint)
    let version = read_varint::<_, u64>(tx).unwrap();
    assert_eq!(version, 3);
    let _unlock_time = read_varint::<_, u64>(tx).unwrap();
    let inputs = read_varint::<_, u64>(tx).unwrap();
    for _ in 0 .. inputs {
      // TxIn:
      // - type
      // - amount
      // - asset_type
      // - key_offsets
      // - key_image
      let kind = read_byte(tx).unwrap();
      assert_eq!(kind, 2);
      let _amount = read_varint::<_, u64>(tx).unwrap();
      let asset_type = read_vec(read_byte, tx).unwrap();
      let _key_offsets = read_vec(read_varint::<_, u64>, tx).unwrap();
      assert_eq!(&asset_type, b"ZEPH");
      let _key_image = read_point(tx).unwrap();
    }
    let outputs = read_varint::<_, u64>(tx).unwrap();
    for _ in 0 .. outputs {
      // TxOut:
      // - amount
      // - type
      // - key
      // - asset_type
      // - view_tag
      let _amount = read_varint::<_, u64>(tx).unwrap();
      let kind = read_byte(tx).unwrap();
      assert_eq!(kind, 2);
      let _key = read_point(tx).unwrap();
      let asset_type = read_vec(read_byte, tx).unwrap();
      assert_eq!(&asset_type, b"ZEPH");
      let _view_tag = read_byte(tx).unwrap();
    }
    let _extra = read_vec(read_byte, tx).unwrap();
    let _pricing_record_height = read_varint::<_, u64>(tx).unwrap();
    let amount_burnt = read_varint::<_, u64>(tx).unwrap();
    let amount_minted = read_varint::<_, u64>(tx).unwrap();
    assert_eq!(amount_burnt, 0);
    assert_eq!(amount_minted, 0);

    // Base:
    // - type
    // - txnFee
    // - ecdhInfo
    // - outPk
    let kind = read_byte(tx).unwrap();
    assert_eq!(kind, 6);
    let _fee = read_varint::<_, u64>(tx).unwrap();
    let _ecdh_info = read_raw_vec(read_u64, outputs.try_into().unwrap(), tx).unwrap();
    let output_commitments = read_raw_vec(read_point, outputs.try_into().unwrap(), tx).unwrap();

    // Prunable:
    // - Option<BP+>
    // - CLSAGs
    // - Pseudo-outs
    let bp_present = read_byte(tx).unwrap();
    assert_eq!(bp_present, 1);
    let bp = Bulletproof::read_plus(tx).unwrap();

    const RING_LEN: usize = 16;
    let _clsags =
      read_raw_vec(|r| Clsag::read(RING_LEN, r), inputs.try_into().unwrap(), tx).unwrap();
    let _pseudo_outs = read_raw_vec(read_point, inputs.try_into().unwrap(), tx).unwrap();
    assert!(tx.is_empty());

    let valid = bp.verify(&mut rand_core::OsRng, &output_commitments);
    println!("{tx_hash} has valid Bulletproofs: {valid}");
    if !valid{
      //Check if adding 16 million to one of the commitments results in a valid BP+
      let amount_to_correct = Scalar::from(16_000_000u64*1_000_000_000_000); // 16 million in atomic units
      let mut output_commitments_adapted = output_commitments.clone();
      output_commitments_adapted[0] += amount_to_correct * H; // Modify first output
      let valid = bp.verify(&mut rand_core::OsRng, &output_commitments_adapted);
      if valid{
        println!("{tx_hash} with an additional 16 million added to the 1st output has valid Bulletproofs: {valid}");
      }
      let mut output_commitments_adapted = output_commitments.clone();
      output_commitments_adapted[1] += amount_to_correct * H; // Modify second output
      let valid = bp.verify(&mut rand_core::OsRng, &output_commitments_adapted);
      if valid{
        println!("{tx_hash} with an additional 16 million added to the 2nd output has valid Bulletproofs: {valid}");
      }
    }
  }
}
