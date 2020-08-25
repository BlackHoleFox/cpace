use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

use cpace;

// These are the first 200 bytes (hex encoded) from the go-cpace transcript test seeded RNG.
// It uses HKDF<SHA256> with a IKM of b"INSECURE".
const RNG_SEEDED_BYTES: &str = "11ab582caf3635b3801183db14a5a5bb38e513217316f8606c7d8f6dc955076d2479483a11aaf7d89bfd04c6971b56c1ca5f84080081b47df5cc9ba0e25bc0a894f7476153423d4487f2f75e55a0b7a608092044474aba5219db27d985d4f507ca835cd943783d58d8c5311bb2fb2999f36ba85c46c19be6d65066b398d2aff43f8c854983f4365202b3c706c1ded7f5b06a3389b57b4bd43631d53f810ed6135eb399fff4103482c19a506c6dde2eeaaaf84bc8dc8e198a01873f88678b41f9b0493d7480996439";

struct TestingRng {
    byte_pool: Vec<u8>,
}

// "Don't try this at home" -- FiloSottile
impl RngCore for TestingRng {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_u64(&mut self) -> u64 {
        self.byte_pool.remove(0) as u64
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let dest_len = dest.len();
        dest[..].copy_from_slice(&self.byte_pool[..dest_len]);
        self.byte_pool.drain(..dest.len()).count();
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        Ok(self.fill_bytes(dest))
    }
}

// "Really don't try this at home" -- Fox
impl CryptoRng for TestingRng {}

const PASSWORD: &str = "password";

const CONTEXT: cpace::Context = cpace::Context {
    initiator_id: "a",
    responder_id: "b",
    associated_data: b"ad",
};

const EXPECTED_INIT_MSG: &str = "11ab582caf3635b3801183db14a5a5bb14575029b4fa53c53a9fca55e7ab4aab9179d5530fbdb70d172bc8b8cf521d35";
const EXPECTED_RSP_MSG: &str = "a229fc634fe3a760361e56d8dab37b9befe941cd62290eba324a9e25f73d1312";

const EXPECTED_SHARED_KEY: &str =
    "54ccaa1f1d24b270075157549c54942adef8331ef733a17ffebe72b6dd663e89";

const EXPECTED_FINAL_TRANSCRIPT: &str = "NpHB1PcNLBGo9idbTXys5aRkuAlV+FQAshGfsJoxs3g";

#[test]
fn transcript() {
    let seed = hex::decode(&RNG_SEEDED_BYTES).unwrap();

    let mut rng = TestingRng { byte_pool: seed };

    let mut tx = Sha256::new();

    let (init_msg, state) = cpace::init(PASSWORD, CONTEXT, &mut rng).unwrap();

    tx.update(&init_msg.0.as_ref());

    let found_init_msg = hex::encode(&init_msg.0.as_ref());
    assert_eq!(&found_init_msg, EXPECTED_INIT_MSG);

    let (bob_key, rsp_msg) = cpace::respond(init_msg, PASSWORD, CONTEXT, &mut rng).unwrap();

    tx.update(&rsp_msg.0.as_ref());
    tx.update(&bob_key.0);

    let found_rsp_msg = hex::encode(&rsp_msg.0);
    assert_eq!(&found_rsp_msg, EXPECTED_RSP_MSG);

    let alice_key = state.recv(rsp_msg).unwrap();

    assert_eq!(alice_key.0[..], bob_key.0[..]);
    assert_eq!(
        alice_key.0[..],
        hex::decode(EXPECTED_SHARED_KEY).unwrap()[..]
    );

    let digest = tx.finalize();
    let found_sum = base64::encode_config(&digest, base64::STANDARD_NO_PAD);
    assert_eq!(&found_sum, EXPECTED_FINAL_TRANSCRIPT);
}
