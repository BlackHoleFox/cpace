use core::convert::TryInto;
use rand::rngs::OsRng;

use cpace;

#[test]
fn key_agreement() {
    let (init_msg, state) = cpace::init(
        "password",
        cpace::Context {
            initiator_id: "Alice",
            responder_id: "Bob",
            associated_data: &[],
        },
        OsRng,
    )
    .unwrap();

    let (bob_key, rsp_msg) = cpace::respond(
        init_msg,
        "password",
        cpace::Context {
            initiator_id: "Alice",
            responder_id: "Bob",
            associated_data: &[],
        },
        OsRng,
    )
    .unwrap();

    let alice_key = state.recv(rsp_msg).unwrap();

    assert_eq!(alice_key.0[..], bob_key.0[..]);
}

// These tests are ported over from https://github.com/FiloSottile/go-cpace-ristretto255/blob/master/cpace_test.go
#[test]
fn large_context_values() {
    const TOO_LARGE: usize = 1 << 16;

    let valid_context = cpace::Context {
        initiator_id: &"a".repeat(1 << (16 - 1)),
        responder_id: "b",
        associated_data: &[],
    };

    let (init_msg, state) = cpace::init("password", valid_context.clone(), OsRng)
        .expect("1 << 16 - 1 should be a valid initator size");

    let (bob_key, rsp_msg) = cpace::respond(init_msg, "password", valid_context.clone(), OsRng)
        .expect("A valid context should be valid to respond to");

    let alice_key = state.recv(rsp_msg).unwrap();

    assert_eq!(alice_key.0[..], bob_key.0[..]);

    let invalid_context = cpace::Context {
        initiator_id: &"a".repeat(TOO_LARGE),
        responder_id: "b",
        associated_data: &[],
    };

    let res = cpace::init("password", invalid_context, OsRng);

    assert!(matches!(
        res,
        Err(cpace::Error::InitiatorIdTooLong(TOO_LARGE))
    ));
}

#[test]
fn broken_message() {
    let context = cpace::Context {
        initiator_id: "192.0.2.1:12345",
        responder_id: "192.0.2.2:42",
        associated_data: &[],
    };

    let (init_msg, state) = cpace::init("password", context, OsRng).unwrap();

    // Initator too short not possible because the type system restricts the `InitMessage`
    // construction to force the array to be 48 bytes in length.

    {
        let mut init_msg_bytes = init_msg.0;

        init_msg_bytes[init_msg_bytes.len() - 1] ^= 0xff;
        let malformed_bytes = init_msg_bytes.try_into().unwrap();
        let malformed_init_msg = cpace::InitMessage(malformed_bytes);

        let res = cpace::respond(malformed_init_msg, "password", context, OsRng);

        assert!(matches!(res, Err(cpace::Error::InvalidPoint)));
    }

    let (_, rsp_msg) = cpace::respond(init_msg, "password", context, OsRng).unwrap();

    // The receiver being too short not possible because the type system restricts the `ResponseMessage` construction
    // to force the array to be 32 bytes in length.

    {
        let mut rsp_msg_bytes = rsp_msg.0;

        rsp_msg_bytes[rsp_msg_bytes.len() - 1] ^= 0xff;
        let malformed_bytes = rsp_msg_bytes.try_into().unwrap();
        let malformed_rsp_msg = cpace::ResponseMessage(malformed_bytes);
        let res = state.recv(malformed_rsp_msg);

        assert!(matches!(res, Err(cpace::Error::InvalidPoint)))
    }
}

struct Test<'ctx> {
    name: &'static str,
    password_a: &'static str,
    password_b: &'static str,
    context_a: cpace::Context<'ctx>,
    context_b: cpace::Context<'ctx>,
}

const VALID_TEST_PAIRS: &[Test] = &[
    Test {
        name: "valid, without ad",
        password_a: "p",
        password_b: "p",
        context_a: cpace::Context {
            initiator_id: "a",
            responder_id: "b",
            associated_data: &[],
        },
        context_b: cpace::Context {
            initiator_id: "a",
            responder_id: "b",
            associated_data: &[],
        },
    },
    Test {
        name: "valid, with ad",
        password_a: "p",
        password_b: "p",
        context_a: cpace::Context {
            initiator_id: "a",
            responder_id: "b",
            associated_data: b"x",
        },
        context_b: cpace::Context {
            initiator_id: "a",
            responder_id: "b",
            associated_data: b"x",
        },
    },
    Test {
        name: "valid, equal identities",
        password_a: "p",
        password_b: "p",
        context_a: cpace::Context {
            initiator_id: "a",
            responder_id: "b",
            associated_data: &[],
        },
        context_b: cpace::Context {
            initiator_id: "a",
            responder_id: "b",
            associated_data: &[],
        },
    },
];

const INVALID_TEST_PAIRS: &[Test] = &[
    Test {
        name: "different passwords",
        password_a: "p",
        password_b: "P",
        context_a: cpace::Context {
            initiator_id: "a",
            responder_id: "b",
            associated_data: &[],
        },
        context_b: cpace::Context {
            initiator_id: "a",
            responder_id: "b",
            associated_data: &[],
        },
    },
    Test {
        name: "different identity a",
        password_a: "p",
        password_b: "p",
        context_a: cpace::Context {
            initiator_id: "a",
            responder_id: "b",
            associated_data: &[],
        },
        context_b: cpace::Context {
            initiator_id: "x",
            responder_id: "b",
            associated_data: &[],
        },
    },
    Test {
        name: "different identity b",
        password_a: "p",
        password_b: "b",
        context_a: cpace::Context {
            initiator_id: "a",
            responder_id: "b",
            associated_data: &[],
        },
        context_b: cpace::Context {
            initiator_id: "a",
            responder_id: "x",
            associated_data: &[],
        },
    },
    Test {
        name: "different ad",
        password_a: "p",
        password_b: "p",
        context_a: cpace::Context {
            initiator_id: "a",
            responder_id: "b",
            associated_data: b"foo",
        },
        context_b: cpace::Context {
            initiator_id: "a",
            responder_id: "b",
            associated_data: b"bar",
        },
    },
    Test {
        name: "swapped identities",
        password_a: "p",
        password_b: "p",
        context_a: cpace::Context {
            initiator_id: "a",
            responder_id: "b",
            associated_data: &[],
        },
        context_b: cpace::Context {
            initiator_id: "b",
            responder_id: "a",
            associated_data: &[],
        },
    },
    Test {
        name: "missing ad",
        password_a: "p",
        password_b: "p",
        context_a: cpace::Context {
            initiator_id: "a",
            responder_id: "b",
            associated_data: b"x",
        },
        context_b: cpace::Context {
            initiator_id: "a",
            responder_id: "b",
            associated_data: &[],
        },
    },
    Test {
        name: "identity concatenation",
        password_a: "p",
        password_b: "p",
        context_a: cpace::Context {
            initiator_id: "ax",
            responder_id: "b",
            associated_data: &[],
        },
        context_b: cpace::Context {
            initiator_id: "a",
            responder_id: "xb",
            associated_data: &[],
        },
    },
    Test {
        name: "empty password",
        password_a: "p",
        password_b: "",
        context_a: cpace::Context {
            initiator_id: "a",
            responder_id: "b",
            associated_data: &[],
        },
        context_b: cpace::Context {
            initiator_id: "a",
            responder_id: "b",
            associated_data: &[],
        },
    },
];

fn do_exchange(test_case: &Test) -> (cpace::Key, cpace::Key) {
    let (init_msg, state) = match cpace::init(test_case.password_a, test_case.context_a, OsRng) {
        Ok((init_msg, state)) => (init_msg, state),
        _ => panic!(
            "Test case '{}' should be able to start the protocol!",
            test_case.name
        ),
    };

    let (bob_key, rsp_msg) =
        match cpace::respond(init_msg, test_case.password_b, test_case.context_b, OsRng) {
            Ok((bob_key, rsp_msg)) => (bob_key, rsp_msg),
            _ => panic!(
                "Test case '{}' should be able to respond to the inital message!",
                test_case.name
            ),
        };

    let alice_key = match state.recv(rsp_msg) {
        Ok(key) => key,
        _ => panic!(
            "Test case '{}' should be able to get the shared key!",
            test_case.name
        ),
    };

    (alice_key, bob_key)
}

const OUT_KEY_SIZE: usize = 32;

#[test]
fn test_valid_case_sets() {
    for test_case in VALID_TEST_PAIRS {
        let (alice_key, bob_key) = do_exchange(test_case);
        assert_eq!(
            alice_key.0[..],
            bob_key.0[..],
            "The two parties should have shared keys!"
        );

        assert_eq!(alice_key.0.len(), OUT_KEY_SIZE);
        assert_eq!(bob_key.0.len(), OUT_KEY_SIZE);
    }
}

#[test]
fn test_invalid_case_sets() {
    for test_case in INVALID_TEST_PAIRS {
        let (alice_key, bob_key) = do_exchange(test_case);

        assert_eq!(alice_key.0.len(), OUT_KEY_SIZE);
        assert_eq!(bob_key.0.len(), OUT_KEY_SIZE);

        assert_ne!(alice_key.0[..], bob_key.0[..])
    }
}

// testIdentity not ported because the Rust Ristretto point
// implementation doesn't have the equivalent of `point.Encode()`.
