//! P2 performance regression benchmarks for FIBEMATE's crypto hot paths.
//!
//! Coverage (aligned with the deep-test plan):
//!   * ML-KEM-768  (FIPS 203) — keygen / encapsulate / decapsulate
//!   * ML-DSA-65   (FIPS 204) — keygen / sign 1KB / verify 1KB
//!   * SM2         (GB/T 32918) — keygen / sign / verify / encrypt 1KB / decrypt 1KB
//!   * X3DH        (X25519)   — initiator / responder
//!   * Double Ratchet         — session create / encrypt 1KB / decrypt 1KB
//!   * DR sustained throughput — 100 sequential 1KB messages encrypt / decrypt
//!   * Session persistence    — encrypted save/load of 50 sessions
//!   * KeyStore               — store/load 32B secret (DPAPI + AES-256-GCM)
//!
//! Run locally:      cargo bench
//! Record baseline:  cargo bench -- --save-baseline main
//! Compare later:    cargo bench -- --baseline main
//! CI threshold gate: python scripts/perf_check.py

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use fibemate_lib::double_ratchet::{
    load_sessions_from_disk_decrypted, RatchetKeyPair, SessionManager, X3DH,
};
use fibemate_lib::key_store::KeyStore;
use fibemate_lib::pq::{
    mlkem768_decapsulate, mlkem768_encapsulate, mlkem768_generate, MlDsa65KeyPair,
};
use fibemate_lib::sm2;
use num_bigint::BigUint;

const KB: usize = 1024;

// ── ML-KEM-768 ─────────────────────────────────────────────────

fn bench_mlkem768(c: &mut Criterion) {
    let mut g = c.benchmark_group("mlkem768");

    g.bench_function("keygen", |b| {
        b.iter(|| black_box(mlkem768_generate()));
    });

    // encapsulate needs a fresh pk per batch but the pk itself is not part
    // of the measured routine — criterion excludes setup time.
    g.bench_function("encapsulate", |b| {
        b.iter_batched(
            || mlkem768_generate().0,
            |pk| black_box(mlkem768_encapsulate(&pk)),
            BatchSize::SmallInput,
        )
    });

    let (pk, sk) = mlkem768_generate();
    let (ct, _) = mlkem768_encapsulate(&pk);
    g.bench_function("decapsulate", |b| {
        b.iter(|| black_box(mlkem768_decapsulate(&sk, &ct)));
    });

    g.finish();
}

// ── ML-DSA-65 ──────────────────────────────────────────────────

fn bench_mldsa65(c: &mut Criterion) {
    let mut g = c.benchmark_group("mldsa65");
    // sign/verify are the slowest operations here (~ms); 30 samples keep the
    // total wall time reasonable while estimates stay statistically stable.
    g.sample_size(30);

    g.bench_function("keygen", |b| {
        b.iter(|| black_box(MlDsa65KeyPair::generate()));
    });

    let kp = MlDsa65KeyPair::generate();
    let msg = vec![0xABu8; KB];
    let sig = kp.sign(&msg, b"bench").unwrap();

    g.bench_function("sign_1kb", |b| {
        b.iter(|| black_box(kp.sign(&msg, b"bench").unwrap()));
    });
    g.bench_function("verify_1kb", |b| {
        b.iter(|| black_box(kp.verify(&msg, b"bench", &sig).unwrap()));
    });

    g.finish();
}

// ── X3DH (X25519) ──────────────────────────────────────────────

fn bench_x3dh(c: &mut Criterion) {
    let mut g = c.benchmark_group("x3dh");

    let ik_a = RatchetKeyPair::generate();
    let ek_a = RatchetKeyPair::generate();
    let ik_b = RatchetKeyPair::generate();
    let spk_b = RatchetKeyPair::generate();

    g.bench_function("initiator", |b| {
        b.iter(|| {
            black_box(
                X3DH::initiator(
                    black_box(&ik_a),
                    black_box(&ek_a),
                    black_box(&ik_b.public_key),
                    black_box(&spk_b.public_key),
                )
                .unwrap(),
            )
        })
    });
    g.bench_function("responder", |b| {
        b.iter(|| {
            black_box(
                X3DH::responder(
                    black_box(&ik_b),
                    black_box(&spk_b),
                    black_box(&ik_a.public_key),
                    black_box(&ek_a.public_key),
                )
                .unwrap(),
            )
        })
    });

    g.finish();
}

// ── Double Ratchet ─────────────────────────────────────────────

/// Fresh Alice session (setup cost excluded from measurement).
fn fresh_session(id: &str) -> SessionManager {
    let sm = SessionManager::new();
    sm.create_session(id, &[0x42u8; 32], true).unwrap();
    sm
}

/// Full one-message pipeline setup: Alice encrypts → Bob can decrypt.
/// Returns (bob, msg). Setup cost excluded from measurement.
fn fresh_decrypt_pair() -> (
    SessionManager,
    fibemate_lib::double_ratchet::EncryptedMessage,
) {
    let alice = fresh_session("a");
    let bob = SessionManager::new();
    bob.create_session("b", &[0x42u8; 32], false).unwrap();
    let alice_pk = alice.get_send_key("a").unwrap();
    bob.set_peer_key("b", alice_pk).unwrap();
    let msg = alice.encrypt_message("a", &vec![0xCDu8; KB]).unwrap();
    (bob, msg)
}

/// Established Alice→Bob pair: Bob has Alice's sending key so he can decrypt.
fn fresh_pair() -> (SessionManager, SessionManager) {
    let alice = fresh_session("a");
    let bob = SessionManager::new();
    bob.create_session("b", &[0x42u8; 32], false).unwrap();
    let alice_pk = alice.get_send_key("a").unwrap();
    bob.set_peer_key("b", alice_pk).unwrap();
    (alice, bob)
}

fn bench_double_ratchet(c: &mut Criterion) {
    let mut g = c.benchmark_group("double_ratchet");

    g.bench_function("create_session", |b| {
        b.iter_batched(
            SessionManager::new,
            |sm| {
                sm.create_session(black_box("s"), &[0x42u8; 32], true)
                    .unwrap()
            },
            BatchSize::SmallInput,
        )
    });

    let payload = vec![0xCDu8; KB];
    g.bench_function("encrypt_1kb", |b| {
        b.iter_batched(
            || fresh_session("a"),
            |sm| black_box(sm.encrypt_message("a", &payload).unwrap()),
            BatchSize::SmallInput,
        )
    });

    g.bench_function("decrypt_1kb", |b| {
        b.iter_batched(
            fresh_decrypt_pair,
            |(bob, msg)| black_box(bob.decrypt_message("b", &msg).unwrap()),
            BatchSize::SmallInput,
        )
    });

    g.finish();
}

// ── Double Ratchet: sustained throughput over one session ──────
//
// The *_1kb benchmarks above measure a single message in isolation, which is
// dominated by setup and hides how the ratchet behaves over a real
// conversation. These measure N sequential messages on ONE established
// session, so the reported number is the cost of N messages (divide by
// DR_MSG_COUNT for the per-message figure).
//
// This is also the only place where per-message state growth (skipped-key
// map, chain advance) shows up as a trend rather than a single point.

const DR_MSG_COUNT: usize = 100;

fn bench_dr_throughput(c: &mut Criterion) {
    let mut g = c.benchmark_group("dr_throughput");
    g.sample_size(20); // each iteration is DR_MSG_COUNT encrypt/decrypt ops

    g.bench_function("encrypt_100x1kb", |b| {
        b.iter_batched(
            || (fresh_session("a"), vec![0xCDu8; KB]),
            |(alice, payload)| {
                for _ in 0..DR_MSG_COUNT {
                    black_box(alice.encrypt_message("a", &payload).unwrap());
                }
            },
            BatchSize::SmallInput,
        )
    });

    g.bench_function("decrypt_100x1kb", |b| {
        b.iter_batched(
            || {
                let (alice, bob) = fresh_pair();
                let payload = vec![0xCDu8; KB];
                let msgs: Vec<_> = (0..DR_MSG_COUNT)
                    .map(|_| alice.encrypt_message("a", &payload).unwrap())
                    .collect();
                (bob, msgs)
            },
            |(bob, msgs)| {
                for m in &msgs {
                    black_box(bob.decrypt_message("b", m).unwrap());
                }
            },
            BatchSize::SmallInput,
        )
    });

    g.finish();
}

// ── Session persistence (encrypted sessions.json) ──────────────

const N_SESSIONS: usize = 50;
const ENC_KEY: [u8; 32] = [0x07u8; 32];

fn sessions_file() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("sessions.json");
    (dir, path)
}

fn populated_manager() -> SessionManager {
    let sm = SessionManager::new();
    for i in 0..N_SESSIONS {
        sm.create_session(&format!("session-{i}"), &[0x42u8; 32], true)
            .unwrap();
    }
    sm
}

fn bench_persistence(c: &mut Criterion) {
    let mut g = c.benchmark_group("persistence");
    g.sample_size(30); // each iteration does full serde + AES-GCM of 50 sessions

    g.bench_function("save_50_sessions_encrypted", |b| {
        b.iter_batched(
            || (sessions_file(), populated_manager()),
            |((_dir, path), sm)| {
                sm.save_to_disk_encrypted(&path, &ENC_KEY).unwrap();
            },
            BatchSize::SmallInput,
        )
    });

    // Write the file once, then measure pure load.
    let (_dir, path) = sessions_file();
    let sm = populated_manager();
    sm.save_to_disk_encrypted(&path, &ENC_KEY).unwrap();
    g.bench_function("load_50_sessions_encrypted", |b| {
        b.iter(|| black_box(load_sessions_from_disk_decrypted(&path, &ENC_KEY).unwrap()));
    });
    // keep _dir alive until here — TempDir cleanup on drop

    g.finish();
}

// ── KeyStore (DPAPI + AES-256-GCM on-disk secret storage) ──────

fn bench_keystore(c: &mut Criterion) {
    let mut g = c.benchmark_group("keystore");
    g.sample_size(30); // each iteration hits DPAPI + disk

    let dir = tempfile::TempDir::new().unwrap();
    let mut ks = KeyStore::new(dir.path()).unwrap();

    g.bench_function("store_32b_secret", |b| {
        b.iter_batched(
            || format!("bench-key-{}", rand::random::<u64>()),
            |id| {
                ks.store_secret_key(&id, &[0u8; 32], &[0x99u8; 32], "fp-bench")
                    .unwrap();
            },
            BatchSize::SmallInput,
        )
    });

    ks.store_secret_key("fixed-key", &[0u8; 32], &[0x99u8; 32], "fp-bench")
        .unwrap();
    g.bench_function("load_32b_secret", |b| {
        b.iter(|| black_box(ks.load_secret_key("fixed-key").unwrap()));
    });

    g.finish();
}

// ── SM2 (GB/T 32918, 国密) ────────────────────────────────────
//
// Functional API (fibemate_lib::sm2): generate_key_pair / sign / verify /
// encrypt / decrypt. Message digest is a BigUint computed from SM3.
// sign/verify are the slowest (~ms); sample_size(30) keeps wall time sane.

fn sm2_setup() -> (sm2::Sm2KeyPair, BigUint, Vec<u8>, String) {
    let kp = sm2::generate_key_pair();
    let msg = vec![0x5Au8; KB];
    let digest = BigUint::from_bytes_be(&fibemate_lib::sm3::sm3(&msg));
    let pk_hex = sm2::pk_to_hex(&kp.public_key);
    (kp, digest, msg, pk_hex)
}

fn bench_sm2(c: &mut Criterion) {
    let mut g = c.benchmark_group("sm2");
    g.sample_size(30);

    g.bench_function("keygen", |b| {
        b.iter(|| black_box(sm2::generate_key_pair()));
    });

    let (kp, digest, msg, pk_hex) = sm2_setup();
    g.bench_function("sign", |b| {
        b.iter(|| black_box(sm2::sign(&kp.private_key, &digest)));
    });

    let sig = sm2::sign(&kp.private_key, &digest);
    g.bench_function("verify", |b| {
        b.iter(|| {
            black_box(sm2::verify(&pk_hex, &digest, &sig.r, &sig.s).unwrap());
        });
    });

    g.bench_function("encrypt_1kb", |b| {
        b.iter(|| black_box(sm2::encrypt(&pk_hex, &msg).unwrap()));
    });

    let ct = sm2::encrypt(&pk_hex, &msg).unwrap();
    g.bench_function("decrypt_1kb", |b| {
        b.iter(|| {
            black_box(sm2::decrypt(&kp.private_key, &ct.c1, &ct.c2).unwrap());
        });
    });

    g.finish();
}

criterion_group!(
    benches,
    bench_mlkem768,
    bench_mldsa65,
    bench_x3dh,
    bench_double_ratchet,
    bench_dr_throughput,
    bench_persistence,
    bench_keystore,
    bench_sm2
);
criterion_main!(benches);
