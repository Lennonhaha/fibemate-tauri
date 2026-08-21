//! 反向交叉验证辅助程序：Rust 加密 → 输出密文，供前端 SM2Browser.decrypt 验证。
//! 运行：cargo run --example sm2_reverse
use fibemate_lib::sm2;
use num_bigint::BigUint;
use num_traits::Num;

fn main() {
    // 用前端向量里的固定私钥，保证和前端公钥一致
    let d = BigUint::from_str_radix(
        "be3dd1fa0d046cc5936737ea5ca22188ef8e76ef53b93187b604408af36920e1",
        16,
    )
    .unwrap();
    let pk = sm2::public_key_from_private(&d);
    let pk_hex = sm2::pk_to_hex(&pk);

    let plaintext = "REVERSE-CROSS-CHECK";
    let ct = sm2::encrypt_standard(&pk_hex, plaintext.as_bytes()).expect("encrypt");

    let sig = sm2::sign_with_za(&d, &pk_hex, "1234567812345678", plaintext.as_bytes())
        .expect("sign");

    println!("PUBKEY={}", pk_hex);
    println!("CIPHER={}", ct.to_hex());
    println!("PLAINTEXT={}", plaintext);
    println!("SIG={}{}", sig.r, sig.s);

    // 写入文件避免终端换行截断
    std::fs::write(
        std::env::temp_dir().join("sm2_reverse_out.txt"),
        format!(
            "PUBKEY={}\nCIPHER={}\nPLAINTEXT={}\nSIG={}{}\n",
            pk_hex,
            ct.to_hex(),
            plaintext,
            sig.r,
            sig.s
        ),
    )
    .expect("write output");
}
