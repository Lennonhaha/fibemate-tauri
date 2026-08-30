// 临时：用后端 sign_with_za 生成签名向量，供前端 SM2Browser.verify 反向验证
use num_bigint::BigUint;
use num_traits::Num;

fn main() {
    let d = BigUint::from_str_radix(
        "be3dd1fa0d046cc5936737ea5ca22188ef8e76ef53b93187b604408af36920e1",
        16,
    )
    .unwrap();
    let pk = fibemate_lib::sm2::public_key_from_private(&d);
    let pk_hex = fibemate_lib::sm2::pk_to_hex(&pk);

    let msg = b"FIBEMATE-REVERSE-ZA-TEST";
    let sig = fibemate_lib::sm2::sign_with_za(&d, &pk_hex, "1234567812345678", msg).unwrap();

    println!("PUBKEY={}", pk_hex);
    println!("MSG={}", String::from_utf8_lossy(msg));
    println!("SIG={}{}", sig.r, sig.s);
}
