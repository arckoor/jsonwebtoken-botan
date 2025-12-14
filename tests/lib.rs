use std::time::{SystemTime, UNIX_EPOCH};

use botan::{Privkey, RandomNumberGenerator};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Claims {
    sub: String,
    exp: u64,
}

#[test]
fn test_eddsa() -> Result<(), botan::Error> {
    jsonwebtoken_botan::install_default().unwrap();

    let mut rng = RandomNumberGenerator::new_system()?;
    let privkey = Privkey::create("Ed25519", "", &mut rng)?;

    let priv_pem = privkey.pem_encode()?;
    let pub_pem = privkey.pubkey()?.pem_encode()?;

    let encoding_key = EncodingKey::from_ed_pem(priv_pem.as_bytes()).unwrap();
    let decoding_key = DecodingKey::from_ed_pem(pub_pem.as_bytes()).unwrap();

    let exp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 100;

    let claims = Claims {
        sub: "me".to_string(),
        exp,
    };

    let token = encode(&Header::new(Algorithm::EdDSA), &claims, &encoding_key).unwrap();

    let decoded =
        decode::<Claims>(token, &decoding_key, &Validation::new(Algorithm::EdDSA)).unwrap();

    assert_eq!(decoded.claims.sub, "me");
    assert_eq!(decoded.claims.exp, exp);

    Ok(())
}

#[test]
#[should_panic]
fn test_no_default_provider() {
    let exp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 100;

    let claims = Claims {
        sub: "me".to_string(),
        exp,
    };

    let encoding_key = EncodingKey::from_secret(b"secret");

    let _ = encode(&Header::new(Algorithm::HS256), &claims, &encoding_key);
}
