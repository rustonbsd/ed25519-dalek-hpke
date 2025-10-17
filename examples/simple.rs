use ed25519_dalek::SigningKey;
use ed25519_dalek_hpke::{Ed25519hpkeEncryption, Ed25519hpkeDecryption};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a new Ed25519 keypair
    let signing_key = SigningKey::generate(&mut rand::rng());
    let verifying_key = signing_key.verifying_key();

    // Message to encrypt
    let message = b"This is a secret message!";
    println!("Original message: {}", String::from_utf8_lossy(message));

    // Encrypt the message using the verifying key (public key)
    let encrypted = verifying_key.encrypt(message)?;
    println!("Encrypted data length: {} bytes", encrypted.len());

    println!("Raw data:       \n{:?}", message);
    println!("Encrypted data: \n{:?}", encrypted);

    // Decrypt the message using the signing key (private key)
    let decrypted = signing_key.decrypt(&encrypted)?;
    println!("Decrypted message: {}", String::from_utf8_lossy(&decrypted));

    // Verify the decrypted message matches the original
    assert_eq!(message, decrypted.as_slice());
    println!("Successfully verified decrypted message matches original!");

    Ok(())
}