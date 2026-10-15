//! Opening a database with a key the KDF has already transformed

#[allow(clippy::expect_used, clippy::unwrap_used)]
mod transformed_key_tests {
    use keepass::{
        db::{Database, DatabaseOpenError},
        error::DatabaseKeyError,
        DatabaseKey,
    };
    use sha2::{Digest, Sha256};
    use std::convert::TryInto;

    /// The transformed keys of the test databases, as `Database::parse` derives them.
    const KNOWN: [(&str, &str, &str); 4] = [
        (
            "test_db_kdbx4_with_password_argon2.kdbx",
            "demopass",
            "37ebda1bfaebf830c55bfd43133413b670ac0647842c10d226c8af6afc94040c",
        ),
        (
            "test_db_kdbx4_with_password_aes.kdbx",
            "demopass",
            "326a494a5132bdfb8c305184fea5c680ff3f2e5da37df48f7e9df9a4ddfa2610",
        ),
        (
            "test_db_with_password.kdbx",
            "demopass",
            "f5ab076484cdfe7f4e4f13f0807627bce93a2582a722a3c2fec50cd3da8ea369",
        ),
        (
            "test_db_kdb_with_password.kdb",
            "foobar",
            "d5d120097e5fc29a64f168d60a32af6b204e33129e411b4551788b08d34ffaad",
        ),
    ];

    fn read(file: &str) -> Vec<u8> {
        std::fs::read(format!("tests/resources/{}", file)).unwrap()
    }

    fn transformed_key(hex: &str) -> [u8; 32] {
        hex::decode(hex).unwrap().try_into().unwrap()
    }

    fn titles(db: &Database) -> Vec<Option<String>> {
        db.root()
            .entries()
            .map(|entry| entry.get_title().map(str::to_owned))
            .collect()
    }

    #[test]
    fn opens_every_format_like_the_password_does() {
        for (file, password, hex) in KNOWN {
            let data = read(file);
            let with_password = Database::parse(&data, DatabaseKey::new().with_password(password)).unwrap();
            let with_transformed_key = Database::parse_with_transformed_key(&data, &transformed_key(hex))
                .unwrap_or_else(|e| panic!("{}: {}", file, e));
            // KDB has no UUIDs, so every parse draws new ones: compare what the file says.
            assert_eq!(with_transformed_key.config, with_password.config, "{}", file);
            assert_eq!(titles(&with_transformed_key), titles(&with_password), "{}", file);
        }
    }

    #[test]
    fn another_transformed_key_is_incorrect() {
        for (file, _, hex) in KNOWN {
            let mut key = transformed_key(hex);
            key[0] ^= 1;
            let result = Database::parse_with_transformed_key(&read(file), &key);
            assert!(
                matches!(
                    result,
                    Err(DatabaseOpenError::Key(DatabaseKeyError::IncorrectKey))
                        | Err(DatabaseOpenError::Cryptography(_))
                ),
                "{}: {:?}",
                file,
                result
            );
        }
    }

    #[test]
    fn the_composite_key_hashes_the_key_elements() {
        let password = Sha256::digest(b"demopass");
        let expected: [u8; 32] = Sha256::digest(password).into();
        let composite_key = DatabaseKey::new()
            .with_password("demopass")
            .composite_key()
            .unwrap();
        assert_eq!(composite_key, expected);
    }

    #[test]
    fn an_empty_key_has_no_composite_key() {
        assert!(matches!(
            DatabaseKey::new().composite_key(),
            Err(DatabaseKeyError::EmptyKey)
        ));
    }
}
