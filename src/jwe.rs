#[cfg(all(feature = "openssl", test))]
mod tests {
    use serde::{Deserialize, Serialize};

    #[derive(Default, Debug, Serialize, Clone, Deserialize, PartialEq)]
    struct CustomExtension {
        my_exten: String,
    }

    #[test]
    fn test_encrypt_and_decrypt() {}
}
