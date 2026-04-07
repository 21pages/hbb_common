use super::SecretStoreResult;

pub fn encrypt_user_data(data: &[u8]) -> SecretStoreResult<Vec<u8>> {
    crate::platform::apple::encrypt_user_data(data)
}

pub fn decrypt_user_data(data: &[u8]) -> SecretStoreResult<Vec<u8>> {
    crate::platform::apple::decrypt_user_data(data)
}
