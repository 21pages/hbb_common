use jni::{
    objects::{JByteArray, JObject, JValue},
    JNIEnv, JavaVM,
};
use std::convert::TryInto;

use crate::config::APP_NAME;

use super::{SecretStoreError, SecretStoreResult};

const PURPOSE_ENCRYPT: i32 = 1;
const PURPOSE_DECRYPT: i32 = 2;
const GCM_TAG_BITS: i32 = 128;

fn crypto_root_alias() -> String {
    format!("{}.crypto-root.02", APP_NAME.read().unwrap().clone())
}

pub fn encrypt_user_data(data: &[u8]) -> SecretStoreResult<Vec<u8>> {
    let ctx = ndk_context::android_context();
    let jvm = unsafe { JavaVM::from_raw(ctx.vm().cast()) }
        .map_err(|err| SecretStoreError::backend("failed to attach to Android JVM", err))?;
    let mut env = jvm
        .attach_current_thread()
        .map_err(|err| SecretStoreError::backend("failed to attach Android thread to JVM", err))?;
    let alias = crypto_root_alias();
    let key = get_or_create_secret_key_by_alias(&mut env, &alias).ok_or_else(|| {
        SecretStoreError::backend_message(
            "failed to access Android crypto root key",
            format!("missing alias {alias}"),
        )
    })?;
    encrypt(&mut env, &key, data).ok_or_else(|| {
        SecretStoreError::backend_message(
            "failed to encrypt Android user data",
            format!("alias {alias}"),
        )
    })
}

pub fn decrypt_user_data(data: &[u8]) -> SecretStoreResult<Vec<u8>> {
    let ctx = ndk_context::android_context();
    let jvm = unsafe { JavaVM::from_raw(ctx.vm().cast()) }
        .map_err(|err| SecretStoreError::backend("failed to attach to Android JVM", err))?;
    let mut env = jvm
        .attach_current_thread()
        .map_err(|err| SecretStoreError::backend("failed to attach Android thread to JVM", err))?;
    let alias = crypto_root_alias();
    let key = get_or_create_secret_key_by_alias(&mut env, &alias).ok_or_else(|| {
        SecretStoreError::backend_message(
            "failed to access Android crypto root key",
            format!("missing alias {alias}"),
        )
    })?;
    decrypt(&mut env, &key, data).ok_or_else(|| {
        SecretStoreError::backend_message(
            "failed to decrypt Android user data",
            format!("alias {alias}"),
        )
    })
}

fn get_or_create_secret_key_by_alias<'local>(
    env: &mut JNIEnv<'local>,
    alias: &str,
) -> Option<JObject<'local>> {
    let provider = env.new_string("AndroidKeyStore").ok()?;
    let keystore = env
        .call_static_method(
            "java/security/KeyStore",
            "getInstance",
            "(Ljava/lang/String;)Ljava/security/KeyStore;",
            &[JValue::Object(&JObject::from(provider))],
        )
        .ok()?
        .l()
        .ok()?;
    env.call_method(
        &keystore,
        "load",
        "(Ljava/security/KeyStore$LoadStoreParameter;)V",
        &[JValue::Object(&JObject::null())],
    )
    .ok()?;

    let alias_string = env.new_string(alias).ok()?;
    let key = env
        .call_method(
            &keystore,
            "getKey",
            "(Ljava/lang/String;[C)Ljava/security/Key;",
            &[
                JValue::Object(&JObject::from(alias_string)),
                JValue::Object(&JObject::null()),
            ],
        )
        .ok()?
        .l()
        .ok()?;
    if !key.is_null() {
        return Some(key);
    }

    let alias_string = env.new_string(alias).ok()?;
    let builder = env
        .new_object(
            "android/security/keystore/KeyGenParameterSpec$Builder",
            "(Ljava/lang/String;I)V",
            &[
                JValue::Object(&JObject::from(alias_string)),
                JValue::Int(PURPOSE_ENCRYPT | PURPOSE_DECRYPT),
            ],
        )
        .ok()?;

    let block_modes = env
        .new_object_array(1, "java/lang/String", JObject::null())
        .ok()?;
    let gcm = env.new_string("GCM").ok()?;
    env.set_object_array_element(&block_modes, 0, &JObject::from(gcm))
        .ok()?;
    env.call_method(
        &builder,
        "setBlockModes",
        "([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
        &[JValue::Object(&JObject::from(block_modes))],
    )
    .ok()?;

    let paddings = env
        .new_object_array(1, "java/lang/String", JObject::null())
        .ok()?;
    let none = env.new_string("NoPadding").ok()?;
    env.set_object_array_element(&paddings, 0, &JObject::from(none))
        .ok()?;
    env.call_method(
        &builder,
        "setEncryptionPaddings",
        "([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
        &[JValue::Object(&JObject::from(paddings))],
    )
    .ok()?;
    env.call_method(
        &builder,
        "setUserAuthenticationRequired",
        "(Z)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
        &[JValue::Bool(0)],
    )
    .ok()?;
    let spec = env
        .call_method(
            &builder,
            "build",
            "()Landroid/security/keystore/KeyGenParameterSpec;",
            &[],
        )
        .ok()?
        .l()
        .ok()?;

    let algorithm = env.new_string("AES").ok()?;
    let provider = env.new_string("AndroidKeyStore").ok()?;
    let generator = env
        .call_static_method(
            "javax/crypto/KeyGenerator",
            "getInstance",
            "(Ljava/lang/String;Ljava/lang/String;)Ljavax/crypto/KeyGenerator;",
            &[
                JValue::Object(&JObject::from(algorithm)),
                JValue::Object(&JObject::from(provider)),
            ],
        )
        .ok()?
        .l()
        .ok()?;
    env.call_method(
        &generator,
        "init",
        "(Ljava/security/spec/AlgorithmParameterSpec;)V",
        &[JValue::Object(&spec)],
    )
    .ok()?;
    env.call_method(&generator, "generateKey", "()Ljavax/crypto/SecretKey;", &[])
        .ok()?
        .l()
        .ok()
}

fn encrypt<'local>(
    env: &mut JNIEnv<'local>,
    key: &JObject<'local>,
    plaintext: &[u8],
) -> Option<Vec<u8>> {
    let transformation = env.new_string("AES/GCM/NoPadding").ok()?;
    let cipher = env
        .call_static_method(
            "javax/crypto/Cipher",
            "getInstance",
            "(Ljava/lang/String;)Ljavax/crypto/Cipher;",
            &[JValue::Object(&JObject::from(transformation))],
        )
        .ok()?
        .l()
        .ok()?;
    env.call_method(
        &cipher,
        "init",
        "(ILjava/security/Key;)V",
        &[JValue::Int(PURPOSE_ENCRYPT), JValue::Object(key)],
    )
    .ok()?;

    let iv = env
        .call_method(&cipher, "getIV", "()[B", &[])
        .ok()?
        .l()
        .ok()?;
    let iv = env.convert_byte_array(JByteArray::from(iv)).ok()?;
    let plaintext = env.byte_array_from_slice(plaintext).ok()?;
    let ciphertext = env
        .call_method(
            &cipher,
            "doFinal",
            "([B)[B",
            &[JValue::Object(&JObject::from(plaintext))],
        )
        .ok()?
        .l()
        .ok()?;
    let ciphertext = env.convert_byte_array(JByteArray::from(ciphertext)).ok()?;

    let mut payload = Vec::with_capacity(1 + iv.len() + ciphertext.len());
    payload.push(iv.len().try_into().ok()?);
    payload.extend_from_slice(&iv);
    payload.extend_from_slice(&ciphertext);
    Some(payload)
}

fn decrypt<'local>(
    env: &mut JNIEnv<'local>,
    key: &JObject<'local>,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let iv_len = *payload.first()? as usize;
    if payload.len() < 1 + iv_len {
        return None;
    }
    let iv = &payload[1..1 + iv_len];
    let ciphertext = &payload[1 + iv_len..];

    let transformation = env.new_string("AES/GCM/NoPadding").ok()?;
    let cipher = env
        .call_static_method(
            "javax/crypto/Cipher",
            "getInstance",
            "(Ljava/lang/String;)Ljavax/crypto/Cipher;",
            &[JValue::Object(&JObject::from(transformation))],
        )
        .ok()?
        .l()
        .ok()?;
    let iv = env.byte_array_from_slice(iv).ok()?;
    let spec = env
        .new_object(
            "javax/crypto/spec/GCMParameterSpec",
            "(I[B)V",
            &[
                JValue::Int(GCM_TAG_BITS),
                JValue::Object(&JObject::from(iv)),
            ],
        )
        .ok()?;
    env.call_method(
        &cipher,
        "init",
        "(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V",
        &[
            JValue::Int(PURPOSE_DECRYPT),
            JValue::Object(key),
            JValue::Object(&spec),
        ],
    )
    .ok()?;
    let ciphertext = env.byte_array_from_slice(ciphertext).ok()?;
    let plaintext = env
        .call_method(
            &cipher,
            "doFinal",
            "([B)[B",
            &[JValue::Object(&JObject::from(ciphertext))],
        )
        .ok()?
        .l()
        .ok()?;
    env.convert_byte_array(JByteArray::from(plaintext)).ok()
}
