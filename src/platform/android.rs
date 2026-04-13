use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};
use jni::{
    objects::{JByteArray, JObject, JString, JValue},
    JNIEnv, JavaVM,
};
use std::convert::TryInto;

use crate::secret_store::{SecretStoreError, SecretStoreResult};

// Android API refs for the raw constants used below:
// - Context.MODE_PRIVATE:
//   https://developer.android.com/reference/android/content/Context#MODE_PRIVATE
// - KeyProperties.PURPOSE_ENCRYPT:
//   https://developer.android.com/reference/android/security/keystore/KeyProperties#PURPOSE_ENCRYPT
// - KeyProperties.PURPOSE_DECRYPT:
//   https://developer.android.com/reference/android/security/keystore/KeyProperties#PURPOSE_DECRYPT
// - GCMParameterSpec(int, byte[]) and tag length guidance:
//   https://developer.android.com/reference/javax/crypto/spec/GCMParameterSpec#GCMParameterSpec(int,%20byte%5B%5D)
const MODE_PRIVATE: i32 = 0;
// These happen to share numeric values today, but they belong to different
// APIs and should stay distinct in the code.
const KEYSTORE_PURPOSE_ENCRYPT: i32 = 1;
const KEYSTORE_PURPOSE_DECRYPT: i32 = 2;
const CIPHER_ENCRYPT_MODE: i32 = 1;
const CIPHER_DECRYPT_MODE: i32 = 2;
const GCM_TAG_BITS: i32 = 128;

pub fn load_secret(service: &str, account: &str) -> SecretStoreResult<Vec<u8>> {
    crate::log::info!(
        "==== android load_secret start service={} account={}",
        service,
        account
    );
    let ctx = ndk_context::android_context();
    let jvm = unsafe { JavaVM::from_raw(ctx.vm().cast()) }
        .map_err(|err| SecretStoreError::backend("failed to attach to Android JVM", err))?;
    let mut env = jvm
        .attach_current_thread()
        .map_err(|err| SecretStoreError::backend("failed to attach Android thread to JVM", err))?;
    crate::log::info!("==== android thread attached to JVM");
    let context = unsafe { JObject::from_raw(ctx.context() as jni::sys::jobject) };
    let store_name = store_name(service);
    let prefs = shared_preferences(&mut env, &context, &store_name).ok_or_else(|| {
        SecretStoreError::backend_message(
            "failed to open Android SharedPreferences",
            store_name.clone(),
        )
    })?;
    crate::log::info!(
        "==== android SharedPreferences opened store_name={}",
        store_name
    );
    if !preferences_contains(&mut env, &prefs, account)? {
        crate::log::info!(
            "==== android secret not found service={} account={}",
            service,
            account
        );
        return Err(SecretStoreError::NotFound);
    }
    let encoded = preferences_get_string(&mut env, &prefs, account).ok_or_else(|| {
        SecretStoreError::backend_message(
            "failed to read Android secret payload",
            format!("missing string value for key {account}"),
        )
    })?;
    crate::log::info!("==== android got encoded secret, length={}", encoded.len());
    let payload = BASE64_STANDARD
        .decode(encoded)
        .map_err(|err| SecretStoreError::backend("failed to decode Android secret payload", err))?;
    crate::log::info!("==== android decoded payload, length={}", payload.len());
    let key = get_or_create_secret_key(&mut env, service).ok_or_else(|| {
        SecretStoreError::backend_message(
            "failed to access Android Keystore key",
            format!("missing alias {}", store_name),
        )
    })?;
    let secret = decrypt(&mut env, &key, &payload).ok_or_else(|| {
        crate::log::error!("==== android decrypt failed");
        SecretStoreError::backend_message(
            "failed to decrypt Android secret payload",
            format!("alias {}", store_name),
        )
    })?;
    crate::log::info!(
        "==== android load_secret success service={} account={} secret_len={} secret_hex={}",
        service,
        account,
        secret.len(),
        crate::platform::bytes_to_hex(&secret)
    );
    Ok(secret)
}

pub fn store_secret(service: &str, account: &str, secret: &[u8]) -> SecretStoreResult<()> {
    crate::log::info!(
        "==== android store_secret start service={} account={} secret_len={} secret_hex={}",
        service,
        account,
        secret.len(),
        crate::platform::bytes_to_hex(secret)
    );
    let ctx = ndk_context::android_context();
    let jvm = unsafe { JavaVM::from_raw(ctx.vm().cast()) }
        .map_err(|err| SecretStoreError::backend("failed to attach to Android JVM", err))?;
    let mut env = jvm
        .attach_current_thread()
        .map_err(|err| SecretStoreError::backend("failed to attach Android thread to JVM", err))?;
    crate::log::info!("==== android thread attached to JVM");
    let context = unsafe { JObject::from_raw(ctx.context() as jni::sys::jobject) };
    let store_name = store_name(service);
    let key = get_or_create_secret_key(&mut env, service).ok_or_else(|| {
        SecretStoreError::backend_message(
            "failed to access Android Keystore key",
            format!("missing alias {}", store_name),
        )
    })?;
    let encrypted = encrypt(&mut env, &key, secret).ok_or_else(|| {
        crate::log::error!("==== android encrypt failed");
        SecretStoreError::backend_message(
            "failed to encrypt Android secret payload",
            format!("alias {}", store_name),
        )
    })?;
    crate::log::info!("==== android encrypted payload, length={}", encrypted.len());
    let encoded = BASE64_STANDARD.encode(encrypted);
    crate::log::info!("==== android base64 encoded, length={}", encoded.len());
    let prefs = shared_preferences(&mut env, &context, &store_name).ok_or_else(|| {
        SecretStoreError::backend_message(
            "failed to open Android SharedPreferences",
            store_name.clone(),
        )
    })?;
    preferences_put_string(&mut env, &prefs, account, &encoded).ok_or_else(|| {
        crate::log::error!("==== android failed to persist to SharedPreferences");
        SecretStoreError::backend_message(
            "failed to persist Android secret payload",
            format!("key {account}"),
        )
    })?;
    crate::log::info!("==== android store_secret success");
    Ok(())
}

fn store_name(service: &str) -> String {
    format!("{service}.secret-store")
}

fn shared_preferences<'local>(
    env: &mut JNIEnv<'local>,
    context: &JObject<'local>,
    name: &str,
) -> Option<JObject<'local>> {
    // Android API refs:
    // - Context.getSharedPreferences(...):
    //   https://developer.android.com/reference/android/content/Context#getSharedPreferences(java.lang.String,%20int)
    // - SharedPreferences:
    //   https://developer.android.com/reference/android/content/SharedPreferences
    // - Context.MODE_PRIVATE:
    //   https://developer.android.com/reference/android/content/Context#MODE_PRIVATE
    let name = env.new_string(name).ok()?;
    env.call_method(
        context,
        "getSharedPreferences",
        "(Ljava/lang/String;I)Landroid/content/SharedPreferences;",
        &[
            JValue::Object(&JObject::from(name)),
            JValue::Int(MODE_PRIVATE),
        ],
    )
    .ok()?
    .l()
    .ok()
}

fn preferences_get_string<'local>(
    env: &mut JNIEnv<'local>,
    prefs: &JObject<'local>,
    key: &str,
) -> Option<String> {
    // Android API ref: SharedPreferences.getString(...)
    // https://developer.android.com/reference/android/content/SharedPreferences#getString(java.lang.String,%20java.lang.String)
    let key = env.new_string(key).ok()?;
    let value = env
        .call_method(
            prefs,
            "getString",
            "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
            &[
                JValue::Object(&JObject::from(key)),
                JValue::Object(&JObject::null()),
            ],
        )
        .ok()?
        .l()
        .ok()?;
    if value.is_null() {
        return None;
    }
    let value = JString::from(value);
    env.get_string(&value).ok().map(Into::into)
}

fn preferences_contains<'local>(
    env: &mut JNIEnv<'local>,
    prefs: &JObject<'local>,
    key: &str,
) -> SecretStoreResult<bool> {
    // Android API ref: SharedPreferences.contains(...)
    // https://developer.android.com/reference/android/content/SharedPreferences#contains(java.lang.String)
    let key = env.new_string(key).map_err(|err| {
        SecretStoreError::backend("failed to allocate Android preference key", err)
    })?;
    env.call_method(
        prefs,
        "contains",
        "(Ljava/lang/String;)Z",
        &[JValue::Object(&JObject::from(key))],
    )
    .map_err(|err| {
        SecretStoreError::backend("failed to query Android preference key presence", err)
    })?
    .z()
    .map_err(|err| {
        SecretStoreError::backend("failed to decode Android preference key presence", err)
    })
}

fn preferences_put_string<'local>(
    env: &mut JNIEnv<'local>,
    prefs: &JObject<'local>,
    key: &str,
    value: &str,
) -> Option<()> {
    // Android API refs:
    // - SharedPreferences.edit()
    //   https://developer.android.com/reference/android/content/SharedPreferences#edit()
    // - SharedPreferences.Editor.putString(...)
    //   https://developer.android.com/reference/android/content/SharedPreferences.Editor#putString(java.lang.String,%20java.lang.String)
    // - SharedPreferences.Editor.commit()
    //   https://developer.android.com/reference/android/content/SharedPreferences.Editor#commit()
    let editor = env
        .call_method(
            prefs,
            "edit",
            "()Landroid/content/SharedPreferences$Editor;",
            &[],
        )
        .ok()?
        .l()
        .ok()?;
    let key = env.new_string(key).ok()?;
    let value = env.new_string(value).ok()?;
    env.call_method(
        &editor,
        "putString",
        "(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;",
        &[
            JValue::Object(&JObject::from(key)),
            JValue::Object(&JObject::from(value)),
        ],
    )
    .ok()?;
    env.call_method(&editor, "commit", "()Z", &[])
        .ok()?
        .z()
        .ok()?
        .then_some(())
}

fn get_or_create_secret_key<'local>(
    env: &mut JNIEnv<'local>,
    service: &str,
) -> Option<JObject<'local>> {
    // RustDesk's Android config is app-private and disappears on uninstall, so
    // this Keystore alias only needs to remain stable for the current app
    // installation. We do not require it to survive uninstall/reinstall.
    // Android API refs:
    // - KeyStore.getInstance(...), KeyStore.load(...), KeyStore.getKey(...)
    //   https://developer.android.com/reference/java/security/KeyStore#getInstance(java.lang.String)
    //   https://developer.android.com/reference/java/security/KeyStore#load(java.security.KeyStore.LoadStoreParameter)
    //   https://developer.android.com/reference/java/security/KeyStore#getKey(java.lang.String,%20char%5B%5D)
    // - KeyGenParameterSpec.Builder and its builder methods
    //   https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#Builder(java.lang.String,%20int)
    //   https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setBlockModes(java.lang.String...)
    //   https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setEncryptionPaddings(java.lang.String...)
    //   https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setUserAuthenticationRequired(boolean)
    //   https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#build()
    // - KeyProperties constants used by the builder
    //   https://developer.android.com/reference/android/security/keystore/KeyProperties#PURPOSE_ENCRYPT
    //   https://developer.android.com/reference/android/security/keystore/KeyProperties#PURPOSE_DECRYPT
    //   https://developer.android.com/reference/android/security/keystore/KeyProperties#BLOCK_MODE_GCM
    //   https://developer.android.com/reference/android/security/keystore/KeyProperties#ENCRYPTION_PADDING_NONE
    // - KeyGenerator.getInstance(...), init(...), generateKey()
    //   https://developer.android.com/reference/javax/crypto/KeyGenerator#getInstance(java.lang.String,%20java.lang.String)
    //   https://developer.android.com/reference/javax/crypto/KeyGenerator#init(java.security.spec.AlgorithmParameterSpec)
    //   https://developer.android.com/reference/javax/crypto/KeyGenerator#generateKey()
    let alias = store_name(service);
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

    let alias_string = env.new_string(&alias).ok()?;
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
        crate::log::info!("==== android found existing Keystore key alias={}", alias);
        return Some(key);
    }

    crate::log::info!("==== android generating new Keystore key alias={}", alias);
    let alias_string = env.new_string(&alias).ok()?;
    let builder = env
        .new_object(
            "android/security/keystore/KeyGenParameterSpec$Builder",
            "(Ljava/lang/String;I)V",
            &[
                JValue::Object(&JObject::from(alias_string)),
                JValue::Int(KEYSTORE_PURPOSE_ENCRYPT | KEYSTORE_PURPOSE_DECRYPT),
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
    // Android API refs:
    // - Cipher.getInstance(...), Cipher.init(...), Cipher.getIV(), Cipher.doFinal(...)
    //   https://developer.android.com/reference/javax/crypto/Cipher#getInstance(java.lang.String)
    //   https://developer.android.com/reference/javax/crypto/Cipher#init(int,%20java.security.Key)
    //   https://developer.android.com/reference/javax/crypto/Cipher#getIV()
    //   https://developer.android.com/reference/javax/crypto/Cipher#doFinal(byte%5B%5D)
    // - KeyProperties constants behind "AES/GCM/NoPadding"
    //   https://developer.android.com/reference/android/security/keystore/KeyProperties#BLOCK_MODE_GCM
    //   https://developer.android.com/reference/android/security/keystore/KeyProperties#ENCRYPTION_PADDING_NONE
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
        &[JValue::Int(CIPHER_ENCRYPT_MODE), JValue::Object(key)],
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
    // Android API refs:
    // - Cipher.getInstance(...), Cipher.init(...), Cipher.doFinal(...)
    //   https://developer.android.com/reference/javax/crypto/Cipher#getInstance(java.lang.String)
    //   https://developer.android.com/reference/javax/crypto/Cipher#init(int,%20java.security.Key,%20java.security.spec.AlgorithmParameterSpec)
    //   https://developer.android.com/reference/javax/crypto/Cipher#doFinal(byte%5B%5D)
    // - GCMParameterSpec(...)
    //   https://developer.android.com/reference/javax/crypto/spec/GCMParameterSpec#GCMParameterSpec(int,%20byte%5B%5D)
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
            JValue::Int(CIPHER_DECRYPT_MODE),
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
