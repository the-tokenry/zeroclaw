//! Brick fork canary tests — lock in the v0.7.4 facts the BrickChannel
//! integration depends on so a future upstream rebase that breaks any of
//! them surfaces immediately rather than silently corrupting every device's
//! first chat turn.
//!
//! Owned by the Brick fork (vendor/PATCHES.md). Upstream zeroclaw-labs has
//! no analogue; do not propose these for upstream.
//!
//! What's locked in:
//! 1. `[providers].fallback = "anthropic-custom:URL"` + matching profile
//!    block dispatches to AnthropicProvider via the factory.
//! 2. Same shape with `custom:URL` dispatches to OpenAiCompatibleProvider.
//! 3. A friendly alias key like `"brick-anthropic"` does NOT drive factory
//!    dispatch — it fails with "Unknown provider". This is the canary for
//!    `apply_named_model_provider_profile` aliasing behavior.
//! 4. With `[secrets].encrypt = false` on a `ModelProviderConfig` whose
//!    api_key holds a JWT, `encrypt_secrets` is a no-op so the rotation
//!    helper's plain-text writes survive `Config::save()` round-trips.

use tempfile::TempDir;
use zeroclaw::config::schema::ModelProviderConfig;
use zeroclaw::providers::create_provider;
use zeroclaw_config::secrets::SecretStore;

#[test]
fn fallback_anthropic_custom_url_dispatches_to_anthropic_provider() {
    // The profile-key form `anthropic-custom:URL` is the literal string
    // `[providers].fallback` carries — the factory matches on the `name`
    // arg, not on aliasing. If this test ever fails after a rebase, our
    // factory_configure_zeroclaw TOML stops constructing AnthropicProvider
    // and the device's first chat turn errors with "Unknown provider".
    let p = create_provider(
        "anthropic-custom:https://cloud.brick.app/v1/llm/anthropic",
        Some("eyJhbGciOiJIUzI1NiJ9.test.sig"),
    );
    if let Err(e) = p {
        panic!("anthropic-custom:URL must dispatch but got: {e}");
    }
}

#[test]
fn fallback_custom_url_dispatches_to_openai_compatible_provider() {
    // Same canary for the `custom:URL` arm — used by the OpenAI-native and
    // LiteLLM-passthrough profiles.
    let p = create_provider(
        "custom:https://cloud.brick.app/v1/llm/openai/v1",
        Some("eyJhbGciOiJIUzI1NiJ9.test.sig"),
    );
    if let Err(e) = p {
        panic!("custom:URL must dispatch but got: {e}");
    }

    let p2 = create_provider(
        "custom:https://cloud.brick.app/v1/llm",
        Some("eyJhbGciOiJIUzI1NiJ9.test.sig"),
    );
    if let Err(e) = p2 {
        panic!("custom:URL litellm form must dispatch but got: {e}");
    }
}

#[test]
fn brick_anthropic_friendly_alias_fails_at_factory() {
    // The plan §0.4 / §13 documents this: v0.7.4's
    // `apply_named_model_provider_profile` only mirrors the entry under
    // additional keys; it does NOT rewrite `[providers].fallback` to the
    // resolved literal URI. So a factory key like `brick-anthropic` would
    // never reach `name.starts_with("anthropic-custom:")` and falls
    // through to the "Unknown provider" arm.
    //
    // If a future upstream change adds alias-driven dispatch, this test
    // will start passing on `Ok` — that's the signal to revisit the plan
    // and let `factory_configure_zeroclaw` use friendly aliases.
    let result = create_provider("brick-anthropic", Some("eyJhbGciOiJIUzI1NiJ9.test.sig"));
    let err = match result {
        Ok(_) => panic!("brick-anthropic must NOT dispatch in v0.7.4"),
        Err(e) => e,
    };
    let msg = err.to_string();
    assert!(
        msg.contains("Unknown provider"),
        "expected 'Unknown provider' error, got: {msg}"
    );
}

#[test]
fn secrets_encrypt_false_is_no_op_for_brick_jwt_in_api_key() {
    // factory_configure_zeroclaw writes [secrets].encrypt = false on Brick
    // devices because the rotation helper writes plain JWTs and Config::save
    // would otherwise re-encrypt them via SecretStore::encrypt and corrupt
    // the next load (see schema.rs:11248-11251 `encrypt_secrets`).
    //
    // This test asserts the underlying primitive: `encrypt_secrets` against
    // a SecretStore created with `encrypt = false` leaves the api_key
    // unchanged. Mirrors the existing `encrypt_no_op_on_disabled_store`
    // test for MatrixConfig but exercises ModelProviderConfig — the type
    // that holds the LLM JWT in production.
    let dir = TempDir::new().unwrap();
    let store = SecretStore::new(dir.path(), false);

    let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJkZXZpY2U6YWJjIn0.sig";
    let mut profile = ModelProviderConfig {
        api_key: Some(jwt.to_string()),
        ..ModelProviderConfig::default()
    };

    profile.encrypt_secrets(&store).unwrap();

    let stored = profile.api_key.as_deref().expect("api_key set");
    assert_eq!(
        stored, jwt,
        "api_key must round-trip plaintext when encrypt = false"
    );
    assert!(
        !SecretStore::is_encrypted(stored),
        "api_key must not be encrypted when store has encrypt = false"
    );
}
