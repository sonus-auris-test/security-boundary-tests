use std::collections::BTreeMap;

use ores_middleware::{
    AuthDecision, IntegrationError, RequestMetadata, StaticAuthVerifier, auth_provider_fn,
};

fn request(token: &str) -> RequestMetadata {
    RequestMetadata {
        method: "POST".into(),
        path: "/v1/audio/session".into(),
        headers: BTreeMap::from([("authorization".into(), token.into())]),
        remote_ip: Some("198.51.100.8".into()),
        content_length: Some(0),
        transport_secure: true,
    }
}

#[tokio::test]
async fn rejected_credential_does_not_poison_the_reused_static_provider() {
    let provider = auth_provider_fn(|request: RequestMetadata| async move {
        let token = request
            .headers
            .get("authorization")
            .ok_or_else(|| IntegrationError {
                code: "missing_auth",
                message: "authorization header is required".into(),
            })?;
        let subject = token
            .strip_prefix("Bearer ok:")
            .ok_or_else(|| IntegrationError {
                code: "invalid_auth",
                message: "provider rejected credentials".into(),
            })?;
        Ok(AuthDecision {
            user_id: Some(subject.to_owned()),
            tenant_id: Some("audio-tenant".into()),
            claims: BTreeMap::new(),
        })
    });

    let rejected = provider
        .verify_owned(request("Bearer raw-secret-that-must-not-leak"))
        .await
        .expect_err("bad credentials must fail closed");
    assert_eq!(rejected.code, "invalid_auth");
    assert_eq!(rejected.message, "provider rejected credentials");
    assert!(!rejected.message.contains("raw-secret-that-must-not-leak"));

    let accepted = provider
        .verify_owned(request("Bearer ok:alice"))
        .await
        .expect("a previous rejection must not poison provider state");
    assert_eq!(accepted.user_id.as_deref(), Some("alice"));
    assert_eq!(accepted.tenant_id.as_deref(), Some("audio-tenant"));
}
