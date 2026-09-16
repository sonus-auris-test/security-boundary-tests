use std::{collections::BTreeMap, sync::Arc};

use ores_middleware::{
    AuthDecision, IntegrationError, RequestMetadata, StaticAuthVerifier, auth_provider_fn,
};

fn request(token: Option<&str>) -> RequestMetadata {
    let mut headers = BTreeMap::new();
    if let Some(token) = token {
        headers.insert("authorization".into(), token.into());
    }
    RequestMetadata {
        method: "POST".into(),
        path: "/v1/audio/session".into(),
        headers,
        remote_ip: Some("127.0.0.1".into()),
        content_length: Some(0),
        transport_secure: true,
    }
}

#[derive(Clone, Default)]
struct LeakySdk;

impl LeakySdk {
    async fn verify(&self, token: String) -> Result<String, String> {
        if let Some(subject) = token.strip_prefix("Bearer ok:") {
            Ok(subject.to_owned())
        } else {
            Err(format!("provider rejected raw credential: {token}"))
        }
    }
}

fn provider() -> impl StaticAuthVerifier {
    let sdk = LeakySdk;
    auth_provider_fn(move |request: RequestMetadata| {
        let sdk = sdk.clone();
        async move {
            let token = request
                .headers
                .get("authorization")
                .cloned()
                .ok_or_else(|| IntegrationError {
                    code: "missing_auth",
                    message: "authorization header is required".into(),
                })?;
            let subject = sdk.verify(token).await.map_err(|_| IntegrationError {
                code: "invalid_auth",
                message: "provider rejected credentials".into(),
            })?;
            Ok(AuthDecision {
                user_id: Some(subject),
                tenant_id: Some("audio-tenant".into()),
                claims: BTreeMap::new(),
            })
        }
    })
}

#[tokio::test]
async fn provider_specific_error_cannot_leak_raw_credential_through_static_adapter() {
    let raw_secret = "Bearer definitely-secret-token-value";
    let provider = provider();
    let error = provider
        .verify_owned(request(Some(raw_secret)))
        .await
        .unwrap_err();

    assert_eq!(error.code, "invalid_auth");
    assert_eq!(error.message, "provider rejected credentials");
    assert!(!error.message.contains("definitely-secret-token-value"));
    assert!(!error.message.contains(raw_secret));
}

#[tokio::test]
async fn missing_credentials_fail_closed_without_provider_specific_details() {
    let provider = provider();
    let error = provider.verify_owned(request(None)).await.unwrap_err();
    assert_eq!(error.code, "missing_auth");
    assert_eq!(error.message, "authorization header is required");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_accept_and_reject_paths_remain_independent_without_dyn_dispatch() {
    let provider = Arc::new(provider());
    let mut tasks = Vec::new();

    for index in 0..192_u32 {
        let provider = Arc::clone(&provider);
        tasks.push(tokio::spawn(async move {
            if index % 3 == 0 {
                let token = format!("Bearer bad-secret-{index}");
                let error = provider
                    .verify_owned(request(Some(&token)))
                    .await
                    .expect_err("invalid token must fail closed");
                assert_eq!(error.code, "invalid_auth");
                assert!(!error.message.contains(&token));
            } else {
                let subject = format!("subject-{index}");
                let token = format!("Bearer ok:{subject}");
                let decision = provider
                    .verify_owned(request(Some(&token)))
                    .await
                    .unwrap();
                assert_eq!(decision.user_id.as_deref(), Some(subject.as_str()));
                assert_eq!(decision.tenant_id.as_deref(), Some("audio-tenant"));
            }
        }));
    }

    for task in tasks {
        task.await.unwrap();
    }
}

#[test]
fn security_provider_remains_a_concrete_static_type() {
    fn assert_static<P: StaticAuthVerifier>(_provider: &P) {}
    let provider = provider();
    assert_static(&provider);
}
