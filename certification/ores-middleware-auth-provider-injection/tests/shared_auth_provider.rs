use std::collections::BTreeMap;

use ores_middleware::{
    RequestMetadata, SharedAuthDataPlane, SharedAuthProvider, SharedAuthProviderContext,
    SharedAuthProviderFailure, SharedAuthVerifiedPrincipal, StaticSharedAuthProviderVerifier,
    shared_auth_provider_fn,
};

fn request(token: &str) -> RequestMetadata {
    RequestMetadata {
        method: "GET".into(),
        path: "/v1/audio/session".into(),
        headers: BTreeMap::from([("authorization".into(), token.into())]),
        remote_ip: Some("127.0.0.1".into()),
        content_length: None,
        transport_secure: true,
    }
}

fn context(provider: SharedAuthProvider, issuer: &str) -> SharedAuthProviderContext {
    SharedAuthProviderContext {
        provider,
        organization: "sonus-auris-test".into(),
        issuer: issuer.into(),
        audience: "sonus-auris-api".into(),
        data_plane: SharedAuthDataPlane::CustomerAuth,
    }
}

#[derive(Clone)]
struct SupabaseSdkV1;

impl SupabaseSdkV1 {
    async fn verify(&self, bearer: String) -> Result<String, &'static str> {
        bearer
            .strip_prefix("supabase-v1:")
            .map(ToOwned::to_owned)
            .ok_or("rejected")
    }
}

#[derive(Clone)]
struct NeonSdkV2;

impl NeonSdkV2 {
    async fn authenticate(&self, token: String) -> Result<(String, String), &'static str> {
        let subject = token.strip_prefix("neon-v2:").ok_or("rejected")?;
        Ok((subject.to_owned(), "audio-tenant".into()))
    }
}

#[tokio::test]
async fn incompatible_shared_auth_sdk_shapes_adapt_without_dyn_provider_dispatch() {
    let supabase = SupabaseSdkV1;
    let supabase_provider = shared_auth_provider_fn(
        move |request: RequestMetadata, context: SharedAuthProviderContext| {
            let sdk = supabase.clone();
            async move {
                let token = request
                    .headers
                    .get("authorization")
                    .cloned()
                    .ok_or_else(|| SharedAuthProviderFailure::rejected(
                        "missing_auth",
                        "authorization header is required",
                    ))?;
                let subject = sdk.verify(token).await.map_err(|_| {
                    SharedAuthProviderFailure::rejected(
                        "invalid_auth",
                        "Supabase provider rejected credentials",
                    )
                })?;
                Ok(SharedAuthVerifiedPrincipal::new(
                    context.provider,
                    subject,
                    "audio-tenant",
                    "session-supabase-v1",
                    context.issuer,
                    context.audience,
                    context.organization,
                    context.data_plane,
                ))
            }
        },
    );

    let neon = NeonSdkV2;
    let neon_provider = shared_auth_provider_fn(
        move |request: RequestMetadata, context: SharedAuthProviderContext| {
            let sdk = neon.clone();
            async move {
                let token = request
                    .headers
                    .get("authorization")
                    .cloned()
                    .ok_or_else(|| SharedAuthProviderFailure::rejected(
                        "missing_auth",
                        "authorization header is required",
                    ))?;
                let (subject, tenant) = sdk.authenticate(token).await.map_err(|_| {
                    SharedAuthProviderFailure::rejected(
                        "invalid_auth",
                        "Neon provider rejected credentials",
                    )
                })?;
                Ok(SharedAuthVerifiedPrincipal::new(
                    context.provider,
                    subject,
                    tenant,
                    "session-neon-v2",
                    context.issuer,
                    context.audience,
                    context.organization,
                    context.data_plane,
                ))
            }
        },
    );

    let supabase_principal = supabase_provider
        .verify_owned(
            request("supabase-v1:alice"),
            context(SharedAuthProvider::Supabase, "https://supabase.example.test"),
        )
        .await
        .unwrap();
    let neon_principal = neon_provider
        .verify_owned(
            request("neon-v2:alice"),
            context(SharedAuthProvider::Neon, "https://neon.example.test"),
        )
        .await
        .unwrap();

    assert_eq!(supabase_principal.subject, "alice");
    assert_eq!(supabase_principal.tenant_id, "audio-tenant");
    assert_eq!(supabase_principal.provider, SharedAuthProvider::Supabase);
    assert_eq!(neon_principal.subject, "alice");
    assert_eq!(neon_principal.tenant_id, "audio-tenant");
    assert_eq!(neon_principal.provider, SharedAuthProvider::Neon);
}

#[tokio::test]
async fn shared_auth_adapter_preserves_provider_failure_classification_without_sdk_types_in_core() {
    let provider = shared_auth_provider_fn(
        |_request: RequestMetadata, _context: SharedAuthProviderContext| async move {
            Err(SharedAuthProviderFailure::unavailable("simulated provider outage"))
        },
    );

    let error = provider
        .verify_owned(
            request("unused"),
            context(SharedAuthProvider::Neon, "https://neon.example.test"),
        )
        .await
        .unwrap_err();

    assert_eq!(error.code, "shared_auth_provider_unavailable");
}
