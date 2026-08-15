// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! Coverage of the provisioning helpers in `common/oidc.rs` themselves: a `PocketID`
//! container, driven only through its documented API, issues real signed tokens.
//!
//! Every test here requires the compose stack (`docker compose --file
//! lore-integration-tests/compose.yaml up --detach pocket-id`).
#[cfg(all(test, feature = "oidc_integration_tests"))]
mod oidc_fixture_tests {
    use crate::common::oidc::oidc_common::TEST_CLIENT_ID;
    use crate::common::oidc::oidc_common::TEST_REDIRECT_URI;
    use crate::common::oidc::oidc_common::setup;

    /// A token is minted for a user the container has never logged in.
    #[tokio::test]
    async fn pocket_id_issues_a_verifiable_token_without_a_browser() {
        let fixture = setup().await.expect("PocketID fixture setup failed");
        let user = fixture
            .create_user("loretest")
            .await
            .expect("Could not provision a test user");

        let tokens = fixture
            .issue_token(&user)
            .await
            .expect("Could not issue a token");

        // Both tokens must verify against the JWKS that discovery points at.
        for token in [&tokens.id_token, &tokens.access_token] {
            let claims = fixture
                .validate_token(token, TEST_CLIENT_ID)
                .await
                .expect("Token did not validate against the issuer's JWKS")
                .claims;

            assert_eq!(claims.iss, fixture.issuer(), "Wrong issuer");
            assert_eq!(
                claims.aud,
                vec![TEST_CLIENT_ID.to_string()],
                "Wrong audience"
            );
            assert_eq!(claims.sub, user.id, "Token is for the wrong subject");
        }

        let id_claims = fixture
            .validate_token(&tokens.id_token, TEST_CLIENT_ID)
            .await
            .expect("id_token did not validate")
            .claims;
        assert_eq!(
            id_claims.preferred_username.as_deref(),
            Some(user.username.as_str())
        );
        assert_eq!(id_claims.email.as_deref(), Some(user.email.as_str()));
        assert_eq!(id_claims.token_type.as_deref(), Some("id-token"));
        assert!(tokens.expires_in > 0, "Token expires immediately");
        assert!(id_claims.exp > 0, "id_token carries no expiry");
        // The nonce binds the token to this exchange.
        assert!(
            id_claims.nonce.is_some(),
            "id_token did not echo the request nonce"
        );

        // The refresh grant keeps a `lore` session alive past expiry.
        assert!(
            tokens.refresh_token.is_some(),
            "No refresh token issued for a public PKCE client"
        );

        // A token minted for another client must not pass as one of ours.
        let other_client = "lore-integration-tests-other";
        fixture
            .ensure_client(other_client, &[TEST_REDIRECT_URI])
            .await
            .expect("Could not create the second client");
        let other = fixture
            .issue_token_for_client(&user, other_client)
            .await
            .expect("Could not issue a token for the second client");
        assert!(
            fixture
                .validate_token(&other.id_token, TEST_CLIENT_ID)
                .await
                .is_err(),
            "A token issued for {other_client} validated as {TEST_CLIENT_ID}"
        );
    }

    /// The device authorization grant (RFC 8628), driven end to end with no browser.
    #[tokio::test]
    async fn pocket_id_device_grant_completes_without_a_browser() {
        let fixture = setup().await.expect("PocketID fixture setup failed");

        // The client keys off the advertisement rather than assuming support.
        let discovery = fixture
            .discovery()
            .await
            .expect("Could not fetch the discovery document");
        assert_eq!(
            discovery["device_authorization_endpoint"].as_str(),
            Some(format!("{}/api/oidc/device/authorize", fixture.issuer()).as_str()),
            "Discovery does not advertise a device authorization endpoint"
        );
        let grant_types = discovery["grant_types_supported"]
            .as_array()
            .expect("Discovery has no grant_types_supported");
        assert!(
            grant_types
                .iter()
                .any(|grant| grant.as_str() == Some("urn:ietf:params:oauth:grant-type:device_code")),
            "Discovery does not advertise the device_code grant: {grant_types:?}"
        );

        let user = fixture
            .create_user("loredevice")
            .await
            .expect("Could not provision a test user");

        let authorization = fixture
            .start_device_authorization()
            .await
            .expect("Could not start a device authorization");
        assert!(!authorization.user_code.is_empty(), "No user code issued");
        assert!(
            authorization.verification_uri.starts_with(fixture.issuer()),
            "Verification URI {} is not on the issuer",
            authorization.verification_uri
        );
        assert!(
            authorization.expires_in > 0,
            "Device code expires immediately"
        );
        assert!(authorization.interval > 0, "No poll interval advertised");

        fixture
            .approve_user_code(&user, &authorization.user_code)
            .await
            .expect("Could not approve the device user code");

        let tokens = fixture
            .redeem_device_code(&authorization.device_code)
            .await
            .expect("Could not redeem the device code");

        let claims = fixture
            .validate_token(&tokens.id_token, TEST_CLIENT_ID)
            .await
            .expect("Device-flow id_token did not validate against the issuer's JWKS")
            .claims;
        assert_eq!(claims.sub, user.id, "Token is for the wrong subject");
        assert_eq!(claims.iss, fixture.issuer(), "Wrong issuer");
        assert_eq!(
            claims.aud,
            vec![TEST_CLIENT_ID.to_string()],
            "Wrong audience"
        );

        // The refresh grant has to work for a device login too.
        assert!(
            tokens.refresh_token.is_some(),
            "No refresh token issued for the device grant"
        );

        // A device code is single-use: redeeming it twice must not mint a second token.
        assert!(
            fixture
                .redeem_device_code(&authorization.device_code)
                .await
                .is_err(),
            "The same device code was redeemed twice"
        );
    }
}
