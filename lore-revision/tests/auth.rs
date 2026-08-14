// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
mod tests {
    use std::time::Duration;
    use std::time::SystemTime;
    use std::time::UNIX_EPOCH;

    #[test]
    fn expiry_time_is_expired() {
        let current = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();

        assert!(lore_transport::auth::exchange::is_expired(
            current.as_millis() as u64
        ));
    }

    #[test]
    fn one_second_in_the_future_is_not_expired() {
        let current = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();

        assert!(!lore_transport::auth::exchange::is_expired(
            (current + Duration::from_secs(1)).as_millis() as u64
        ));
    }

    #[test]
    fn one_second_in_the_past_is_expired() {
        let current = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();

        assert!(lore_transport::auth::exchange::is_expired(
            (current - Duration::from_secs(1)).as_millis() as u64
        ));
    }

    mod verify_jwt_usage_for_remote_tests {

        use lore_credential::JWTUserInfo;
        use lore_credential::domain_in_root_domains;
        use lore_credential::verify_jwt_usage_for_remote;

        fn make_jwt_with_audience(audience: Vec<String>) -> JWTUserInfo {
            JWTUserInfo {
                issuer: "my_test_issuer.example.com".to_string(),
                user_id: "my_user_id".into(),
                name: Some("my_name".into()),
                preferred_username: None,
                is_service_account: None,
                expires: 1,
                audience,
            }
        }

        #[test]
        fn acceptable_jwt_domains() {
            let token = make_jwt_with_audience(vec![
                "lore-1.example.com".to_string(),
                "lore-2.example.com".to_string(),
            ]);
            let acceptable_domains = token.acceptable_root_domains();

            assert_eq!(
                acceptable_domains,
                vec![
                    "my_test_issuer.example.com".to_string(),
                    "lore-1.example.com".to_string(),
                    "lore-2.example.com".to_string(),
                ]
            );
        }

        #[test]
        fn errors_on_domain_not_in_audience() {
            let token = make_jwt_with_audience(vec!["real.lore.example.com".to_string()]);
            verify_jwt_usage_for_remote(&token, "attacker.lore.example.com").unwrap_err();
        }

        #[test]
        fn allows_exact_jwt_aud_use() {
            let token = make_jwt_with_audience(vec![
                "some_other_remote.example.com".to_string(),
                "lore.example.com".to_string(),
            ]);

            verify_jwt_usage_for_remote(&token, "lore.example.com").unwrap();
        }

        #[test]
        fn allows_jwt_aud_root_domain_matching_use() {
            let token = make_jwt_with_audience(vec!["lore.example.com".to_string()]);

            verify_jwt_usage_for_remote(&token, "lore-server.lore.example.com").unwrap();
        }

        #[test]
        fn leading_dot_aud_matches_subdomains_and_apex() {
            let token = make_jwt_with_audience(vec![".lore.example.com".to_string()]);

            // Subdomains ("*.lore.example.com") match.
            verify_jwt_usage_for_remote(&token, "lore-server.lore.example.com").unwrap();
            // The bare apex domain ("lore.example.com") also matches.
            verify_jwt_usage_for_remote(&token, "lore.example.com").unwrap();
        }

        #[test]
        fn leading_dot_aud_rejects_unrelated_domain() {
            let token = make_jwt_with_audience(vec![".lore.example.com".to_string()]);

            verify_jwt_usage_for_remote(&token, "attackerlore.example.com").unwrap_err();
        }

        #[test]
        fn naked_aud_rejects_mid_label_suffix_domain() {
            // A dotless `aud` must respect the label boundary.
            let token = make_jwt_with_audience(vec!["epicgames.net".to_string()]);

            // The apex and true subdomains match.
            verify_jwt_usage_for_remote(&token, "epicgames.net").unwrap();
            verify_jwt_usage_for_remote(&token, "lore.epicgames.net").unwrap();
            // The look-alike registrable domain does not.
            verify_jwt_usage_for_remote(&token, "evilepicgames.net").unwrap_err();
        }

        /// A UCS Auth token's acceptable set is `iss` followed by `aud`, and `aud` is a list
        /// of root domains -- which is the whole reason the JWT-derived derivation works for
        /// that scheme. Pinned here because the OIDC work made the stored set authoritative
        /// when an implementation supplies one, and `ucs-auth` supplies none.
        #[test]
        fn ucs_auth_derivation_is_unchanged() {
            let token = make_jwt_with_audience(vec!["lore.example.com".to_string()]);

            assert_eq!(
                token.acceptable_root_domains(),
                vec![
                    "my_test_issuer.example.com".to_string(),
                    "lore.example.com".to_string(),
                ]
            );
            verify_jwt_usage_for_remote(&token, "lore.example.com").unwrap();
            verify_jwt_usage_for_remote(&token, "my_test_issuer.example.com").unwrap();
        }

        /// The mismatch that makes the JWT-derived set unusable for `OpenID` Connect: `aud`
        /// carries a client id and `iss` a URL, and neither is a domain any remote could
        /// match, so every OIDC login would refuse its own token.
        #[test]
        fn oidc_shaped_claims_cannot_derive_their_own_recipients() {
            let mut token = make_jwt_with_audience(vec!["lore".to_string()]);
            token.issuer = "https://id.example.com".to_string();

            verify_jwt_usage_for_remote(&token, "lore.example.com").unwrap_err();
            verify_jwt_usage_for_remote(&token, "id.example.com").unwrap_err();
        }

        /// What the implementation-supplied set buys instead: an OIDC token is usable at the
        /// remote it was obtained for and at its issuer, and nowhere else. The issuer entry
        /// comes from the OIDC implementation; the remote entry is added by
        /// `login::interactive`, the only layer that knows it.
        #[test]
        fn oidc_authoritative_domains_admit_the_remote_and_the_issuer_only() {
            let domains = vec!["id.example.com".to_string(), "lore.example.com".to_string()];

            assert!(domain_in_root_domains("lore.example.com", &domains));
            assert!(domain_in_root_domains("id.example.com", &domains));
            // A subdomain of the remote is still the remote's deployment.
            assert!(domain_in_root_domains("eu.lore.example.com", &domains));
            // A server the user never logged in to gets nothing, which is the whole threat
            // the guard exists for.
            assert!(!domain_in_root_domains("attacker.example.com", &domains));
            assert!(!domain_in_root_domains("evillore.example.com", &domains));
        }
    }
}
