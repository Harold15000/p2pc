// SPDX-License-Identifier: Apache-2.0

//! The start-up check (spec §7, U7, AC-9): an agent must never be able to spend without a cap.

use p2pc_client::KeyLimits;
use p2pc_proto::api::Scope;

/// What the owner explicitly allowed on the command line.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Allow {
    /// `--allow-admin`: serve a key that has the `admin` scope.
    pub admin: bool,
    /// `--allow-uncapped`: serve a key that has no daily cap (or whose cap the server did not report).
    pub uncapped: bool,
}

/// The command that makes a key that passes the check.
const SAFE_KEY_COMMAND: &str = "p2pc keys create --label agent --scope jobs:write --scope jobs:read \
     --cap <UNITS> --image 'docker.io/library/*'";

/// Checks the key `p2pc mcp` was started with.
///
/// - `Ok(warnings)`: serve. There is one warning for each override that was needed.
/// - `Err(message)`: refuse, with a message that says why and how to get a key that works.
///
/// A key is refused when it has the `admin` scope, or when it has no `daily_unit_cap`. A server that does not report
/// the cap at all (it predates the cap fields) counts as "no cap": the cap is unknown, and unknown is not safe.
pub fn check_key(limits: &KeyLimits, allow: Allow) -> Result<Vec<String>, String> {
    let mut problems = Vec::new();
    let mut warnings = Vec::new();

    if limits.scopes.contains(&Scope::Admin) {
        if allow.admin {
            warnings.push(
                "--allow-admin: this key has the `admin` scope, so the agent can create and revoke keys and enroll \
                 or remove machines."
                    .to_string(),
            );
        } else {
            problems.push(
                "the API key has the `admin` scope. An agent must not hold admin power. Pass --allow-admin only if \
                 you really mean it."
                    .to_string(),
            );
        }
    }

    if limits.daily_unit_cap.is_none() {
        if allow.uncapped {
            warnings.push(if limits.cap_reported {
                "--allow-uncapped: this key has no daily unit cap, so the agent can spend without limit.".to_string()
            } else {
                "--allow-uncapped: the server did not say whether this key has a daily unit cap (it may be older \
                 than the cap fields), so the agent may be able to spend without limit."
                    .to_string()
            });
        } else if limits.cap_reported {
            problems.push(
                "the API key has no daily unit cap, so an agent could spend without limit. Pass --allow-uncapped only \
                 if you really mean it."
                    .to_string(),
            );
        } else {
            problems.push(
                "the server did not report this key's daily unit cap (it may be older than the cap fields), so the \
                 cap is unknown. Update the server, or pass --allow-uncapped if you really mean it."
                    .to_string(),
            );
        }
    }

    if problems.is_empty() {
        return Ok(warnings);
    }
    let mut message = String::from("refusing to start the MCP server:");
    for problem in &problems {
        message.push_str("\n  - ");
        message.push_str(problem);
    }
    message.push_str(&format!(
        "\nCreate a key for the agent with an admin key (`p2pc login` with it first):\n  {SAFE_KEY_COMMAND}\nthen \
         `p2pc login --profile agent` with the new key, and start `p2pc mcp --profile agent`."
    ));
    Err(message)
}

#[cfg(test)]
mod tests {
    use p2pc_proto::ids::KeyId;
    use p2pc_proto::units::Units;

    use super::*;

    fn limits(scopes: &[Scope], cap: Option<u64>, cap_reported: bool) -> KeyLimits {
        KeyLimits {
            key_id: KeyId::generate(),
            scopes: scopes.to_vec(),
            daily_unit_cap: cap.map(Units::from_units),
            cap_reported,
            allowed_images: None,
        }
    }

    const NONE: Allow = Allow {
        admin: false,
        uncapped: false,
    };

    #[test]
    fn a_capped_key_without_admin_passes_without_warnings() {
        let k = limits(&[Scope::JobsWrite, Scope::JobsRead], Some(5), true);
        assert_eq!(check_key(&k, NONE), Ok(vec![]));
    }

    #[test]
    fn an_admin_key_is_refused_even_if_it_has_a_cap() {
        let err = check_key(&limits(&[Scope::Admin], Some(5), true), NONE).unwrap_err();
        assert!(err.contains("`admin`") && err.contains("--allow-admin"), "{err}");
        assert!(err.contains("p2pc keys create --label agent"), "{err}");
        assert!(!err.contains("daily unit cap"), "only the real problem is named: {err}");
    }

    #[test]
    fn an_uncapped_key_is_refused() {
        let err = check_key(&limits(&[Scope::JobsWrite], None, true), NONE).unwrap_err();
        assert!(
            err.contains("no daily unit cap") && err.contains("--allow-uncapped"),
            "{err}"
        );
    }

    #[test]
    fn a_server_that_does_not_report_the_cap_is_refused_as_unknown() {
        let err = check_key(&limits(&[Scope::JobsWrite], None, false), NONE).unwrap_err();
        assert!(err.contains("did not report"), "{err}");
        assert!(err.contains("--allow-uncapped"), "{err}");
    }

    #[test]
    fn a_key_that_is_both_admin_and_uncapped_gets_both_reasons() {
        let err = check_key(&limits(&[Scope::Admin], None, true), NONE).unwrap_err();
        assert!(err.contains("`admin`") && err.contains("no daily unit cap"), "{err}");
    }

    #[test]
    fn each_override_flag_lifts_only_its_own_refusal_and_warns() {
        let admin_capped = limits(&[Scope::Admin], Some(5), true);
        let warnings = check_key(
            &admin_capped,
            Allow {
                admin: true,
                uncapped: false,
            },
        )
        .unwrap();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("--allow-admin"));

        let plain_uncapped = limits(&[Scope::JobsWrite], None, true);
        let warnings = check_key(
            &plain_uncapped,
            Allow {
                admin: false,
                uncapped: true,
            },
        )
        .unwrap();
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("--allow-uncapped") && warnings[0].contains("no daily unit cap"));

        // --allow-admin does not excuse a missing cap, and --allow-uncapped does not excuse admin.
        let both = limits(&[Scope::Admin], None, true);
        assert!(
            check_key(
                &both,
                Allow {
                    admin: true,
                    uncapped: false
                }
            )
            .is_err()
        );
        assert!(
            check_key(
                &both,
                Allow {
                    admin: false,
                    uncapped: true
                }
            )
            .is_err()
        );
        let warnings = check_key(
            &both,
            Allow {
                admin: true,
                uncapped: true,
            },
        )
        .unwrap();
        assert_eq!(warnings.len(), 2);
    }

    #[test]
    fn allow_uncapped_on_an_unreported_cap_warns_that_it_is_unknown() {
        let warnings = check_key(
            &limits(&[Scope::JobsWrite], None, false),
            Allow {
                admin: false,
                uncapped: true,
            },
        )
        .unwrap();
        assert!(warnings[0].contains("did not say"), "{warnings:?}");
    }

    #[test]
    fn the_overrides_are_silent_for_a_key_that_needs_none() {
        let k = limits(&[Scope::JobsWrite], Some(1), true);
        let all = Allow {
            admin: true,
            uncapped: true,
        };
        assert_eq!(check_key(&k, all), Ok(vec![]));
    }
}
