// SPDX-License-Identifier: AGPL-3.0-only

//! SI-H2-14 (H2 spec §7.6 "Bundle"): the hub loads a template bundle file only with a valid release signature, a
//! `bundle_version` above the embedded one and not below its persisted high-water mark (equal only with the recorded
//! SHA-256), a satisfied `min_hub_version` and every bundle rule; and it never serves a bundle below the mark.
//!
//! Every bundle here is the repository's own templates, signed at test time with a throwaway key. A "restart" is a
//! new template store over the same database and data dir.

mod common;

use common::TestApp;
use common::bundles::{Signer, audited_versions, bundle, bytes, mark, put, remove, served_version, start};
use p2pc_server::templates::{Refused, Source, Trust};
use templates_bundle::bundle::{Bundle, MAX_BUNDLE_BYTES};

/// The version of the bundle the test hub embeds, unless a test says otherwise. `TestApp` already started a hub with
/// the build's own embedded bundle, which is these same templates.
const EMBEDDED: u64 = 1;

#[tokio::test]
async fn a_new_hub_serves_its_embedded_bundle_and_records_it_as_the_mark() {
    let app = TestApp::new().await;
    let served = app.state.bundle.served().unwrap();
    assert_eq!(served.source, Source::Embedded);
    assert!(served.template("private-chat").is_some() && served.template("transcribe").is_some());
    // The mark is the embedded bundle's version and SHA-256, written when it became current, and audited once.
    let (version, sha) = mark(&app).await.unwrap();
    assert_eq!(u64::try_from(version).unwrap(), served.version());
    assert_eq!(sha, served.sha256);
    assert_eq!(audited_versions(&app).await, [version]);
    // A restart with the same bundle raises nothing and audits nothing.
    let again = start(&app, Trust::built_in()).await;
    assert_eq!(served_version(&again), Some(served.version()));
    assert_eq!(audited_versions(&app).await, [version]);
}

#[tokio::test]
async fn a_validly_signed_newer_bundle_becomes_current_and_stays_after_a_restart() {
    let app = TestApp::new().await;
    let signer = Signer::new();
    let hub = start(&app, signer.trust(EMBEDDED)).await;
    assert_eq!(served_version(&hub), Some(EMBEDDED));

    let (file, signature) = signer.sign(&bundle(3));
    put(&app, &file, Some(&signature));
    // Nothing changes until the hub reads the directory again (at start and every 60 s).
    assert_eq!(served_version(&hub), Some(EMBEDDED));
    hub.reload().await.unwrap();
    let served = hub.served().unwrap();
    assert_eq!((served.version(), served.source), (3, Source::File));
    // The mark rose in the same step, and the bundle that became current is audited with its version.
    assert_eq!(mark(&app).await.unwrap(), (3, served.sha256.clone()));
    assert_eq!(audited_versions(&app).await, [1, 3]);
    // Reading the same file again changes nothing.
    hub.reload().await.unwrap();
    assert_eq!(audited_versions(&app).await, [1, 3]);

    // After a restart the bundle at the mark, with the recorded SHA-256, loads again.
    let restarted = start(&app, signer.trust(EMBEDDED)).await;
    assert_eq!(served_version(&restarted), Some(3));
    assert_eq!(audited_versions(&app).await, [1, 3]);
}

/// Each way a bundle file fails: the hub ignores the file and keeps serving its embedded bundle, and the mark stays.
#[tokio::test]
async fn a_bundle_file_that_fails_any_check_is_ignored() {
    let app = TestApp::new().await;
    let signer = Signer::new();
    let other_key = Signer::new();
    let good = bundle(3);
    let (file, signature) = signer.sign(&good);

    let mut for_newer_hub = bundle(3);
    for_newer_hub.min_hub_version = "0.2.0".into();
    let mut unpinned = bundle(3);
    unpinned.templates[0].spec.image = "docker.io/ollama/ollama:latest".into();
    let unpinned_bytes = bytes(&unpinned);
    let not_a_bundle = br#"{"hello": "world"}"#.to_vec();
    let mut tampered = file.clone();
    let last = tampered.len() - 2;
    tampered[last] ^= 1;
    let oversized = vec![b' '; MAX_BUNDLE_BYTES + 1];

    let not_verified = |r: &Refused| matches!(r, Refused::NotVerified(_));
    // (what, the file, its signature, the trust of the hub, the refusal it must get)
    type Case<'a> = (&'a str, Vec<u8>, Option<String>, Trust, &'a dyn Fn(&Refused) -> bool);
    let cases: Vec<Case<'_>> = vec![
        ("no signature file", file.clone(), None, signer.trust(EMBEDDED), &|r| {
            *r == Refused::NoSignature
        }),
        (
            "a signature that is not one",
            file.clone(),
            Some("not a signature".into()),
            signer.trust(EMBEDDED),
            &not_verified,
        ),
        (
            "one changed byte",
            tampered,
            Some(signature.clone()),
            signer.trust(EMBEDDED),
            &not_verified,
        ),
        (
            "signed with another key",
            file.clone(),
            Some(other_key.sign(&good).1),
            signer.trust(EMBEDDED),
            &not_verified,
        ),
        (
            "a hub built without the release key",
            file.clone(),
            Some(signature.clone()),
            Trust {
                public_key: None,
                ..signer.trust(EMBEDDED)
            },
            &|r| *r == Refused::NoKey,
        ),
        (
            "a signature for another version",
            file.clone(),
            Some(signer.sign_raw(&file, 9)),
            signer.trust(EMBEDDED),
            &not_verified,
        ),
        (
            "signed bytes that are not a bundle",
            not_a_bundle.clone(),
            Some(signer.sign_raw(&not_a_bundle, 3)),
            signer.trust(EMBEDDED),
            &not_verified,
        ),
        (
            "a signed bundle that breaks a bundle rule",
            unpinned_bytes.clone(),
            Some(signer.sign_raw(&unpinned_bytes, 3)),
            signer.trust(EMBEDDED),
            &|r| matches!(r, Refused::Rules { .. }),
        ),
        (
            "a min_hub_version above the hub",
            bytes(&for_newer_hub),
            Some(signer.sign(&for_newer_hub).1),
            signer.trust(EMBEDDED),
            &|r| matches!(r, Refused::HubTooOld { .. }),
        ),
        (
            "a version equal to the embedded one",
            file.clone(),
            Some(signature.clone()),
            signer.trust(3),
            &|r| {
                *r == Refused::NotAboveEmbedded {
                    version: 3,
                    embedded: 3,
                }
            },
        ),
        (
            "a version below the embedded one",
            file.clone(),
            Some(signature.clone()),
            signer.trust(4),
            &|r| {
                *r == Refused::NotAboveEmbedded {
                    version: 3,
                    embedded: 4,
                }
            },
        ),
        (
            "a file over the size limit",
            oversized.clone(),
            Some(signer.sign_raw(&oversized, 3)),
            signer.trust(EMBEDDED),
            &|r| matches!(r, Refused::Unreadable(_)),
        ),
    ];
    for (what, file, signature, trust, expected) in cases {
        // A hub of its own per case: each has its own embedded version, so its own mark.
        let app = TestApp::new().await;
        let embedded: Bundle = serde_json::from_slice(&trust.embedded).unwrap();
        put(&app, &file, signature.as_deref());
        let hub = start(&app, trust).await;
        let refused = hub
            .file_refused()
            .await
            .unwrap_or_else(|| panic!("{what}: the file was not refused"));
        assert!(expected(&refused), "{what}: refused for another reason: {refused}");
        let served = hub.served().unwrap_or_else(|e| panic!("{what}: nothing served: {e}"));
        assert_eq!(
            (served.version(), served.source),
            (embedded.bundle_version, Source::Embedded),
            "{what}"
        );
        assert_eq!(
            mark(&app).await.unwrap().0,
            i64::try_from(embedded.bundle_version).unwrap(),
            "{what}: the mark"
        );
    }
    // The good file itself loads: the cases above fail for the reason they name.
    put(&app, &file, Some(&signature));
    assert_eq!(served_version(&start(&app, signer.trust(EMBEDDED)).await), Some(3));
}

#[tokio::test]
async fn a_validly_signed_bundle_below_the_mark_is_refused_also_after_a_restart() {
    let app = TestApp::new().await;
    let signer = Signer::new();
    let hub = start(&app, signer.trust(EMBEDDED)).await;
    let (v3, v3_signature) = signer.sign(&bundle(3));
    put(&app, &v3, Some(&v3_signature));
    hub.reload().await.unwrap();
    assert_eq!(served_version(&hub), Some(3));

    // The rollback: a stale or hostile update endpoint hands out the older bundle, validly signed and above the
    // embedded one.
    let (v2, v2_signature) = signer.sign(&bundle(2));
    put(&app, &v2, Some(&v2_signature));
    hub.reload().await.unwrap();
    // Neither the older file nor the still older embedded bundle is served.
    let why = hub.served().unwrap_err();
    assert!(why.contains("version 3"), "{why}");
    assert_eq!(mark(&app).await.unwrap().0, 3, "the mark never goes down");

    let restarted = start(&app, signer.trust(EMBEDDED)).await;
    assert!(restarted.served().is_err(), "also after a restart");
    assert_eq!(mark(&app).await.unwrap().0, 3);
    assert_eq!(
        audited_versions(&app).await,
        [1, 3],
        "a refused bundle is not audited as loaded"
    );

    // The current bundle comes back: served again.
    put(&app, &v3, Some(&v3_signature));
    restarted.reload().await.unwrap();
    assert_eq!(served_version(&restarted), Some(3));
}

#[tokio::test]
async fn a_different_bundle_with_the_marks_version_is_refused() {
    let app = TestApp::new().await;
    let signer = Signer::new();
    let (v3, v3_signature) = signer.sign(&bundle(3));
    put(&app, &v3, Some(&v3_signature));
    let hub = start(&app, signer.trust(EMBEDDED)).await;
    assert_eq!(served_version(&hub), Some(3));
    let recorded = mark(&app).await.unwrap();

    // Same version, validly signed, other content.
    let mut other = bundle(3);
    other.templates[0].info.title = "Another title".into();
    let (other_bytes, other_signature) = signer.sign(&other);
    assert_ne!(other_bytes, v3);
    put(&app, &other_bytes, Some(&other_signature));
    hub.reload().await.unwrap();
    assert!(hub.served().is_err());
    assert!(start(&app, signer.trust(EMBEDDED)).await.served().is_err());
    assert_eq!(mark(&app).await.unwrap(), recorded, "the recorded SHA-256 stays");
}

#[tokio::test]
async fn with_the_file_at_the_mark_deleted_the_hub_serves_no_template_rather_than_the_older_embedded_one() {
    let app = TestApp::new().await;
    let signer = Signer::new();
    let (v3, v3_signature) = signer.sign(&bundle(3));
    put(&app, &v3, Some(&v3_signature));
    let hub = start(&app, signer.trust(EMBEDDED)).await;
    assert_eq!(served_version(&hub), Some(3));

    remove(&app);
    hub.reload().await.unwrap();
    assert!(hub.served().is_err());
    // The catalog of the job routes and of the port filter has nothing either.
    use p2pc_server::jobs_api::TemplateCatalog;
    assert!(hub.singleton_ids().is_empty());
    assert!(hub.allowed_routes("private-chat").is_empty());
    let restarted = start(&app, signer.trust(EMBEDDED)).await;
    assert!(restarted.served().is_err());

    // A damaged file at the mark is no better than a deleted one.
    put(&app, &v3[..v3.len() - 1], Some(&v3_signature));
    restarted.reload().await.unwrap();
    assert!(restarted.served().is_err());
}

#[tokio::test]
async fn a_hub_upgrade_whose_embedded_bundle_is_above_the_mark_raises_it_at_start() {
    let app = TestApp::new().await;
    let signer = Signer::new();
    let (v3, v3_signature) = signer.sign(&bundle(3));
    put(&app, &v3, Some(&v3_signature));
    assert_eq!(served_version(&start(&app, signer.trust(EMBEDDED)).await), Some(3));

    // The upgrade: a hub that embeds bundle 5. The file (3) is no longer above the embedded bundle.
    let upgraded = start(&app, signer.trust(5)).await;
    let served = upgraded.served().unwrap();
    assert_eq!((served.version(), served.source), (5, Source::Embedded));
    assert_eq!(mark(&app).await.unwrap(), (5, served.sha256.clone()));
    assert_eq!(audited_versions(&app).await, [1, 3, 5]);

    // A downgrade of the hub itself brings nothing older back.
    let downgraded = start(&app, signer.trust(EMBEDDED)).await;
    assert!(downgraded.served().is_err());
    assert_eq!(mark(&app).await.unwrap().0, 5);
}
