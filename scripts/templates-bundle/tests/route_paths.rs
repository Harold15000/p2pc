// SPDX-License-Identifier: Apache-2.0

//! `route_path_problem` with the reviewed-wildcard list passed in (review finding 3).
//!
//! The beta list is empty, so through `check_template` every wildcard stops at "needs a reviewed entry" before the
//! model-write expansion is reached. These tests pass a non-empty list, so a final `*` that stands for `pull`,
//! `create`, `blobs`… is tested for what it is: refused for reaching a model-writing endpoint, with that message.

// Helpers unwrap freely: a panic is the failure message of a test.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use templates_bundle::check::{WILDCARD_ROUTES, route_path_problem};

const ID: &str = "fixture-chat";

#[test]
fn the_beta_list_of_reviewed_wildcards_is_empty() {
    assert!(
        WILDCARD_ROUTES.is_empty(),
        "§7.4: the beta templates have no wildcard route"
    );
}

#[test]
fn a_wildcard_not_on_the_list_is_refused_as_unreviewed() {
    let why = route_path_problem(ID, "/files/*", &[]).expect("refused");
    assert!(why.contains("reviewed entry"), "{why}");
    // On the list for another template, or another path of this one, does not count.
    let list = [("other", "/files/*"), (ID, "/other/*")];
    let why = route_path_problem(ID, "/files/*", &list).expect("refused");
    assert!(why.contains("reviewed entry"), "{why}");
}

#[test]
fn a_reviewed_wildcard_that_cannot_reach_a_model_write_is_accepted() {
    let list = [(ID, "/files/*"), (ID, "/v1/api/*")];
    assert_eq!(route_path_problem(ID, "/files/*", &list), None);
    assert_eq!(route_path_problem(ID, "/v1/api/*", &list), None);
}

#[test]
fn a_reviewed_wildcard_under_api_is_refused_because_it_expands_to_a_model_write() {
    for path in ["/api/*", "/API/*"] {
        let list = [(ID, path)];
        let why = route_path_problem(ID, path, &list).expect("refused");
        assert!(why.contains("model-writing endpoint"), "{path}: {why}");
    }
}

#[test]
fn a_reviewed_one_segment_wildcard_is_not_a_model_write_by_itself() {
    // `/*` stands for one segment, such as `/api`; a model write needs `/api/<word>`, so the expansion finds none.
    let list = [(ID, "/*")];
    let why = route_path_problem(ID, "/*", &list);
    assert_eq!(
        why, None,
        "`/*` stands for one segment such as `/api`, which writes nothing"
    );
}

#[test]
fn a_reviewed_wildcard_one_below_api_is_refused_for_every_model_writing_word() {
    // `/api/*` is the case that matters: each of pull, create, copy, push, delete and blobs must be caught, so the
    // expansion cannot have a hole. Check the list of words by planting an exact route for each and comparing.
    for word in ["pull", "create", "copy", "push", "delete", "blobs"] {
        let exact = format!("/api/{word}");
        let why = route_path_problem(ID, &exact, &[]).expect("an exact model-write route is refused");
        assert!(why.contains("model-writing endpoint"), "{exact}: {why}");
    }
    let list = [(ID, "/api/*")];
    let why = route_path_problem(ID, "/api/*", &list).expect("refused");
    assert!(why.contains("model-writing endpoint"), "{why}");
}

#[test]
fn a_wildcard_is_only_a_whole_final_segment() {
    let list = [(ID, "/files/a*"), (ID, "/*/files"), (ID, "/files/*/x")];
    for path in ["/files/a*", "/*/files", "/files/*/x", "/files/**"] {
        let why = route_path_problem(ID, path, &list).expect("refused");
        assert!(why.contains("whole final `*` segment"), "{path}: {why}");
    }
}

#[test]
fn exact_paths_are_unaffected_by_the_list() {
    let list = [(ID, "/files/*")];
    assert_eq!(route_path_problem(ID, "/api/chat", &list), None);
    assert_eq!(route_path_problem(ID, "/api/tags", &[]), None);
    assert!(route_path_problem(ID, "/api/pull", &list).is_some());
}
