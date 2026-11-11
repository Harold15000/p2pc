// SPDX-License-Identifier: Apache-2.0

//! `login`, `logout` and `whoami`.

use p2pc_proto::api::WhoAmI;
use p2pc_proto::auth::ApiKey;

use crate::app::{CliError, Ctx};
use crate::cli::LoginArgs;
use crate::config::{ConfigError, Credentials, ProfileCredentials, Server, Store, resolve_profile, resolve_server};
use crate::output::{fmt_time, render_kv, wire_name};

/// `p2pc login`: checks the key with `GET /v1/whoami`, stores it, and prints who it is.
///
/// The server may be a URL or a server address `p2pc_srv_…`, which is reached through the tunnel. With
/// `--via-tunnel` the server is a URL: the key is checked there, the server's address is read from `GET /v1/server`,
/// the key is checked again through the tunnel, and the address is what the profile stores.
pub async fn login(ctx: &mut Ctx<'_, '_>, args: LoginArgs) -> Result<u8, CliError> {
    let store = ctx.store()?;
    let mut config = store.load_config()?;
    let profile = resolve_profile(&ctx.flags, ctx.host.env, &config);
    let server = resolve_server(&ctx.flags, ctx.host.env, &config, &profile)?
        .ok_or_else(|| CliError::usage("no server: pass --server URL (or set P2PC_SERVER)"))?;
    // Before the key is read and before any request (spec §7: check the flags first).
    if args.via_tunnel && !matches!(Server::parse(&server)?, Server::Url(_)) {
        return Err(CliError::usage(
            "--via-tunnel needs the server's URL in --server; a server address already goes through the tunnel",
        ));
    }

    let text = if args.key_stdin {
        let mut line = String::new();
        ctx.host.stdin.read_line(&mut line)?;
        line
    } else if ctx.host.stdin_is_tty {
        (ctx.host.prompt_secret)("API key (input is hidden): ")?
    } else {
        return Err(CliError::usage(
            "there is no terminal to ask for the key: pipe it in with --key-stdin",
        ));
    };
    // The message never repeats the input: it may be a key with a typo.
    let key = ApiKey::parse(text.trim())
        .map_err(|_| CliError::usage("that is not a valid API key (expected p2pc_sk_<id>_<secret>)"))?;

    let client = ctx.client_for(&server, key.clone())?;
    let mut who = client.whoami().await?;
    let mut server = server;
    if args.via_tunnel {
        let address = client.server_info().await?.address;
        let text = address
            .encode()
            .map_err(|_| CliError::usage("the server returned an address that is not valid"))?;
        writeln!(
            ctx.host.err,
            "The server's address is {text}; checking the key through the tunnel."
        )?;
        who = ctx.client_for(&text, key.clone())?.whoami().await?;
        server = text;
    }

    let mut credentials = load_credentials_for_login(ctx, &store)?;
    credentials
        .profiles
        .insert(profile.clone(), ProfileCredentials { api_key: key });
    store.save_credentials(&credentials)?;
    config.profiles.entry(profile.clone()).or_default().server = Some(server.clone());
    store.save_config(&config)?;

    if ctx.json {
        ctx.print_json(&who)?;
    } else {
        writeln!(ctx.host.err, "Logged in to {server} (profile {profile:?}).")?;
        print_who(ctx, &who)?;
    }
    Ok(0)
}

/// The credentials `login` adds the key to. A file that other users can read is not read at all: it is replaced, with
/// a warning, by a private file that holds only the new key (`docs/cli.md`).
fn load_credentials_for_login(ctx: &mut Ctx<'_, '_>, store: &Store) -> Result<Credentials, CliError> {
    match store.load_credentials() {
        Ok(credentials) => Ok(credentials),
        Err(ConfigError::InsecurePermissions { path, mode }) => {
            writeln!(
                ctx.host.err,
                "warning: {path} was readable by other users (mode {mode:04o}). It is replaced by a private file \
                 (mode 0600) that holds only this profile's key; log in again for any other profile it held. Treat \
                 the keys it held as exposed: revoke them with `p2pc keys revoke`."
            )?;
            Ok(Credentials::default())
        }
        Err(e) => Err(e.into()),
    }
}

/// `p2pc logout`: removes the profile's key from `credentials.toml`.
pub fn logout(ctx: &mut Ctx<'_, '_>) -> Result<u8, CliError> {
    let store = ctx.store()?;
    let config = store.load_config()?;
    let profile = resolve_profile(&ctx.flags, ctx.host.env, &config);
    let mut credentials = store.load_credentials()?;
    if credentials.profiles.remove(&profile).is_some() {
        store.save_credentials(&credentials)?;
        writeln!(ctx.host.err, "Logged out: the key of profile {profile:?} was removed.")?;
    } else {
        writeln!(ctx.host.err, "Profile {profile:?} has no stored key.")?;
    }
    if (ctx.host.env)("P2PC_API_KEY").is_some_and(|v| !v.is_empty()) {
        writeln!(
            ctx.host.err,
            "note: P2PC_API_KEY is set in your environment and still works; unset it too."
        )?;
    }
    Ok(0)
}

/// `p2pc whoami`.
pub async fn whoami(ctx: &mut Ctx<'_, '_>) -> Result<u8, CliError> {
    let who = ctx.client()?.whoami().await?;
    if ctx.json {
        ctx.print_json(&who)?;
    } else {
        print_who(ctx, &who)?;
    }
    Ok(0)
}

fn print_who(ctx: &mut Ctx<'_, '_>, who: &WhoAmI) -> Result<(), CliError> {
    let scopes: Vec<String> = who.scopes.iter().map(wire_name).collect();
    let mut rows = vec![
        ("account", who.account_id.to_string()),
        ("project", who.project_id.to_string()),
    ];
    // An API key always has a key ID, shown as in H1. A device principal has none (H2 §5.5): it is named instead.
    match (who.key_id, who.principal) {
        (Some(key), _) => rows.push(("key", key.to_string())),
        (None, Some(principal)) => rows.push(("principal", principal.to_string())),
        (None, None) => {}
    }
    if let Some(label) = &who.label {
        rows.push(("label", label.clone()));
    }
    rows.push(("scopes", scopes.join(", ")));
    // The key's own limits (§7), in the words `p2pc keys list` uses: no cap, any image, never expires.
    rows.push((
        "daily cap",
        who.daily_unit_cap
            .map_or_else(|| "none".to_string(), |cap| format!("{cap} units")),
    ));
    rows.push((
        "images",
        who.allowed_images
            .as_ref()
            .map_or_else(|| "any".to_string(), |images| images.join(", ")),
    ));
    rows.push(("expires", who.expires_at.map_or_else(|| "never".to_string(), fmt_time)));
    let text = render_kv(&rows);
    write!(ctx.host.out, "{text}")?;
    Ok(())
}
