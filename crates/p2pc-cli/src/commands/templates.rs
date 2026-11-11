// SPDX-License-Identifier: Apache-2.0

//! `templates`: list the hub's templates and launch one (H2 §7.6, §7.8).

use std::collections::BTreeMap;

use p2pc_proto::api::{GpuRequirement, LaunchTemplate, ParamType, ParamValue, TemplateInfo};

use crate::app::{CliError, Ctx};
use crate::cli::{TemplateLaunchArgs, TemplatesArgs, TemplatesCommand};
use crate::output::{Table, fmt_mib, printable};

/// `p2pc templates <ls|launch>`.
pub async fn run(ctx: &mut Ctx<'_, '_>, args: TemplatesArgs) -> Result<u8, CliError> {
    match args.command {
        TemplatesCommand::Ls => list(ctx).await,
        TemplatesCommand::Launch(a) => launch(ctx, a).await,
    }
}

async fn list(ctx: &mut Ctx<'_, '_>) -> Result<u8, CliError> {
    let list = ctx.client()?.list_templates().await?;
    if ctx.json {
        // The hub's own answer: `bundle_version` and `bundle_error` matter to a script too.
        ctx.print_json(&list)?;
        return Ok(0);
    }
    if let Some(error) = &list.bundle_error {
        writeln!(ctx.host.err, "the hub cannot serve its templates: {}", printable(error))?;
    }
    if list.templates.is_empty() {
        if list.bundle_error.is_none() {
            writeln!(ctx.host.err, "No templates.")?;
        }
    } else {
        write!(ctx.host.out, "{}", template_table(&list.templates).render())?;
    }
    Ok(0)
}

fn template_table(templates: &[TemplateInfo]) -> Table {
    let mut table = Table::new(["ID", "TITLE", "KIND", "GPU", "DOWNLOAD", "SINGLETON"]);
    for t in templates {
        let gpu = match t.requirements.gpu {
            GpuRequirement::Required => "required",
            GpuRequirement::Preferred => "preferred",
            GpuRequirement::None => "no",
        };
        table.row([
            // Everything here comes from a bundle the hub loaded: shown, never obeyed.
            printable(&t.id),
            printable(&t.title),
            t.kind.to_string(),
            gpu.to_string(),
            fmt_mib(t.download_mb),
            if t.singleton { "yes" } else { "no" }.to_string(),
        ]);
    }
    table
}

/// `p2pc templates launch <id> [--param k=v]…`.
///
/// The hub checks bounds, enum values and required parameters (`422 invalid_params`); this command only gives each
/// value the type its parameter declares, so that a number reaches the hub as a number. That takes the template's
/// description, so the list is fetched first and nothing is launched for a parameter the template does not have.
async fn launch(ctx: &mut Ctx<'_, '_>, args: TemplateLaunchArgs) -> Result<u8, CliError> {
    let given = split_params(&args.params)?;
    let client = ctx.client()?;
    let list = client.list_templates().await?;
    let Some(template) = list.templates.iter().find(|t| t.id == args.id) else {
        return Err(match &list.bundle_error {
            Some(error) => CliError::usage(format!("the hub cannot serve its templates: {}", printable(error))),
            None => CliError::usage(format!(
                "no template is named {:?}; `p2pc templates ls` lists them",
                printable(&args.id)
            )),
        });
    };
    let mut launch = LaunchTemplate::default();
    for (name, text) in given {
        let Some(param) = template.params.iter().find(|p| p.name == name) else {
            let known: Vec<&str> = template.params.iter().map(|p| p.name.as_str()).collect();
            return Err(CliError::usage(format!(
                "template {} has no parameter {:?}{}",
                printable(&template.id),
                printable(&name),
                if known.is_empty() {
                    " (it takes none)".to_string()
                } else {
                    format!(" (it takes: {})", known.join(", "))
                }
            )));
        };
        launch
            .params
            .insert(name.clone(), typed(&name, &param.ty, &text).map_err(CliError::Usage)?);
    }
    let launched = client.launch_template(&template.id, &launch).await?;
    if launched.existing {
        writeln!(
            ctx.host.err,
            "{} is already running as {}: it is shared, so that is the job you get.",
            printable(&template.title),
            launched.job.id
        )?;
    } else {
        writeln!(
            ctx.host.err,
            "started {}: {}",
            printable(&template.title),
            launched.job.id
        )?;
    }
    if ctx.json {
        ctx.print_json(&launched.job)?;
    } else {
        writeln!(ctx.host.out, "{}", launched.job.id)?;
    }
    Ok(0)
}

/// `name=value` pairs, each name once.
fn split_params(args: &[String]) -> Result<BTreeMap<String, String>, CliError> {
    let mut given = BTreeMap::new();
    for arg in args {
        let Some((name, value)) = arg.split_once('=').filter(|(name, _)| !name.is_empty()) else {
            return Err(CliError::usage(format!(
                "--param {:?} is not a parameter: use --param name=value (k=v)",
                printable(arg)
            )));
        };
        if given.insert(name.to_string(), value.to_string()).is_some() {
            return Err(CliError::usage(format!("--param {} is given twice", printable(name))));
        }
    }
    Ok(given)
}

/// The value of a parameter, as the type the template declares.
fn typed(name: &str, ty: &ParamType, text: &str) -> Result<ParamValue, String> {
    let name = printable(name);
    match ty {
        ParamType::Enum { .. } => Ok(ParamValue::Text(text.to_string())),
        ParamType::Int { .. } => text
            .parse::<i64>()
            .map(ParamValue::Int)
            .map_err(|_| format!("--param {name}: {:?} is not a whole number", printable(text))),
        ParamType::Bool => match text {
            "true" => Ok(ParamValue::Bool(true)),
            "false" => Ok(ParamValue::Bool(false)),
            _ => Err(format!("--param {name}: use true or false")),
        },
        ParamType::Blob => crate::parse::parse_digest(text)
            .map(|d| ParamValue::Text(crate::commands::blobs::blob_ref(&d)))
            .map_err(|e| format!("--param {name}: {e}")),
    }
}
