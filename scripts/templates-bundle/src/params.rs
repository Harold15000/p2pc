// SPDX-License-Identifier: Apache-2.0

//! The JobSpec of a template launch (H2 §7.6 "Launch"): the template's `spec` with each parameter's value written to
//! its one target. This is the reference for the hub's launch (T2-15): the same targets, the same type and bounds
//! checks, the same placement hint for the GPU.
//!
//! A value reaches the job in exactly one of these ways, and never inside a longer string:
//!
//! - `env:<NAME>`: the whole value of an env variable the template's `spec` already has;
//! - `argv:<index>`: one whole element of the template's `command`;
//! - `field:timeout_s` or `field:service.idle_timeout_s`: an `int` inside the template's bounds;
//! - `input:<path>`: one `inputs` entry at the template's fixed path (a `blob` digest);
//! - `pull`: the model of a chat template (an `enum` value), recorded in `template.pull`.
//!
//! Enum values are the template's own, ints are rendered as decimal digits and bools as `true`/`false`, so no value a
//! caller sends can put a shell metacharacter into the job. The result is not validated here: the caller runs the
//! normal JobSpec validation on it (`JobSpec::validate_in` with `SpecContext::Launch`), as the hub does.

use std::collections::BTreeMap;

use p2pc_proto::api::{
    BlobInput, BlobRef, GpuRequirement, JobSpec, ParamField, ParamTarget, ParamType, ParamValue, Template,
    TemplateParam, TemplateRef,
};

/// Why a launch's parameters were refused. The hub answers every one with `422 invalid_params`. Messages name the
/// template's own parameters and never repeat a value the caller sent.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParamError {
    /// A parameter the template does not have.
    #[error("unknown parameter `{name}`")]
    Unknown {
        /// The name, only when it is a short plain identifier.
        name: String,
    },
    /// A value of the wrong type.
    #[error("parameter `{name}` must be {expected}")]
    WrongType {
        /// The template's parameter.
        name: String,
        /// What it takes.
        expected: &'static str,
    },
    /// An `int` outside the template's bounds.
    #[error("parameter `{name}` is outside its bounds")]
    OutOfBounds {
        /// The template's parameter.
        name: String,
    },
    /// An `enum` value the template does not list.
    #[error("parameter `{name}` is not one of the template's values")]
    NotListed {
        /// The template's parameter.
        name: String,
    },
    /// A required parameter that was left out.
    #[error("parameter `{name}` is required")]
    Missing {
        /// The template's parameter.
        name: String,
    },
    /// The template itself cannot be launched: a bug in the template, caught by the bundle checks.
    #[error("the template is inconsistent: {0}")]
    Template(String),
}

/// A name that is safe to show: short and made of `[a-z0-9_]` only.
fn shown_name(name: &str) -> String {
    if !name.is_empty()
        && name.len() <= 32
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    {
        name.to_string()
    } else {
        "<invalid name>".to_string()
    }
}

/// A resolved value, already checked against its parameter's type and bounds.
enum Resolved {
    Text(String),
    Int(i64),
    Bool(bool),
    Blob(BlobRef),
}

impl Resolved {
    /// The whole string an env value or an argv element gets. `None` for a blob, which has no such target.
    fn word(&self) -> Option<String> {
        match self {
            Resolved::Text(s) => Some(s.clone()),
            Resolved::Int(i) => Some(i.to_string()),
            Resolved::Bool(b) => Some(b.to_string()),
            Resolved::Blob(_) => None,
        }
    }
}

fn resolve(param: &TemplateParam, given: Option<&ParamValue>) -> Result<Resolved, ParamError> {
    let name = || param.name.clone();
    let from_default = given.is_none();
    let value = given
        .or(param.default.as_ref())
        .ok_or_else(|| ParamError::Missing { name: name() })?;
    // A bad default is the template's fault, not the caller's.
    let fail = |e: ParamError| {
        if from_default {
            ParamError::Template(format!("the default of `{}` is invalid", param.name))
        } else {
            e
        }
    };
    match (&param.ty, value) {
        (ParamType::Enum { values }, ParamValue::Text(s)) => {
            if values.contains(s) {
                Ok(Resolved::Text(s.clone()))
            } else {
                Err(fail(ParamError::NotListed { name: name() }))
            }
        }
        (ParamType::Enum { .. }, _) => Err(fail(ParamError::WrongType {
            name: name(),
            expected: "a string",
        })),
        (ParamType::Int { min, max }, ParamValue::Int(i)) => {
            if (*min..=*max).contains(i) {
                Ok(Resolved::Int(*i))
            } else {
                Err(fail(ParamError::OutOfBounds { name: name() }))
            }
        }
        (ParamType::Int { .. }, _) => Err(fail(ParamError::WrongType {
            name: name(),
            expected: "an integer",
        })),
        (ParamType::Bool, ParamValue::Bool(b)) => Ok(Resolved::Bool(*b)),
        (ParamType::Bool, _) => Err(fail(ParamError::WrongType {
            name: name(),
            expected: "true or false",
        })),
        (ParamType::Blob, ParamValue::Text(s)) => {
            s.parse::<BlobRef>()
                .map(Resolved::Blob)
                .map_err(|_| ParamError::WrongType {
                    name: name(),
                    expected: "a blob digest `sha256:<64 lowercase hex>`",
                })
        }
        (ParamType::Blob, _) => Err(ParamError::WrongType {
            name: name(),
            expected: "a blob digest `sha256:<64 lowercase hex>`",
        }),
    }
}

/// Builds the JobSpec of a launch of `template` with `values` (a parameter left out takes its default).
///
/// `gpu_available` is the placement hint of §7.6: whether the account has an eligible GPU node. It decides
/// `resources.gpu` for `requirements.gpu = "preferred"`.
pub fn build_spec(
    template: &Template,
    values: &BTreeMap<String, ParamValue>,
    gpu_available: bool,
) -> Result<JobSpec, ParamError> {
    let info = &template.info;
    if let Some(unknown) = values.keys().find(|k| !info.params.iter().any(|p| &p.name == *k)) {
        return Err(ParamError::Unknown {
            name: shown_name(unknown),
        });
    }

    let mut spec = template.spec.clone();
    let mut pull = None;
    for param in &info.params {
        let resolved = resolve(param, values.get(&param.name))?;
        let broken = |what: &str| ParamError::Template(format!("`{}`: {what}", param.name));
        match &param.target {
            ParamTarget::Env(var) => {
                let word = resolved.word().ok_or_else(|| broken("a blob has no env target"))?;
                *spec
                    .env
                    .get_mut(var)
                    .ok_or_else(|| broken("its env variable is not in the spec"))? = word;
            }
            ParamTarget::Argv(index) => {
                let word = resolved.word().ok_or_else(|| broken("a blob has no argv target"))?;
                let slot = usize::try_from(*index).ok().and_then(|i| spec.command.get_mut(i));
                *slot.ok_or_else(|| broken("its argv index is outside the command"))? = word;
            }
            ParamTarget::Field(field) => {
                let Resolved::Int(i) = resolved else {
                    return Err(broken("a field target takes an int"));
                };
                let seconds = u32::try_from(i).map_err(|_| ParamError::OutOfBounds {
                    name: param.name.clone(),
                })?;
                match field {
                    ParamField::TimeoutS => spec.timeout_s = seconds,
                    ParamField::ServiceIdleTimeoutS => {
                        let service = spec
                            .service
                            .as_mut()
                            .ok_or_else(|| broken("the spec has no service block"))?;
                        service.idle_timeout_s = Some(seconds);
                    }
                }
            }
            ParamTarget::Input(path) => {
                let Resolved::Blob(blob) = resolved else {
                    return Err(broken("an input target takes a blob"));
                };
                spec.inputs.push(BlobInput {
                    path: path.clone(),
                    blob,
                });
            }
            ParamTarget::Pull => {
                let Resolved::Text(model) = resolved else {
                    return Err(broken("`pull` takes an enum"));
                };
                pull = Some(model);
            }
        }
    }

    spec.resources.gpu = match info.requirements.gpu {
        GpuRequirement::Required => 1,
        GpuRequirement::Preferred => u32::from(gpu_available),
        GpuRequirement::None => 0,
    };
    spec.template = Some(TemplateRef {
        id: info.id.clone(),
        version: info.version,
        pull,
    });
    Ok(spec)
}
