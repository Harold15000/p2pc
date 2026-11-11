// SPDX-License-Identifier: Apache-2.0

//! `p2pc`: the P2PC command-line client. See the library for the commands.

use std::io::{self, IsTerminal, Write};
use std::process::ExitCode;

use p2pc_cli::app::{self, Host};
use p2pc_cli::outcome::EXIT_CANNOT_RUN;
use p2pc_client::RetryPolicy;
use time::OffsetDateTime;

/// Completes on SIGTERM. Never, where there is no such signal or its handler cannot be installed.
async fn terminate() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        if let Ok(mut term) = signal(SignalKind::terminate()) {
            term.recv().await;
            return;
        }
    }
    std::future::pending::<()>().await;
}

fn main() -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: could not start the async runtime: {e}");
            return ExitCode::from(EXIT_CANNOT_RUN);
        }
    };
    let args: Vec<_> = std::env::args_os().collect();
    let env = |name: &str| std::env::var(name).ok();
    let prompt = |text: &str| rpassword::prompt_password(text);
    // Not locked for the whole run: `p2pc mcp` reads and writes the process's stdin and stdout from the runtime's
    // blocking pool, and a lock held here would make that wait forever.
    let mut stdout = io::stdout();
    let mut stderr = io::stderr();
    let mut stdin = io::BufReader::new(io::stdin());
    let code = {
        let stdin_is_tty = io::stdin().is_terminal();
        let mut host = Host {
            env: &env,
            out: &mut stdout,
            err: &mut stderr,
            stdin: &mut stdin,
            stdin_is_tty,
            stdout_is_tty: io::stdout().is_terminal(),
            stderr_is_tty: io::stderr().is_terminal(),
            prompt_secret: &prompt,
            interrupt: Some(Box::pin(async {
                // If the handler cannot be installed, never fire: the default Ctrl-C then ends the process.
                if tokio::signal::ctrl_c().await.is_err() {
                    std::future::pending::<()>().await;
                }
            })),
            // Only `p2pc proxy` listens for it (a clean stop, exit 0); elsewhere SIGTERM keeps its default.
            terminate: Some(Box::pin(terminate())),
            now: OffsetDateTime::now_utc(),
            retry: RetryPolicy::default(),
            tunnel: app::TunnelSettings::default(),
            poll: p2pc_cli::follow::PollSchedule::default(),
        };
        runtime.block_on(app::run(&args, &mut host))
    };
    let _ = stdout.flush();
    let _ = stderr.flush();
    ExitCode::from(code)
}
