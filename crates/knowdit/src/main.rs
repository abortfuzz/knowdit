//! Binary entry point. The CLI tree itself (every `KnowditSubCommands`
//! variant, every per-phase `*Args` struct, every dispatcher) lives in
//! the library half of this crate so other programs can embed it; see
//! [`knowdit`].

use std::io::IsTerminal;

use clap::Parser;
use knowdit::KnowditCommand;

// Linux-only: switch the global allocator to tikv-jemalloc so the
// fuzz/regen hot path (multi-MB CallGraph clones, forge output
// buffers) doesn't accumulate fragmented RSS the way glibc malloc
// does. Other targets fall back to the system allocator.
#[cfg(target_os = "linux")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn main() {
    let use_colors = std::io::stdout().is_terminal()
        && std::io::stderr().is_terminal()
        && std::env::var("NO_COLOR") == Err(std::env::VarError::NotPresent);
    if use_colors {
        color_eyre::install().expect("init color_eyre");
    } else {
        color_eyre::config::HookBuilder::new()
            .theme(color_eyre::config::Theme::new())
            .install()
            .expect("init no color color_eyre");
    }
    let direnv_exists = std::env::var("DIRENV_DIR").is_ok();
    if !direnv_exists {
        if let Ok(dot_file) = std::env::var("DOT") {
            dotenvy::from_path_override(dot_file).expect("can not read dotenvy");
        } else {
            // Allows failure and do not override
            let _ = dotenvy::dotenv();
        }
    }
    let sub = tracing_subscriber::FmtSubscriber::builder()
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing::Level::INFO.into())
                .from_env()
                .expect("env contains non-utf8"),
        )
        .with_ansi(use_colors)
        .finish();
    tracing::subscriber::set_global_default(sub).expect("can not set default tracing");

    let cmd = KnowditCommand::parse();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("can not build tokio");

    if let Err(err) = runtime.block_on(cmd.run()) {
        eprintln!("{err:?}");
        std::process::exit(1);
    }
}
