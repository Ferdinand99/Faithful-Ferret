//! `ferret`: the Faithful Ferret server. `ferret --help` lists the flags and
//! their `FERRET_` environment variables.

use std::io::IsTerminal as _;

use clap::Parser as _;
use ferret_server::config::Config;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    if ferret_server::build_info::requested(std::env::args_os()) {
        print!("{}", ferret_server::build_info::text());
        return;
    }
    // vole-kit needs to know which product it runs in before anything else.
    ferret_server::install();
    let config = Config::parse();

    // Colours only on a terminal: `docker logs` and log files get plain text.
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(std::io::stdout().is_terminal())
        .init();

    if let Err(err) = ferret_server::server::run(config).await {
        tracing::error!("{err}");
        std::process::exit(1);
    }
}
