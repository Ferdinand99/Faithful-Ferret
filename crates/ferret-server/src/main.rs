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
    // `ferret restore-epoch bump` and the like: not the server.
    if let Some(parsed) = ferret_server::cli::parse(std::env::args_os()) {
        let command = parsed.unwrap_or_else(|err| err.exit());
        match ferret_server::cli::run(command) {
            Ok(line) => println!("{line}"),
            Err(err) => {
                eprintln!("{err}");
                std::process::exit(1);
            }
        }
        return;
    }
    let config = Config::parse();

    // Colours only on a terminal: `docker logs` and log files get plain text.
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(std::io::stdout().is_terminal())
        .init();

    // A restore that did not finish leaves a directory that must not be served.
    // Refused here, before the server takes the lock of the directory or makes
    // anything in it.
    if let Err(err) = ferret_server::backup::restore::refuse_if_in_progress(&config.data_dir) {
        tracing::error!("{err}");
        std::process::exit(1);
    }

    if let Err(err) = ferret_server::server::run(config).await {
        tracing::error!("{err}");
        std::process::exit(1);
    }
}
