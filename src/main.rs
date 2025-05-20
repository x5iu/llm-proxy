use std::error::Error;
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time;

use clap::{Parser, Subcommand};

use signal_hook::consts::signal;
use signal_hook::iterator::exfiltrator::SignalOnly;
use signal_hook::iterator::SignalsInfo;

use llm_proxy::executor::Executor;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct LLMProxy {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Start the proxy server
    Start {
        /// Path to the config file
        #[arg(short, long, value_name = "FILE")]
        config: PathBuf,

        /// Auto watch and reload config file
        #[arg(long = "auto-reload-config")]
        auto_reload_config: Option<bool>,
    },
}

fn main() -> Result<(), Box<dyn Error>> {
    let llm_proxy = LLMProxy::parse();
    match llm_proxy.command {
        Some(Command::Start {
                 config,
                 auto_reload_config,
             }) => start(config, auto_reload_config.unwrap_or_default())?,
        _ => (),
    }
    Ok(())
}

fn start(config: PathBuf, auto_reload_config: bool) -> Result<(), Box<dyn Error>> {
    llm_proxy::load_config(&config)?;
    let mut signals =
        SignalsInfo::<SignalOnly>::new([signal::SIGTERM, signal::SIGINT, signal::SIGHUP])?;
    let executor = Arc::new(Executor::new());
    run_background(Arc::clone(&executor));
    if auto_reload_config {
        watch_config(config.clone());
    }
    log::info!(tls = true, debug = cfg!(debug_assertions); "start_llm_proxy");
    for signal in &mut signals {
        match signal {
            signal::SIGTERM | signal::SIGINT => break,
            signal::SIGHUP => llm_proxy::force_update_config(&config)?,
            _ => (),
        }
    }
    executor.shutdown();
    log::info!(tls = true, debug = cfg!(debug_assertions); "exit_llm_proxy");
    Ok(())
}

fn run_background(executor: Arc<Executor>) {
    thread::spawn(move || {
        let listener = TcpListener::bind("0.0.0.0:443").unwrap();
        for incoming in listener.incoming() {
            let stream = incoming.unwrap();
            executor.execute(stream);
        }
    });
}

fn watch_config(path: PathBuf) {
    thread::spawn(move || loop {
        thread::sleep(time::Duration::from_secs(5));
        if let Err(e) = llm_proxy::update_config(&path) {
            log::error!(error = e.to_string(); "update_config_error");
        }
    });
}
