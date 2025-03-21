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

use gpt::executor::Executor;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct GPT {
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
    },
}

fn main() -> Result<(), Box<dyn Error>> {
    let gpt = GPT::parse();
    match gpt.command {
        Some(Command::Start { config }) => start(config)?,
        _ => (),
    }
    Ok(())
}

fn start(config: PathBuf) -> Result<(), Box<dyn Error>> {
    gpt::load_config(&config)?;
    let mut signals = SignalsInfo::<SignalOnly>::new([signal::SIGTERM, signal::SIGINT])?;
    let executor = Arc::new(Executor::new());
    run_background(Arc::clone(&executor));
    watch_config(config);
    log::info!(tls = true, debug = cfg!(debug_assertions); "start_gpt_proxy");
    for signal in &mut signals {
        match signal {
            signal::SIGTERM | signal::SIGINT => break,
            _ => (),
        }
    }
    executor.shutdown();
    log::info!(tls = true, debug = cfg!(debug_assertions); "exit_gpt_proxy");
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
        if let Err(e) = gpt::update_config(&path) {
            log::error!(error = e.to_string(); "update_config_error");
        }
    });
}
