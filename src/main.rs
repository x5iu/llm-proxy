use std::error::Error;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time;

use tokio::net::TcpListener;

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
        auto_reload_config: bool,

        /// Enable provider health check
        #[arg(long = "enable-health-check")]
        enable_health_check: bool,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let llm_proxy = LLMProxy::parse();
    match llm_proxy.command {
        Some(Command::Start {
                 config,
                 auto_reload_config,
                 enable_health_check,
             }) => start(
            config,
            auto_reload_config,
            enable_health_check,
        )?,
        _ => (),
    }
    Ok(())
}

fn start(
    config: PathBuf,
    auto_reload_config: bool,
    enable_health_check: bool,
) -> Result<(), Box<dyn Error>> {
    llm_proxy::load_config(&config)?;
    let mut signals =
        SignalsInfo::<SignalOnly>::new([signal::SIGTERM, signal::SIGINT, signal::SIGHUP])?;
    let executor = Arc::new(Executor::new());
    run_background(Arc::clone(&executor), enable_health_check);
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
    log::info!(tls = true, debug = cfg!(debug_assertions); "exit_llm_proxy");
    Ok(())
}

fn run_background(executor: Arc<Executor>, enable_health_check: bool) {
    if enable_health_check {
        executor.run_health_check();
    }
    tokio::spawn(async move {
        let listener = TcpListener::bind("0.0.0.0:443").await.unwrap();
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let executor = Arc::clone(&executor);
                    tokio::spawn(async move {
                        executor.execute(stream).await;
                    });
                }
                #[cfg_attr(not(debug_assertions), allow(unused))]
                Err(e) => {
                    #[cfg(debug_assertions)]
                    log::error!(error = e.to_string(); "tcp_accept_error")
                }
            }
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
