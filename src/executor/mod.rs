use std::io::Write;
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time;

use crossbeam::channel::SendTimeoutError;
use crossbeam::channel::{Receiver, Sender};
use crossbeam::deque::Injector;

use crate::conn::{Conn, Pool, ProxyError};

enum Task {
    TcpStream(TcpStream),
    Shutdown,
}

pub struct Executor {
    sender: Sender<Task>,
    receiver: Receiver<Task>,
    workers: Mutex<Option<Vec<Worker>>>,
    conn_injector: Arc<Injector<Conn>>,
}

impl Executor {
    pub fn new() -> Self {
        let (sender, receiver) = crossbeam::channel::bounded(0);
        Executor {
            sender,
            receiver,
            workers: Mutex::new(Some(Vec::with_capacity(4))),
            conn_injector: Arc::new(Injector::new()),
        }
    }

    pub fn execute(&self, stream: TcpStream) {
        let mut slot = Some(stream);
        loop {
            match self.sender.send_timeout(
                Task::TcpStream(slot.take().unwrap()),
                time::Duration::from_millis(200),
            ) {
                Ok(()) => return,
                Err(SendTimeoutError::Timeout(Task::TcpStream(stream))) => {
                    slot.replace(stream);
                    self.cleanup();
                    let worker =
                        Worker::new(self.receiver.clone(), Arc::clone(&self.conn_injector));
                    let Ok(mut workers) = self.workers.lock() else {
                        unreachable!();
                    };
                    if let Some(workers) = workers.as_mut() {
                        workers.push(worker);
                    } else {
                        return;
                    }
                }
                _ => unreachable!(),
            }
        }
    }

    pub fn shutdown(&self) {
        self.cleanup();
        let Ok(mut workers) = self.workers.lock() else {
            unreachable!();
        };
        if let Some(workers) = workers.take() {
            (0..workers.len()).for_each(|_| {
                if let Err(_) = self.sender.send(Task::Shutdown) {
                    unreachable!();
                }
            });
        }
    }

    fn cleanup(&self) {
        let Ok(mut workers) = self.workers.lock() else {
            unreachable!();
        };
        if let Some(workers) = workers.as_mut() {
            workers.retain(|worker| !worker.is_dead.load(Ordering::SeqCst));
        }
    }
}

struct Worker {
    thread_join_handle: Option<JoinHandle<()>>,
    is_dead: Arc<AtomicBool>,
}

impl Worker {
    pub fn new(receiver: Receiver<Task>, conn_injector: Arc<Injector<Conn>>) -> Self {
        let is_dead = Arc::new(AtomicBool::new(false));
        let is_dead_flag = Arc::clone(&is_dead);
        let join_handle = thread::spawn(move || {
            let mut pool = Pool::new(conn_injector);
            while let Ok(Task::TcpStream(mut stream)) =
                receiver.recv_timeout(time::Duration::from_secs(30))
            {
                let Ok(mut tls_server_conn) =
                    rustls::ServerConnection::new(Arc::clone(&crate::args().tls_server_config))
                else {
                    unreachable!();
                };
                let mut tls_stream = rustls::Stream::new(&mut tls_server_conn, &mut stream);
                if let Err(ProxyError::Server(_)) = pool.proxy(&mut tls_stream) {
                    let _ = tls_stream
                        .write_all(
                            b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        );
                }
            }
            is_dead_flag.store(true, Ordering::SeqCst);
        });
        Worker {
            thread_join_handle: Some(join_handle),
            is_dead,
        }
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        if let Some(join_handle) = self.thread_join_handle.take() {
            let _ = join_handle.join();
        }
    }
}
