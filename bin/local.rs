use std::env;
use std::io;
use std::net::TcpListener;
use std::net::TcpStream;
use std::process;
use std::thread;

fn main() {
    let port = env::args().nth(1).unwrap_or_else(|| {
        println!("usage: local [port] [remote]");
        process::exit(1);
    });
    let remote = env::args().nth(2).unwrap_or_else(|| {
        println!("usage: local [port] [remote]");
        process::exit(1);
    });
    let addr = format!("0.0.0.0:{}", &port);
    if let Ok(listener) = TcpListener::bind(&addr) {
        println!("socks5 local is running {}", &addr);
        for stream in listener.incoming() {
            if let Ok(stream) = stream {
                let remote = remote.clone();
                thread::spawn(move || process(stream, &remote));
            } else if let Err(e) = stream {
                println!("Failed to accept: {e}");
            }
        }
    } else {
        println!("Failed to bind {}", &port);
    }
}

fn process(stream: TcpStream, remote: &str) {
    let mut reader = stream.try_clone().unwrap();
    let mut writer = stream;
    if let Ok(remote_stream) = TcpStream::connect(&remote) {
        println!("connect {:?}", &remote);
        let mut remote_reader = remote_stream.try_clone().unwrap();
        let mut remote_writer = remote_stream;

        thread::spawn(move || io::copy(&mut reader, &mut remote_writer).ok());
        io::copy(&mut remote_reader, &mut writer).ok();
    } else {
        println!("Failed to connect {}", remote);
    }
}
