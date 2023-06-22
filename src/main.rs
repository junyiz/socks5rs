use std::fmt::Display;
use std::{env, io};
use std::io::prelude::*;
use std::net::{TcpListener, TcpStream, Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::thread;

// SOCKS Protocol Version 5
// https://datatracker.ietf.org/doc/html/rfc1928

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("usage: socks5rs [port]");
        return;
    }
    let port = &args[1];
    let addr = format!("0.0.0.0:{}", port);
    match TcpListener::bind(&addr) {
        Ok(listener) => {
            println!("socks5rs is running {}", &addr);
            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        thread::spawn(move || handler(stream));
                    }
                    Err(e) => {
                        println!("Error accepting client connection: {}", e);
                    }
                }
            }
        }
        Err(e) => {
            println!("Error bind {} {}", &addr, e);
        }
    }
}

fn log<T: Display>(color: &str, text: &str, err: T) {
    // https://gist.github.com/fnky/458719343aabd01cfb17a3a4f7296797
    println!("\x1b[0;{}m{}\x1b[0m: {}", color, text, err);
}

fn handshake(reader: &mut TcpStream, writer: &mut TcpStream) -> io::Result<()> {
    let mut buffer = vec![0u8; 258];

    // The client connects to the server, and sends a version
    // identifier/method selection message:
    // +-----+----------+----------+
    // | VER | NMETHODS | METHODS  |
    // +-----+----------+----------+
    // |  1  |    1     | 1 to 255 |
    // +-----+----------+----------+

    // read socks5 header
    match reader.read(&mut buffer) {
        Ok(n) => {
            let ver = buffer[0];
            let nmethods = buffer[1] as usize;
            let methods = &buffer[2..n];
            let length = methods.len();
            println!("n = {n}, ver = {ver}, nmethods = {nmethods}, methods length = {length}");
            if ver != 5 {
                return Err(io::Error::new(io::ErrorKind::Other, "not supported ver = {ver}"));
            }
            let response = [5, 0];
            writer.write_all(&response)
        }
        Err(e) => {
            Err(e)
        }
    }
}

fn parse(reader: &mut TcpStream) -> io::Result<String>{
    let mut buffer = [0u8; 1024];
    let mut dst = String::from("");

    // Once the method-dependent subnegotiation has completed, the client
    // sends the request details.  If the negotiated method includes
    // encapsulation for purposes of integrity checking and/or
    // confidentiality, these requests MUST be encapsulated in the method-
    // dependent encapsulation.

    // The SOCKS request is formed as follows:
    // +----+-----+-------+------+----------+----------+
    // |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    // +----+-----+-------+------+----------+----------+
    // | 1  |  1  | X'00' |  1   | Variable |    2     |
    // +----+-----+-------+------+----------+----------+

    match reader.read_exact(&mut buffer[0..4]) {
        Ok(_) => {
            let ver = buffer[0];
            let cmd = buffer[1];
            let _ = buffer[2]; // RSV
            let atyp = buffer[3];
            println!("ver = {ver}, cmd = {cmd}, atyp = {atyp}");
            match atyp {
                0x01 => {
                    // ipv4(4bytes) + port(2bytes)
                    reader.read_exact(&mut buffer[0..6]).unwrap();
                    let mut array: [u8; 4] = Default::default();
                    array.copy_from_slice(&buffer[0..4]);
                    let ipv4 = Ipv4Addr::from(array);
                    let port: u16 = ((buffer[4] as u16) << 8) | (buffer[5] as u16);
                    let socket_addr_v4 = SocketAddrV4::new(ipv4, port);
                    dst = format!("{}", socket_addr_v4);
                    println!("ipv4: {}", dst);
                }
                0x03 => {
                    // DOMAINNAME
                    reader.read_exact(&mut buffer[0..1]).unwrap();
                    let len = buffer[0] as usize;
                    reader.read_exact(&mut buffer[0..len + 2]).unwrap();
                    let port: u16 = ((buffer[len] as u16) << 8) | (buffer[len + 1] as u16);
                    if let Ok(addr) = std::str::from_utf8(&buffer[0..len]) {
                        dst = format!("{}:{}", addr, port);
                    }
                    println!("domain: {}", dst);
                }
                0x04 => {
                    // ipv6(16bytes) + port(2bytes)
                    reader.read_exact(&mut buffer[0..18]).unwrap();
                    let mut array: [u8; 16] = Default::default();
                    array.copy_from_slice(&buffer[0..16]);
                    let ipv6 = Ipv6Addr::from(array);
                    let port: u16 = ((buffer[16] as u16) << 8) | (buffer[17] as u16);
                    let socket_addr_v6 = SocketAddrV6::new(ipv6, port, 0, 0);
                    dst = format!("{}", socket_addr_v6);
                    println!("ipv6: {}", dst);
                }
                _ => {
                    // nothing
                }
            }
        }
        Err(e) => {
            println!("Failed to read Request message: {}", e);
            return Err(e);
        }    
    }

    Ok(dst)
}

fn copy(reader: &mut TcpStream, writer: &mut TcpStream) {
    let mut buf = vec![0; 1024];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => {
                writer.flush().unwrap();
                break;
            }  
            Ok(n) => {
                if let Err(e) = writer.write_all(&buf[..n]) {
                    log("32", "Failed to write", e);
                }
            }
            Err(e) => {
                log("1", "Failed to read", e);
                break;
            }
        }
    }
}

fn handler(stream: TcpStream) {
    let mut reader = stream.try_clone().unwrap();
    let mut writer = stream;

    if handshake(&mut reader, &mut writer).is_err() {
        println!("hand shake error");
        return;
    }

    match parse(&mut reader) {
        Ok(dst) => {
            match TcpStream::connect(&dst) {
                Ok(socket) => {
                    // send connect success
                    // +----+-----+-------+------+----------+----------+
                    // |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
                    // +----+-----+-------+------+----------+----------+
                    // | 1  |  1  | X'00' |  1   | Variable |    2     |
                    // +----+-----+-------+------+----------+----------+
                    let response = [0x05u8, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
                    writer.write_all(&response).unwrap();

                    let mut remote_reader = socket.try_clone().unwrap();
                    let mut remote_writer = socket;

                    // Handle client traffic -> remote server
                    thread::spawn(move || copy(&mut reader, &mut remote_writer));

                    // Handle remote server -> client traffic
                    copy(&mut remote_reader, &mut writer);
                }
                Err(e) => {
                    log("35", format!("Failed to connect {}", dst).as_str(), e);
                }
            }
        }
        Err(e) => {
            println!("Failed to parse address: {}", e);
        }
    }
}
