use std::{env, io};
use std::io::prelude::*;
use std::net::{TcpListener, TcpStream, Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6, SocketAddr};
use std::thread;

use util::Color;

pub mod util;

// SOCKS Protocol Version 5
// https://datatracker.ietf.org/doc/html/rfc1928

fn main() {
    let args: Vec<String> = env::args().collect();
    let port = args.get(1).unwrap_or_else(|| {
        println!("usage: socks5rs [port]");
        std::process::exit(1);
    });
    let addr = format!("0.0.0.0:{}", port);
    if let Ok(listener) = TcpListener::bind(&addr) {
        println!("socks5rs is running {}", &addr);
        for stream in listener.incoming() {
            if let Ok(stream) = stream {
                thread::spawn(move || handler(stream));
            } else if let Err(e) = stream {
                println!("Failed to accept: {e}");
            }
        }
    } else {
        println!("Failed to bind {}", &addr);
    }
}


fn handshake(reader: &mut TcpStream, writer: &mut TcpStream) -> io::Result<()> {
    let mut buffer = vec![0u8; 512];

    // The client connects to the server, and sends a version
    // identifier/method selection message:
    // +-----+----------+----------+
    // | VER | NMETHODS | METHODS  |
    // +-----+----------+----------+
    // |  1  |    1     | 1 to 255 |
    // +-----+----------+----------+

    // read socks5 header
    let n = reader.read(&mut buffer)?;
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

fn parse(reader: &mut TcpStream) -> io::Result<String>{
    let mut buffer = [0u8; 1024];
    let mut dst = String::new();

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
    reader.read_exact(&mut buffer[0..4])?;
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

    Ok(dst)
}

fn copy(reader: &mut TcpStream, writer: &mut TcpStream, direction: &str) -> io::Result<()> {
    let mut buffer = vec![0; 4096];
    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            println!("{} closed", direction);
            return Ok(());
        }
        writer.write_all(&buffer[..bytes_read])?;
    }
}

fn handler(stream: TcpStream) {
    let peer_addr: SocketAddr = stream.peer_addr().unwrap();
    let mut reader = stream.try_clone().unwrap();
    let mut writer = stream;

    if handshake(&mut reader, &mut writer).is_err() {
        println!("hand shake error");
        return;
    }

    let dst = match parse(&mut reader) {
        Ok(dst) => dst,
        Err(e) => {
            println!("Failed to parse address: {}", e);
            return;
        }
    };

    let addr = dst.clone();
    if let Err(e) = TcpStream::connect(&dst).and_then(|socket| {
        // send connect success
        // +----+-----+-------+------+----------+----------+
        // |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        // +----+-----+-------+------+----------+----------+
        // | 1  |  1  | X'00' |  1   | Variable |    2     |
        // +----+-----+-------+------+----------+----------+
        let response = [0x05u8, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        writer.write_all(&response)?;

        let mut remote_reader = socket.try_clone()?;
        let mut remote_writer = socket;
        let dst2 = dst.clone();

        // Handle client traffic -> remote server
        let inbound_thread = thread::spawn(move || {
            if let Err(e) = copy(&mut reader, &mut remote_writer, "inbound") {
                util::log(Color::Magenta.as_str(), format!("inbound {} -> {}", peer_addr.to_string().as_str(), &dst).as_str(), e);
            }
        });

        // Handle remote server -> client traffic
        if let Err(e) = copy(&mut remote_reader, &mut writer, "outbound") {
            util::log(Color::Red.as_str(), format!("outbound {} <- {}", peer_addr.to_string().as_str(), &dst2).as_str(), e);
        }

        // Wait for inbound thread to finish
        let _ = inbound_thread.join().unwrap();

        Ok(())
    }) {
        util::log(Color::Green.as_str(), format!("Failed to connect {}: {}", addr, e).as_str(), e);
    }
}
