use std::io;
use std::thread;
use std::fmt::Display;
use std::io::prelude::*;
use std::net::TcpStream;
use std::net::TcpListener;
use std::net::{Ipv4Addr,Ipv6Addr,SocketAddrV6,SocketAddrV4,Shutdown};
use bytes::Buf;

fn log<T: Display>(color: &str, text: &str, err: T) {
    // https://gist.github.com/fnky/458719343aabd01cfb17a3a4f7296797
    println!("\x1b[0;{}m{}\x1b[0m: {}", color, text, err);
}

// https://datatracker.ietf.org/doc/html/rfc1928
// https://aber.sh/articles/Socks5/

fn main() {
    let listener = TcpListener::bind("0.0.0.0:10080").unwrap();
    for stream in listener.incoming() {
        let stream = stream.unwrap();
        thread::spawn(move || {
            handle_connection(stream);
        });
    }
}

fn handle_connection(stream: TcpStream) {
    let mut reader = stream.try_clone().unwrap();
    let mut writer = stream;

    let mut buffer = vec![0u8; 512];


    // The client connects to the server, and sends a version
    // identifier/method selection message:
    // +-----+----------+----------+
    // | VER | NMETHODS | METHODS  |
    // +-----+----------+----------+
    // |  1  |    1     | 1 to 255 |
    // +-----+----------+----------+

    // read socks5 header
    reader.read_exact(&mut buffer[0..2]).unwrap(); // read VER and NMETHODS
    if buffer[0] != 0x05 {
       // TODO tips: 
       // only socks5 protocol is supported
    }

    let methods = buffer[1] as usize;
    println!("methods {}", methods);
    reader.read_exact(&mut buffer[0..methods]).unwrap(); // read METHODS

    // TODO tips:
    // only no-auth is supported

    // server send to client accepted auth method (0x00 no-auth only yet)
    writer.write(&[0x05u8, 0x00]).unwrap();       
    writer.flush().unwrap();


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

    // read socks5 VER/CMD/RSV/ATYP
    reader.read_exact(&mut buffer[0..4]).unwrap();
    let cmd = buffer[1];
    let atyp = buffer[3];

    let mut addr_port = String::from("");
    match atyp {
        0x01 => {
            // ipv4(4bytes) + port(2bytes)
            reader.read_exact(&mut buffer[0..6]).unwrap();
            let mut tmp_array: [u8; 4] = Default::default();
            tmp_array.copy_from_slice(&buffer[0..4]);
            let ipv4 = Ipv4Addr::from(tmp_array);
            let port: u16 = buffer[4..6].as_ref().get_u16();
            let socket = SocketAddrV4::new(ipv4, port);
            addr_port = format!("{}", socket);
            println!("ipv4: {}", addr_port);
        }
        0x03 => {
            // DOMAINNAME
            reader.read_exact(&mut buffer[0..1]).unwrap();
            let len = buffer[0] as usize;
            reader.read_exact(&mut buffer[0..len + 2]).unwrap();
            let port: u16 = buffer[len..len + 2].as_ref().get_u16();
            if let Ok(addr) = std::str::from_utf8(&buffer[0..len]) {
                addr_port = format!("{}:{}", addr, port);
            }
            println!("domain: {}", addr_port);
        }
        0x04 => {
            // ipv6(16bytes) + port(2bytes)
            reader.read_exact(&mut buffer[0..18]).unwrap();
            let mut tmp_array: [u8; 16] = Default::default();
            tmp_array.copy_from_slice(&buffer[0..16]);
            let ipv6 = Ipv6Addr::from(tmp_array);
            let port = buffer[16..18].as_ref().get_u16();
            let socket = SocketAddrV6::new(ipv6, port, 0, 0);
            addr_port = format!("{}", socket);
            println!("ipv6: {}", addr_port);
        }
        _ => {
            // nothing
        }
    }
    
    match cmd {
        0x01 => {
            if let Ok(socket) = TcpStream::connect(addr_port.as_str()) {
                // send connect success
                // +----+-----+-------+------+----------+----------+
                // |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
                // +----+-----+-------+------+----------+----------+
                // | 1  |  1  | X'00' |  1   | Variable |    2     |
                // +----+-----+-------+------+----------+----------+
                writer.write(&[0x05u8, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,]).unwrap();
                let mut remote_reader = socket.try_clone().unwrap();
                let mut remote_writer = socket;
                thread::spawn(move || {
                    match io::copy(&mut reader, &mut remote_writer) {
                        Ok(len) => {
                            log("1", "local>remote", len);
                            reader.shutdown(Shutdown::Both).unwrap_or_else(|err| {
                                log("31", "reader", err);
                            });
                            remote_writer.shutdown(Shutdown::Both).unwrap_or_else(|err| {
                                log("32", "remote_writer", err);
                            });
                        },
                        Err(err) => log("7", "local>remote error", err)
                    }
                });
                match io::copy(&mut remote_reader, &mut writer) {
                    Ok(len) => {
                        log("47", "remote>local", len);
                        remote_reader.shutdown(Shutdown::Both).unwrap_or_else(|err| {
                            log("33", "remote_reader", err);
                        });
                        writer.shutdown(Shutdown::Both).unwrap_or_else(|err| {
                            log("35", "writer", err);
                        });
                    },
                    Err(err) => log("43", "remote>local error", err)
                }
            } else {
                println!("cannot connect {}", addr_port);
            }
        }
        _ => {
            println!("others cmd: {}", cmd);
        }
    }
}
