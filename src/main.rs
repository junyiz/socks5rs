use std::env;
use std::io::prelude::*;
use std::net::TcpListener;
use std::net::TcpStream;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
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
    let mut addr = String::from("0.0.0.0:");
    addr.push_str(port);
    match TcpListener::bind(&addr) {
        Ok(listener) => {
            println!("socks5rs is running {}", &addr);
            for stream in listener.incoming() {
                let stream = stream.unwrap();
                thread::spawn(move || {
                    handle_connection(stream);
                });
            }
        }
        Err(e) => {
            println!("{}", e);
        }
    }
}

fn handshake(reader: &mut TcpStream, writer: &mut TcpStream) {
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
        panic!("only socks5 protocol is supported");
    }

    let methods = buffer[1] as usize;
    reader.read_exact(&mut buffer[0..methods]).unwrap(); // read METHODS

    // server send to client accepted auth method (0x00 no-auth only yet)
    writer.write(&[0x05u8, 0x00]).unwrap();
    writer.flush().unwrap();
}

fn parse_dst(reader: &mut TcpStream, atyp: u8) -> String {
    let mut buffer = vec![0u8; 512];
    let mut dst = String::from("");
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

    dst
}

fn handle_connection(stream: TcpStream) {
    let mut reader = stream.try_clone().unwrap();
    let mut writer = stream;
    let mut buffer = vec![0u8; 512];

    handshake(&mut reader, &mut writer);

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

    if cmd != 0x01 {
        // only support 0x01(connect)
        println!("not support cmd: {}", cmd);
        return;
    }

    let dst = parse_dst(&mut reader, atyp);

    match TcpStream::connect(dst.as_str()) {
        Ok(socket) => {
            // send connect success
            // +----+-----+-------+------+----------+----------+
            // |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
            // +----+-----+-------+------+----------+----------+
            // | 1  |  1  | X'00' |  1   | Variable |    2     |
            // +----+-----+-------+------+----------+----------+
            writer
                .write(&[0x05u8, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
                .unwrap();
            let mut remote_reader = socket.try_clone().unwrap();
            let mut remote_writer = socket;
            thread::spawn(move || {
                let mut buf = vec![0; 1024];
                loop {
                    match reader.read(&mut buf) {
                        Ok(0) => return,  
                        Ok(n) => {
                            remote_writer.write(&buf[..n]).unwrap();
                        }
                        Err(e) => {
                            println!("reader error: {e:?}");
                        }
                    }
                }
            });
            let mut buf = vec![0; 1024];
            loop {
                match remote_reader.read(&mut buf) {
                  Ok(0) => return,  
                  Ok(n) => {
                    writer.write(&buf[..n]).unwrap();
                  }
                  Err(e) => {
                    println!("remote reader error: {e:?}");
                  }
                }
            }
        }
        Err(e) => {
            println!("cannot connect {e:?}");
        }
    }
}
