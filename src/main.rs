use std::io;
use std::thread;
use std::io::prelude::*;
use std::net::TcpStream;
use std::net::TcpListener;
use std::net::{Ipv4Addr,Ipv6Addr,SocketAddrV6,SocketAddrV4,Shutdown};
use std::time::Duration;
use bytes::Buf;

fn main() {
    let listener = TcpListener::bind("0.0.0.0:1080").unwrap();
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
    reader.read_exact(&mut buffer[0..2]).unwrap();

    let methods = buffer[1] as usize;
    reader.read_exact(&mut buffer[0..methods]).unwrap();

    writer.write(&[0x05u8, 0x00]).unwrap();       
    writer.flush().unwrap();

    reader.read_exact(&mut buffer[0..4]).unwrap();
    let cmd = buffer[1];
    let atyp = buffer[3];

    let mut addr_port = String::from("");
    match atyp {
        0x01 => {
            // ipv4: 4bytes + port
            reader.read_exact(&mut buffer[0..6]).unwrap();
            let mut tmp_array: [u8; 4] = Default::default();
            tmp_array.copy_from_slice(&buffer[0..4]);
            let ipv4 = Ipv4Addr::from(tmp_array);
            let port: u16 = buffer[4..6].as_ref().get_u16();
            let socket = SocketAddrV4::new(ipv4, port);
            println!("ipv4 port: {} * 256 + {}", buffer[4], buffer[5]);
            addr_port = format!("{}", socket);
            println!("ipv4: {}", addr_port);
        }
        0x03 => {
            // DOMAINNAME
            reader.read_exact(&mut buffer[0..1]).unwrap();
            let len = buffer[0] as usize;
            reader.read_exact(&mut buffer[0..len + 2]).unwrap();
            let port: u16 = buffer[len..len + 2].as_ref().get_u16();
            println!("domain port: {} * 256 + {}", buffer[len], buffer[len + 1]);
            if let Ok(addr) = std::str::from_utf8(&buffer[0..len]) {
                addr_port = format!("{}:{}", addr, port);
            }
            println!("domain: {}", addr_port);
        }
        0x04 => {
            // ipv6: 16bytes + port
            reader.read_exact(&mut buffer[0..18]).unwrap();
            let mut tmp_array: [u8; 16] = Default::default();
            tmp_array.copy_from_slice(&buffer[0..16]);
            let ipv6 = Ipv6Addr::from(tmp_array);
            let port = buffer[16..18].as_ref().get_u16();
            println!("domain port: {} * 256 + {}", buffer[16], buffer[17]);
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
                writer.write(&[0x05u8, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,]).unwrap();
                let mut remote_reader = socket.try_clone().unwrap();
                let mut remote_writer = socket;
                thread::spawn(move || {
                    io::copy(&mut reader, &mut remote_writer).unwrap();
                    thread::sleep(Duration::from_secs(30));
                    reader.shutdown(Shutdown::Both).unwrap();
                    remote_writer.shutdown(Shutdown::Both).unwrap();
                });
                io::copy(&mut remote_reader, &mut writer).unwrap();
                thread::sleep(Duration::from_secs(30));
                remote_reader.shutdown(Shutdown::Both).unwrap();
                writer.shutdown(Shutdown::Both).unwrap();
            } else {
                println!("cannot connect {}", addr_port);
            }
        }
        _ => {
        }
    }
}
