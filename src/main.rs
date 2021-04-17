use std::io;
use std::thread;
use std::io::prelude::*;
use std::net::TcpStream;
use std::net::TcpListener;
use std::net::{Ipv4Addr,Ipv6Addr,SocketAddrV6,SocketAddrV4};

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
            // ipv4
            reader.read_exact(&mut buffer[0..6]).unwrap();
            let mut tmp_array: [u8; 4] = Default::default();
            tmp_array.copy_from_slice(&buffer[0..4]);
            let ipv4 = Ipv4Addr::from(tmp_array);
            let socket = SocketAddrV4::new(ipv4, 0x1BB);
            println!("ipv4 port: {} * 256 + {}", buffer[4], buffer[5]);
            addr_port = format!("{}", socket);
            println!("ipv4: {}", addr_port);
        }
        0x03 => {
            // DOMAINNAME
            reader.read_exact(&mut buffer[0..1]).unwrap();
            let len = buffer[0] as usize;
            reader.read_exact(&mut buffer[0..len + 2]).unwrap();
            println!("domain port: {} * 256 + {}", buffer[len], buffer[len + 1]);
            if let Ok(addr) = std::str::from_utf8(&buffer[0..len]) {
                addr_port = format!("{}:{}", addr, 0x1BB);
            }
            println!("domain: {}", addr_port);
        }
        0x04 => {
            // ipv6
            reader.read_exact(&mut buffer[0..18]).unwrap();
            let mut tmp_array: [u8; 16] = Default::default();
            tmp_array.copy_from_slice(&buffer[0..16]);
            let ipv6 = Ipv6Addr::from(tmp_array);
            println!("domain port: {} * 256 + {}", buffer[16], buffer[17]);
            let socket = SocketAddrV6::new(ipv6, 0x1BB, 0, 0);
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
                writer.write(&[0x05u8, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,]).unwrap();
                let mut remote_reader = socket.try_clone().unwrap();
                let mut remote_writer = socket;
                thread::spawn(move || {
                    io::copy(&mut reader, &mut remote_writer).unwrap();
                });
                io::copy(&mut remote_reader, &mut writer).unwrap();

            } else {
                println!("cannot connect {}", addr_port);
            }
        }
        _ => {
        }
    }
}
