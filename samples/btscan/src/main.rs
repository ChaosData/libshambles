extern crate rustc_serialize;
extern crate docopt;
extern crate regex;
extern crate r2d2;
extern crate num_cpus;
extern crate kirk;
extern crate crossbeam;
extern crate pcap;
extern crate pnet; //note: this is here so that worker.rs doesn't need to
                   //      self:: everything
extern crate fnv;

#[macro_use]
mod lib;

mod binlib;
use binlib::cli;

use lib::conn::*;
use lib::data::{PacketDataKey, FromBytes};
use lib::worker::*;

use std::sync::Mutex;

use std::collections::HashMap;
use std::hash::BuildHasherDefault;


fn parse_target(target: &String) -> (&str, u16) {
  let mut host_port = target.split(":").take(2);
  let host = host_port.next().unwrap();
  let port: u16 = host_port.next().unwrap().parse::<u16>().unwrap();
  (host, port)
}

fn create_pool(host: &str, port: u16) -> r2d2::Pool<TcpConnectionManager> {
  let cpool_config = r2d2::Config::builder()
                    .pool_size(128)
                    .error_handler(Box::new(r2d2::LoggingErrorHandler))
                    .build();
  let cpool_manager = TcpConnectionManager::new(host.to_string(), port).unwrap();

  r2d2::Pool::new(cpool_config, cpool_manager).unwrap()
}

fn get_threadpool_count() -> usize {
  match num_cpus::get() {
    1 => 1,
    v if v > 1 => v - 1,
    x => {
      println!("Invalid number of CPUs? Got {:?}.", x);
      std::process::exit(1)
    }
  }
}



fn main() {
  let args = cli::Args::get_args();
  println!("{:?}", args);

  let (host, port) = parse_target(&args.arg_target);

  let hash: Mutex<HashMap<PacketDataKey, (),
                          BuildHasherDefault<fnv::FnvHasher>>
                 > = Mutex::new(HashMap::default());

  crossbeam::scope(|_| {
    udp_closer(&args.arg_listen, &hash);
  });

  
  let cpool = create_pool(host, port);
  println!("cpool: {:?}", cpool);


  let iface = pcap::Device {
    name: args.arg_iface.clone(),
    desc: Some("inner".to_string())
  };

  let mut cap = pcap::Capture::from_device(iface).unwrap()
                .promisc(false)
                .timeout(0)
                .snaplen(2048)
                .buffer_size(128*1024*1024)
                .open().unwrap();

  let mut ops = kirk::crew::deque::Options::default();
  ops.num_workers = get_threadpool_count();

  loop {
    match cap.next() {
      Ok(packet) => {
        if cfg!(debug_assertions) {
          d_println!("received packet! {:?}", packet);
          if packet.header.caplen != packet.header.len {
            d_println!("caplen != len");
          }
        }

        crossbeam::scope(|scope| {

          let mut pool = kirk::Pool::<kirk::Deque<Worker>>::scoped(scope, ops);
          pool.push(Worker {
            cpool: cpool.clone(),
            packet: packet,
            hash: &hash
          });

        });
      },
      Err(_) => {}
    };
  }
}





fn udp_closer(conn: &str, hash: &Mutex<HashMap<PacketDataKey, (),
                                   BuildHasherDefault<fnv::FnvHasher>>>) {
  use std::net::UdpSocket;
  
  let udp = match UdpSocket::bind(conn) {
    Ok(udp) => udp,
    Err(err) => {
      d_println!("UDP failed to bind: {}", err);
      std::process::exit(1)
    }
  };

  let mut buf = [0u8; 12];
  loop {
    match udp.recv_from(&mut buf) {
      Ok((read, peer_addr)) => {
        if read != 12 {
          d_println!("UDP failed to recv_from: ({},{:?}); {:?}", read, peer_addr, buf);
          continue;
        }
      },
      Err(err) => {
        d_println!("UDP failed to recv_from: {}", err);
        continue
      }
    };

    let key: &PacketDataKey = PacketDataKey::from_bytes(&buf);
    let key_r: PacketDataKey = key.swap();
    {
      let mut hash = match hash.lock() {
        Ok(hash) => hash,
        Err(poisoned_hash) => {
          d_println!("got poisoned_hash {:?}", poisoned_hash);
          return;
        }
      };

      match (hash.remove(key), hash.remove(&key_r)) {
        (None,None) => {
          d_println!("UDP closer: keys not found: {:?}", key);
        }
        _ => {}
      };
    }

  }
}


