extern crate rustc_serialize;
extern crate docopt;
extern crate regex;

extern crate pnet;
extern crate r2d2;
extern crate kirk;
extern crate pcap;
extern crate fnv;

extern crate num_cpus;
extern crate crossbeam;
extern crate chan_signal;

#[macro_use]
mod lib;

mod binlib;
use binlib::cli;

use chan_signal::Signal;

use lib::conn::*;
use lib::data::{PacketDataKey, FromBytes};
use lib::worker::*;

use std::sync::Mutex;

use std::collections::HashMap;
use std::hash::BuildHasherDefault;

use kirk::Job;

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
  let signal = chan_signal::notify(&[Signal::INT, Signal::QUIT]);

  let args = cli::Args::get_args();
  println!("{:?}", args);

  let target = &args.arg_target;
  let (host, port) = cli::parse_target(target);

  let hash: Mutex<HashMap<PacketDataKey, (),
                          BuildHasherDefault<fnv::FnvHasher>>
                 > = Mutex::new(HashMap::default());


  /*
  println!("1");
  crossbeam::scope(|scope| {
    let mut ops = kirk::crew::deque::Options::default();
    ops.num_workers = 2;
    let mut pool = kirk::Pool::<kirk::Deque<kirk::Task>>::scoped(scope, ops);
    pool.push(|| {
      println!("2");
      udp_closer(&args.clone().arg_listen, &hash);
      println!("3");
    });
    println!("???");
  });
  */



  let cpool = create_pool(host, port);
  println!("cpool: {:?}", cpool);


  // let mut cap = pcap::Capture::from_device(pcap::Device {
  //                 name: args.arg_iface.clone(),
  //                 desc: Some("inner".to_string())
  //               }).unwrap()
  //               .promisc(false)
  //               .timeout(0)
  //               .snaplen(2048)
  //               .buffer_size(128*1024*1024)
  //               .open().unwrap();

  let mut cap = pcap::Capture::from_device(pcap::Device {
                  name: args.arg_iface.clone(),
                  desc: Some("inner".to_string())
                }).unwrap()
                .promisc(false)
                .timeout(1)
                .snaplen(2048)
                .buffer_size(128*1024*1024)
                .open().unwrap();

  
  //std::thread::spawn(move || {
  //});


  let mut signal_ops = kirk::crew::deque::Options::default();
  signal_ops.num_workers = 1;

  let mut udp_ops = kirk::crew::deque::Options::default();
  udp_ops.num_workers = 1;

  let mut ops = kirk::crew::deque::Options::default();
  ops.num_workers = 8;//get_threadpool_count();


  crossbeam::scope(|scope| {
    let mut signal_pool =
      kirk::Pool::<kirk::Deque<kirk::Task>>::scoped(scope, signal_ops);
    signal_pool.push(|| {
      let hash = &hash;
      loop {
        let s = signal.recv().unwrap();
        if s == Signal::INT {
          std::process::exit(1);
        }
        println!(">^\\>^\\> got signal: {:?}", s);
        let hash = hash.lock().unwrap();
        println!("hash.len(): {}", hash.len());
      }
    });


    let mut udp_pool =
      kirk::Pool::<kirk::Deque<kirk::Task>>::scoped(scope, udp_ops);
    udp_pool.push(|| {
      udp_closer(&args.clone().arg_listen, &hash);
    });


    /*    
    let mut pool = kirk::Pool::<kirk::Deque<Worker>>::scoped(scope, ops);
    loop {
      match cap.next() {
        Ok(packet) => {
          if cfg!(debug_assertions) {
            d_println!("received packet! {:?}", packet);
            if packet.header.caplen != packet.header.len {
              d_println!("caplen != len");
            }
          }
          pool.push(Worker {
            cpool: cpool.clone(),
            packet_data: { //note: this is suboptimal, use netmap in future
                           //to avoid having to copy packets
              let mut v: std::vec::Vec<u8> = vec![0u8; packet.data.len()]; 
              v.clone_from_slice(packet.data);
              v
            },
            hash: &hash
          });
        },
        Err(_) => (),
      }
    }
    */
    
    
    loop {
      match cap.next() {
        Ok(packet) => {
          if cfg!(debug_assertions) {
            d_println!("received packet! {:?}", packet);
            if packet.header.caplen != packet.header.len {
              d_println!("caplen != len");
            }
          }
          let worker = Worker {
            cpool: cpool.clone(),
            packet_data: &packet.data,
            hash: &hash
          };
          worker.perform();
        },
        Err(_) => (),
      }
    }
    
  });
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
          println!("UDP failed to recv_from: ({},{:?}); {:?}", read, peer_addr, buf);
          continue;
        }
      },
      Err(err) => {
        d_println!("UDP failed to recv_from: {}", err);
        continue
      }
    };

    let key: &PacketDataKey = PacketDataKey::from_bytes(&buf);
    println!("UDP: got key {:?}", key);
    let key_r: PacketDataKey = key.swap();
    {
      let mut hash = match hash.lock() {
        Ok(hash) => hash,
        Err(poisoned_hash) => {
          println!("got poisoned_hash {:?}", poisoned_hash);
          return;
        }
      };

      match (hash.remove(key), hash.remove(&key_r)) {
        (None,None) => {
          println!("UDP closer: keys not found: {:?}", key);
        }
        _ => {}
      };
    }

  }
}


