extern crate r2d2;
extern crate kirk;
extern crate pnet;
extern crate pcap;
extern crate fnv;

use std;
use std::io::Write;

use std::sync::Mutex;
use std::collections::HashMap;
use std::hash::BuildHasherDefault;

use pnet::packet::Packet;
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::TcpPacket;

use lib::conn::*;
use lib::data::*;

static HANDSHAKE_PRELUDE: &'static [u8] = b"\x13BitTorrent protocol";

pub struct Worker<'a> {
  pub cpool: r2d2::Pool<TcpConnectionManager>,
  pub packet: pcap::Packet<'a>,
  pub hash: &'a Mutex<HashMap<PacketDataKey, (), BuildHasherDefault<fnv::FnvHasher>>>
}

impl<'a> kirk::Job for Worker<'a> {
  fn perform(self) {
    println!("wpacket: {:?}", self.packet);

    let ethernet  = match EthernetPacket::new(self.packet.data) {
      Some(ethernet) => ethernet,
      None => {
        d_println!("Invalid ethernet packet");
        return;
      }
    };
    if !self.handle_ethernet(&ethernet) { return; }

    let ipv4 = match Ipv4Packet::new(ethernet.payload()) {
      Some(ipv4) => ipv4,
      None => {
        d_println!("Invalid IPv4 packet");
        return;
      }
    };
    if !self.handle_ipv4(&ipv4) { return; }

    let tcp = match TcpPacket::new(ipv4.payload()) {
      Some(tcp) => tcp,
      None => {
        d_println!("Invalid TCP packet");
        return;
      }
    };
    self.handle_tcp(&tcp, &ipv4);
  }
}

impl<'a> Worker<'a> {
  fn handle_ethernet(&self, packet: &EthernetPacket) -> bool {
    d_println!("eth!\n{:?}", packet);

    let etype = packet.get_ethertype();
    match etype {
      EtherTypes::Ipv4 => {
        true
      },
      _ => {
        d_println!("Non-IPv4 packet");
        false
      }
    }
  }


  fn handle_ipv4(&self, packet: &Ipv4Packet) -> bool {
    d_println!("ipv4!\n{:?}", packet);

    let proto = packet.get_next_level_protocol();

    match proto {
      IpNextHeaderProtocols::Tcp => {
        true
      },
      _ => {
        d_println!("Non-TCP packet");
        false
      }
    }
  }

  fn handle_tcp(&self, tcp: &TcpPacket, ipv4: &Ipv4Packet) {
    d_println!("tcp!\n{:?}", tcp);

    let payload = tcp.payload();

    if payload.starts_with(HANDSHAKE_PRELUDE) {
      println!(">>>BitTorrent<<<");
      let len = payload.len() as u16;

      let data = PacketData {
        key: PacketDataKey {
          src_addr: ipv4.get_source().octets(),
          dst_addr: ipv4.get_destination().octets(),

          src_port: tcp.get_source().to_be(),
          dst_port: tcp.get_destination().to_be()
        },

        seq: (tcp.get_sequence() + (len as u32)).to_be(),
        ack: tcp.get_acknowledgement().to_be(),

        payload_len: len.to_be()
      };

      let key = &data.key;
      {
        let mut hash = match self.hash.lock() {
          Ok(hash) => hash,
          Err(poisoned_hash) => {
            d_println!("got poisoned_hash {:?}", poisoned_hash);
            return;
          }
        };

        if hash.contains_key(key) {
          return;
        }
        let key_r = key.swap();
        if hash.contains_key(&key_r) {
          return;
        }

        //b/c the next one is going to be in the reverse direction,
        //we're going to insert the reverse here so that it matches
        //on during the first check
        hash.insert(key_r, ());
      }


      let mut conn = self.cpool.get().unwrap();
      if conn.is_connected() {
        println!("live socket");
      } else {
        println!("dead socket");
      }
      println!("conn2: {:?}", *conn);
      let _ = conn.write(data.to_bytes());

      std::process::exit(1);
    }
  }
}
