use std;

#[derive(Debug)]
#[repr(C, packed)]
#[derive(PartialEq, Eq, Hash)]
pub struct PacketDataKey {
  pub src_addr: [u8;4],
  pub dst_addr: [u8;4],

  pub src_port: u16,
  pub dst_port: u16,
}

impl PacketDataKey {
  pub fn swap(&self) -> PacketDataKey {
    PacketDataKey {
      src_addr: self.dst_addr,
      dst_addr: self.src_addr,

      src_port: self.dst_port,
      dst_port: self.src_port
    }
  }
}

#[derive(Debug)]
#[repr(C, packed)]
pub struct PacketData {
  pub key: PacketDataKey,

  pub seq: u32,
  pub ack: u32,

  pub payload_len: u16
}

pub trait ToBytes {
  type RetType;

  fn to_bytes(&self) -> &Self::RetType;
}


pub trait FromBytes {
  type InType;

  fn from_bytes<'a>(bytes: &'a Self::InType) -> &'a Self;
}

impl FromBytes for PacketDataKey {
  type InType = [u8; 12];

  fn from_bytes<'a>(bytes: &'a [u8; 12]) -> &'a PacketDataKey {
    let p: *const u8 = bytes as *const u8;
    let p: *const PacketDataKey = p as *const PacketDataKey;
    unsafe { std::mem::transmute::<*const PacketDataKey, &PacketDataKey>(p) }
  }
}


impl<'a> ToBytes for PacketDataKey {
  type RetType = [u8; 12];

  fn to_bytes(&self) -> &[u8; 12] {
    let p: *const PacketDataKey = self;
    let p: *const u8 = p as *const u8;
    unsafe { std::mem::transmute(p) }
  }
}

impl ToBytes for PacketData {
  type RetType = [u8; 22];

  fn to_bytes(&self) -> &[u8; 22] {
    let p: *const PacketData = self;
    let p: *const u8 = p as *const u8;
    unsafe { std::mem::transmute(p) }
  }
}
