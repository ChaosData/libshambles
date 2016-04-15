extern crate libc;
extern crate r2d2;

use std;
use std::os::unix::io::{RawFd, AsRawFd};
use std::io::Error;
use std::net::TcpStream;

pub trait IsConnected {
  fn is_connected(&mut self) -> bool;
}

impl IsConnected for TcpStream {
  fn is_connected(&mut self) -> bool {
    let mut error: libc::c_int = 0;
    let mut len: libc::socklen_t = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let fd: RawFd = self.as_raw_fd();
    unsafe {
      let r: libc::c_int = libc::getsockopt(
        fd, libc::SOL_SOCKET, libc::SO_ERROR,
        &mut error as *mut _ as *mut libc::c_void,
        &mut len as *mut libc::socklen_t
      );
      d_println!("is_connected: r:{:?} error:{:?} errno:{:?}",
               r, error, *libc::__errno_location());
      r == 0
    }
  }
}

#[derive(Debug)]
pub struct TcpConnectionManager {
  host: String,
  port: u16
}

impl TcpConnectionManager {
  pub fn new(host: String, port: u16)
  -> Result<TcpConnectionManager, Error> {
    Ok(TcpConnectionManager {
      host: host,
      port: port
    })
  }
}

impl r2d2::ManageConnection for TcpConnectionManager {
  type Connection = TcpStream;
  type Error = Error;

  fn connect(&self) -> Result<TcpStream, Error> {
    let conn = TcpStream::connect((self.host.as_str(), self.port));
    match conn {
      Ok(v) => {
        d_println!("creating new connection! conn: {:?}", v);
        Ok(v)
      },
      Err(e) => {
        d_println!("creating new connection... FAILED");
        Err(e)
      }
    }
  }

  fn is_valid(&self, _conn: &mut TcpStream) -> Result<(), Error> {
    if _conn.is_connected() {
      return Ok(());
    } else {
      return Err(std::io::Error::new(std::io::ErrorKind::Other, "err"))
    }
  }

  fn has_broken(&self, _conn: &mut TcpStream) -> bool {
    //don't want to reuse,
    //this will cause replacements to be created oob of processing
    true
  }
}