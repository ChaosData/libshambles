use std;

use docopt::Docopt;
use regex::Regex;

const USAGE: &'static str = "
BitTorrent Shambler Scanner.

Usage:
  btscan <iface> <listen> <target>
  btscan (-h | --help)
  btscan --version

Example:
  btscan eth1 '0.0.0.0:2222' '10.1.2.3:5555'

Options:
  -h --help     Show this screen.
  --version     Show version.
";

#[derive(Debug, RustcDecodable)]
pub struct Args {
  pub arg_iface: String,
  pub arg_listen: String,
  pub arg_target: String,
}

impl Args {
  pub fn get_args() -> Args {
    match Docopt::new(USAGE) {
      Ok(d) => {
        let args: Args = match d.decode() {
          Ok(d) => {
            d
          },
          Err(_) => {
            exit()
          }
        };
        
        if !args.validate() {
          exit()
        }

        args
      }
      Err(e) => {
        d_println!("invalid USAGE str: {:?}", e);
        exit()
      }
    }
  }

  fn validate(&self) -> bool {
    let re = Regex::new(r"^[a-zA-Z]+[a-zA-Z0-9.-]+:[0-9]+$").unwrap();
    re.is_match(&self.arg_listen) && re.is_match(&self.arg_target)
  }
}

fn exit() -> ! {
  print!("{}", USAGE.to_string()
               .replace("\nBitTorrent Shambler Scanner.",
                        "Invalid arguments.")
  );
  std::process::exit(1);
}