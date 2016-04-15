
#[macro_export]
macro_rules! d_println {
  () => ();
  ($fmt:expr) => {
    if cfg!(debug_assertions) {
      print!(concat!($fmt, "\n"));
    }
  };
  ($fmt:expr, $($arg:tt)*) => {
    if cfg!(debug_assertions) {
      print!(concat!($fmt, "\n"), $($arg)*);
    }
  };
}