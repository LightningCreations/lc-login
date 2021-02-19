pub fn main() {
    let mut args = std::env::args();
    let name = args.next().unwrap();
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("{}: Cannot work without effective root", name);
        std::process::exit(1);
    }
}
