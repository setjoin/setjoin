fn main() {
    std::process::exit(setjoin_mailctl::run(std::env::args().skip(1).collect()));
}
