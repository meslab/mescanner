use clap::Parser;
use log::debug;
use messcanner::tls::TlsVersions;
use std::process::Command;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[clap(
    version = "v0.1.0",
    author = "Anton Sidorov tonysidrock@gmail.com",
    about = "Web scanner"
)]
struct Args {
    #[clap(short, long, required = true)]
    address: String,

    #[clap(short, long, default_value_t = 443)]
    port: u16,
}

fn main() {
    env_logger::init();

    let args = Args::parse();

    let host: &str = &args.address;
    let port = args.port;
    debug!("Connecting to {}:{}", host, port);

    let output = Command::new("openssl")
        .arg("ciphers")
        .arg("ALL:eNULL")
        .output()
        .expect("Failed to execute command");

    let cipher_list_binding = String::from_utf8(output.stdout).unwrap();
    let cipher_list = cipher_list_binding.split(':').collect();

    let tls_versions = TlsVersions::new(cipher_list);
    for tls_protocol in tls_versions.try_connect(host, port) {
        println!("{}", tls_protocol);
    }
}
