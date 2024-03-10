use clap::Parser;
use log::debug;
use messcanner::tls::TlsVersions;
use std::fs::{self, File};
use std::io::Write;
use std::process::Command;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[clap(
    version = "v0.2.0",
    author = "Anton Sidorov tonysidrock@gmail.com",
    about = "Web scanner"
)]
struct Args {
    #[clap(short, long, required = true)]
    address: String,

    #[clap(short, long, default_value_t = 443)]
    port: u16,

    #[clap(short, long)]
    write: bool,

    #[clap(short, long)]
    quiet: bool,

    #[clap(short, long, default_value = "reports")]
    target: String,
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

    if args.write {
        write_tls_protocols_to_file(&tls_versions, host, port, &args.target, args.quiet);
    } else {
        for tls_protocol in tls_versions.try_connect(host, port, args.quiet) {
            println!("{}", tls_protocol);
        }
    }
}

fn write_tls_protocols_to_file(
    tls_versions: &TlsVersions,
    host: &str,
    port: u16,
    target: &str,
    quiet: bool,
) {
    fs::create_dir_all(target).unwrap();
    let mut file = File::create(format!("./{}/{}.txt", target, host)).unwrap();

    for tls_protocol in tls_versions.try_connect(host, port, quiet) {
        writeln!(file, "{}", tls_protocol).unwrap();
    }
}
