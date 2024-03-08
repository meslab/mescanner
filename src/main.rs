use clap::Parser;
use log::debug;
use messcanner::tls::TlsVersions;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[clap(
    version = "v0.0.2",
    author = "Anton Sidorov tonysidrock@gmail.com",
    about = "Security scanner"
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

    let tls_versions = TlsVersions::new();
    tls_versions.try_connect(host, port);
}
