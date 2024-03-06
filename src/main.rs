use clap::Parser;
use env_logger;
use log::{debug, info};
use openssl::ssl::{SslConnector, SslMethod};
use std::net::TcpStream;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
#[clap(
    version = "v0.0.1",
    author = "Anton Sidorov tonysidrock@gmail.com",
    about = "Security scanner"
)]
struct Args {
    #[clap(short, long, required = true)]
    address: String,
}

fn main() {
    env_logger::init();

    let args = Args::parse();

    let host: &str = &args.address;
    let port = 443;
    debug!("Connecting to {}:{}", host, port);

    // Create an SSL connector with default options
    let ssl_connector = SslConnector::builder(SslMethod::tls()).unwrap().build();
    debug!("SSL connector created successfully");

    // Connect to the server
    let stream = TcpStream::connect((host, port)).unwrap();
    let ssl_stream = ssl_connector.connect(&host, stream).unwrap();

    // Get the SSL connection's current cipher and protocol
    let ssl = ssl_stream.ssl();
    println!("Supported Ciphers:");
    for cipher in ssl.current_cipher().unwrap().name().split(':') {
        println!("{}", cipher);
    }
    println!("Protocol: {}", ssl.version_str());
}
