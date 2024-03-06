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

    #[clap(short, long, default_value_t = 443)]
    port: u16,
}

fn main() {
    env_logger::init();

    let args = Args::parse();

    let host: &str = &args.address;
    let port = args.port;
    debug!("Connecting to {}:{}", host, port);

    let tls_versions = [
        openssl::ssl::SslVersion::SSL3,
        openssl::ssl::SslVersion::TLS1,
        openssl::ssl::SslVersion::TLS1_1,
        openssl::ssl::SslVersion::TLS1_2,
        openssl::ssl::SslVersion::TLS1_3,
    ];

    for &tls_version in &tls_versions {
        let mut ssl_connector_builder = SslConnector::builder(SslMethod::tls()).unwrap();
        ssl_connector_builder
            .set_min_proto_version(Some(tls_version))
            .unwrap();
        ssl_connector_builder
            .set_max_proto_version(Some(tls_version))
            .unwrap();
        let ssl_connector = ssl_connector_builder.build();

        match TcpStream::connect((host, port)) {
            Ok(stream) => {
                match ssl_connector.connect(host, stream) {
                    Ok(ssl_stream) => {
                        debug!("SSL stream: {:?}", ssl_stream);
                        let ssl = ssl_stream.ssl();
                        println!("Connected using TLS version: {}", ssl.version_str());
                        println!("Supported Ciphers:");
                        for cipher in ssl.current_cipher().unwrap().name().split(':') {
                            println!("{}", cipher);
                        }
                        //    break; // Exit the loop if successful connection
                    }
                    Err(err) => {
                        println!(
                            "Connection attempt using TLS {:?} failed: {}",
                            tls_version, err
                        );
                    }
                }
            }
            Err(err) => {
                println!(
                    "Connection attempt using TLS {:?} failed: {}",
                    tls_version, err
                );
            }
        }
    }
}
