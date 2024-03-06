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

struct TlsVersions {
    versions: Vec<openssl::ssl::SslVersion>,
}

impl TlsVersions {
    fn new() -> Self {
        TlsVersions {
            versions: vec![
                openssl::ssl::SslVersion::TLS1,
                openssl::ssl::SslVersion::TLS1_1,
                openssl::ssl::SslVersion::TLS1_2,
            ],
        }
    }

    fn try_connect(&self, host: &str, port: u16) {
        for &tls_version in &self.versions {
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
                            println!(
                                "Connected using TLS version: {}",
                                self.tls_version_to_string(tls_version)
                            );
                            println!("Supported Ciphers:");
                            for cipher in ssl.current_cipher().unwrap().name().split(':') {
                                println!("{}", cipher);
                            }
                            return; // Exit the loop if successful connection
                        }
                        Err(err) => {
                            println!(
                                "Connection attempt using TLS {} failed: {}",
                                self.tls_version_to_string(tls_version),
                                err
                            );
                        }
                    }
                }
                Err(err) => {
                    println!(
                        "Connection attempt using TLS {} failed: {}",
                        self.tls_version_to_string(tls_version),
                        err
                    );
                }
            }
        }
    }

    fn tls_version_to_string(&self, tls_version: openssl::ssl::SslVersion) -> &'static str {
        match tls_version {
            openssl::ssl::SslVersion::TLS1 => "TLSv1",
            openssl::ssl::SslVersion::TLS1_1 => "TLSv1.1",
            openssl::ssl::SslVersion::TLS1_2 => "TLSv1.2",
            _ => "Unknown",
        }
    }
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
