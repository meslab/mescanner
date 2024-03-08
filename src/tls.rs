use log::debug;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use std::net::TcpStream;

pub struct TlsVersions {
    versions: Vec<openssl::ssl::SslVersion>,
}

impl TlsVersions {
    pub fn new() -> Self {
        TlsVersions {
            versions: vec![
                // openssl::ssl::SslVersion::SSL3,
                openssl::ssl::SslVersion::TLS1,
                openssl::ssl::SslVersion::TLS1_1,
                openssl::ssl::SslVersion::TLS1_2,
                openssl::ssl::SslVersion::TLS1_3,
            ],
        }
    }

    pub fn try_connect(&self, host: &str, port: u16) {
        for &tls_version in &self.versions {
            let mut ssl_connector_builder = SslConnector::builder(SslMethod::tls_client()).unwrap();
            ssl_connector_builder.set_verify(SslVerifyMode::NONE);
            ssl_connector_builder.set_security_level(0);
            match tls_version {
                openssl::ssl::SslVersion::TLS1_3 => {}
                _ => ssl_connector_builder.set_cipher_list("ALL").unwrap(),
            }
            ssl_connector_builder
                .set_min_proto_version(Some(tls_version))
                .unwrap();
            ssl_connector_builder
                .set_max_proto_version(Some(tls_version))
                .unwrap();
            let ssl_connector = ssl_connector_builder.build();

            match TcpStream::connect((host, port)) {
                Ok(stream) => match ssl_connector.connect(host, stream) {
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
                    }
                    Err(err) => {
                        println!(
                            "Connection attempt using TLS {} failed: {}",
                            self.tls_version_to_string(tls_version),
                            err
                        );
                    }
                },
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

    pub fn tls_version_to_string(&self, tls_version: openssl::ssl::SslVersion) -> &'static str {
        match tls_version {
            openssl::ssl::SslVersion::SSL3 => "SSLv3",
            openssl::ssl::SslVersion::TLS1 => "TLSv1",
            openssl::ssl::SslVersion::TLS1_1 => "TLSv1.1",
            openssl::ssl::SslVersion::TLS1_2 => "TLSv1.2",
            openssl::ssl::SslVersion::TLS1_3 => "TLSv1.3",
            _ => "Unknown",
        }
    }
}
