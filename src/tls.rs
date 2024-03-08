use log::debug;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use std::net::TcpStream;

pub struct TlsVersions<'a> {
    versions: Vec<openssl::ssl::SslVersion>,
    cipher_list: Vec<&'a str>,
}

impl<'a> TlsVersions<'a> {
    pub fn new(cipher_list: Vec<&'a str>) -> Self {
        TlsVersions {
            versions: vec![
                openssl::ssl::SslVersion::TLS1_3,
                openssl::ssl::SslVersion::TLS1_2,
                openssl::ssl::SslVersion::TLS1_1,
                openssl::ssl::SslVersion::TLS1,
                // openssl::ssl::SslVersion::SSL3,
            ],
            cipher_list: cipher_list,
        }
    }

    pub fn try_connect(&self, host: &str, port: u16) {
        debug!("Supported ciphers: {:?}", self.cipher_list);

        for &tls_version in &self.versions {
            let mut client_supported_ciphers: Vec<String> = Vec::new();
            let mut client_unsupported_ciphers: Vec<String> = Vec::new();
            let mut server_supported_ciphers: Vec<String> = Vec::new();
            let mut server_unsupported_ciphers: Vec<String> = Vec::new();
            for cipher in &self.cipher_list {
                debug!(
                    "Trying to connect using TLS version: {}, cipher: {}",
                    self.tls_version_to_string(tls_version),
                    cipher
                );
                let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
                builder.set_verify(SslVerifyMode::NONE);
                builder.set_security_level(0);

                match builder.set_ciphersuites(cipher) {
                    Result::Ok(_) => {
                        client_supported_ciphers.push(cipher.to_string());
                    }
                    _ => match builder.set_cipher_list(cipher) {
                        Result::Ok(_) => {
                            client_supported_ciphers.push(cipher.to_string());
                        }
                        _ => {
                            client_unsupported_ciphers.push(cipher.to_string());
                            continue;
                        }
                    },
                };
                builder.set_min_proto_version(Some(tls_version)).unwrap();
                builder.set_max_proto_version(Some(tls_version)).unwrap();
                let connector = builder.build();

                match TcpStream::connect((host, port)) {
                    Ok(stream) => match connector.connect(host, stream) {
                        Ok(ssl_stream) => {
                            debug!("SSL stream: {:?}", ssl_stream);
                            let current_ciphers =
                                ssl_stream.ssl().current_cipher().unwrap().name().split(':');
                            for current_cipher in current_ciphers {
                                if !server_supported_ciphers.contains(&current_cipher.to_string()) {
                                    server_supported_ciphers.push(current_cipher.to_string());
                                }
                            }
                        }
                        Err(err) => {
                            server_unsupported_ciphers.push(cipher.to_string());
                            debug!(
                                "Connection attempt using TLS {} failed: {}",
                                self.tls_version_to_string(tls_version),
                                err
                            );
                        }
                    },
                    Err(err) => {
                        debug!(
                            "Connection attempt using TLS {} failed: {}",
                            self.tls_version_to_string(tls_version),
                            err
                        );
                    }
                }
            }
            match server_supported_ciphers.len() {
                0 => {
                    println!(
                        "Server does not support TLS version {}",
                        self.tls_version_to_string(tls_version)
                    );
                }
                _ => {
                    println!(
                        "TLS version: {} supported by server\n Ciphers: {:?}",
                        self.tls_version_to_string(tls_version),
                        server_supported_ciphers
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
