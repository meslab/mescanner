use log::debug;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use std::io::{self, Write};
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
            cipher_list,
        }
    }

    pub fn try_connect(&self, host: &str, port: u16) -> Vec<TlsVersion> {
        debug!("Supported ciphers: {:?}", self.cipher_list);
        println!(
            "Testing secure connection to {}:{} using different TLS versions and ciphers",
            host, port
        );
        println!("Legend: '+' - successful connection attempt, '-' - failed connecion attempt.",);

        let mut tls_ciphers: Vec<TlsVersion> = Vec::new();

        for &tls_version in &self.versions {
            println!("Using {} ", tls_version_to_string(tls_version));
            let mut tls_proto = TlsVersion::new(tls_version);

            for cipher in &self.cipher_list {
                debug!(
                    "Trying to connect using Protocol {}, cipher: {}",
                    tls_version_to_string(tls_version),
                    cipher
                );
                let mut builder = SslConnector::builder(SslMethod::tls()).unwrap();
                builder.set_verify(SslVerifyMode::NONE);
                builder.set_security_level(0);

                match tls_version {
                    openssl::ssl::SslVersion::TLS1_3 => match builder.set_ciphersuites(cipher) {
                        Result::Ok(_) => {
                            tls_proto.client_supported_ciphers.push(cipher.to_string());
                        }
                        _ => {
                            tls_proto
                                .client_unsupported_ciphers
                                .push(cipher.to_string());
                            continue;
                        }
                    },
                    _ => match builder.set_cipher_list(cipher) {
                        Result::Ok(_) => {
                            tls_proto.client_supported_ciphers.push(cipher.to_string());
                        }
                        _ => {
                            tls_proto
                                .client_unsupported_ciphers
                                .push(cipher.to_string());
                            continue;
                        }
                    },
                }

                builder.set_min_proto_version(Some(tls_version)).unwrap();
                builder.set_max_proto_version(Some(tls_version)).unwrap();
                let connector = builder.build();

                match TcpStream::connect((host, port)) {
                    Ok(stream) => match connector.connect(host, stream) {
                        Ok(ssl_stream) => {
                            print!("+");
                            debug!("SSL stream: {:?}", ssl_stream);
                            let current_ciphers = ssl_stream
                                .ssl()
                                .current_cipher()
                                .unwrap()
                                .name()
                                .split(':')
                                .map(|s| s.to_string())
                                .collect::<Vec<String>>();
                            for current_cipher in current_ciphers {
                                match tls_proto.server_supported_ciphers.contains(&current_cipher) {
                                    false => {
                                        &tls_proto.server_supported_ciphers.push(current_cipher)
                                    }
                                    _ => continue,
                                };
                            }
                        }
                        Err(err) => {
                            print!("-");

                            let _ = &tls_proto
                                .server_unsupported_ciphers
                                .push(cipher.to_string());
                            debug!(
                                "Connection attempt using TLS {} failed: {}",
                                tls_version_to_string(tls_version),
                                err
                            );
                        }
                    },
                    Err(err) => {
                        debug!(
                            "Connection attempt using TLS {} failed: {}",
                            tls_version_to_string(tls_version),
                            err
                        );
                    }
                }
                io::stdout().flush().unwrap();
            }
            println!();
            match &tls_proto.server_supported_ciphers.len() {
                0 => {
                    debug!(
                        "Server does not support TLS version {}",
                        tls_version_to_string(tls_version)
                    );
                }
                _ => {
                    debug!(
                        "Protocol {} supported by server\n Ciphers: {:?}",
                        tls_version_to_string(tls_version),
                        &tls_proto.server_supported_ciphers
                    );
                }
            }
            tls_ciphers.push(tls_proto);
        }
        tls_ciphers
    }
}

#[derive(Debug)]
pub struct TlsVersion {
    version: openssl::ssl::SslVersion,
    client_supported_ciphers: Vec<String>,
    client_unsupported_ciphers: Vec<String>,
    server_supported_ciphers: Vec<String>,
    server_unsupported_ciphers: Vec<String>,
}

impl TlsVersion {
    pub fn new(version: openssl::ssl::SslVersion) -> Self {
        TlsVersion {
            version,
            client_supported_ciphers: Vec::new(),
            client_unsupported_ciphers: Vec::new(),
            server_supported_ciphers: Vec::new(),
            server_unsupported_ciphers: Vec::new(),
        }
    }
}

use std::fmt;

impl fmt::Display for TlsVersion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Protocol: {}", tls_version_to_string(self.version))?;
        match &self.server_supported_ciphers.len() {
            0 => writeln!(f, "Server does not support this protocol"),
            _ => {
                writeln!(f, "  Server Supported Ciphers:")?;
                for cipher in &self.server_supported_ciphers {
                    writeln!(f, "    {}", cipher)?;
                }
                write!(f, "")
            }
        }
    }
}

fn tls_version_to_string(tls_version: openssl::ssl::SslVersion) -> &'static str {
    match tls_version {
        openssl::ssl::SslVersion::SSL3 => "SSLv3",
        openssl::ssl::SslVersion::TLS1 => "TLSv1",
        openssl::ssl::SslVersion::TLS1_1 => "TLSv1.1",
        openssl::ssl::SslVersion::TLS1_2 => "TLSv1.2",
        openssl::ssl::SslVersion::TLS1_3 => "TLSv1.3",
        _ => "Unknown",
    }
}
