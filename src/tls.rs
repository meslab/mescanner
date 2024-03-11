use log::debug;
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use std::fmt;
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

    pub fn try_connect(&self, host: &str, port: u16, quiet: bool) -> Vec<TlsVersion> {
        debug!("Supported ciphers: {:?}", self.cipher_list);

        let print_if_not_quiet = |message: &str| {
            if !quiet {
                println!("{}", message);
            }
        };

        let debug_connection_attempt_failure = |tls_version, err| {
            debug!(
                "Connection attempt using TLS {} failed: {}",
                tls_version_to_string(tls_version),
                err
            );
        };

        print_if_not_quiet(&format!(
            "Testing secure connection to {}:{} using different TLS versions and ciphers\nLegend: '+' - successful connection attempt, '-' - failed connecion attempt.",
            host, port
        ));
        
        let mut tls_ciphers: Vec<TlsVersion> = Vec::new();

        for &tls_version in &self.versions {
            print_if_not_quiet(&format!("Using {} ", tls_version_to_string(tls_version)));
            let mut tls_proto = TlsVersion::new(tls_version);
            let mut legend = "";

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
                        Ok(_) => {
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
                        Ok(_) => {
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
                            legend = "+";
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
                            legend = "-";
                            let _ = &tls_proto
                                .server_unsupported_ciphers
                                .push(cipher.to_string());
                            debug_connection_attempt_failure(tls_version, format!("{}", err));
                        }
                    },
                    Err(err) => {
                        debug_connection_attempt_failure(tls_version, format!("{}", err));
                    }
                }
                if !quiet {
                    print!("{}", legend);
                    io::stdout().flush().unwrap();
                }
            }
            print_if_not_quiet("");
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
