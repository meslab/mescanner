use openssl::ssl::{SslConnector, SslMethod};
use openssl::ssl::SslStream;
use std::net::TcpStream;

fn main() {
    // Define the URL of the website you want to check
    let host = "www.google.com";
    let port = 443;

    // Create an SSL connector with default options
    let ssl_connector = SslConnector::builder(SslMethod::tls()).unwrap().build();

    // Connect to the server
    let stream = TcpStream::connect((host, port)).unwrap();
    let ssl_stream = ssl_connector.connect(host, stream).unwrap();

    // Get the SSL connection's current cipher and protocol
    let ssl = ssl_stream.ssl();
    println!("Supported Ciphers:");
    for cipher in ssl.current_cipher().unwrap().name().split(':') {
        println!("{}", cipher);
    }
    println!("Protocol: {}", ssl.version_str());
}
