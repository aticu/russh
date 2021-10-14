use russh_transport::{Builder, ConnectionAlgorithms, ConnectionRole};

mod openssh;

/// Runs a test as client against OpenSSH with the default builder modified by the given closure.
async fn test_client_against_openssh<
    F: for<'a> FnOnce(
        Builder<tokio::net::tcp::ReadHalf<'a>, tokio::net::tcp::WriteHalf<'a>>,
    ) -> Builder<tokio::net::tcp::ReadHalf<'a>, tokio::net::tcp::WriteHalf<'a>>,
>(
    builder_init: F,
) {
    let sshd = openssh::Sshd::launch().await;

    let mut stream = tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, sshd.port))
        .await
        .expect("tcp connection to sshd could not be opened");
    let (read, write) = stream.split();

    let builder = Builder::new(read, write, ConnectionRole::Client);

    let handler = builder_init(builder)
        .build()
        .await
        .expect("client could not successfully exchange keys with sshd");

    drop(handler);

    let output = sshd
        .run_to_completion()
        .await
        .expect("could not read output from sshd");

    assert!(output.contains("KEX done"));
}

/// Runs a test as server against OpenSSH with the default builder modified by the given closure.
async fn test_server_against_openssh<
    F: for<'a> FnOnce(
        Builder<tokio::net::tcp::ReadHalf<'a>, tokio::net::tcp::WriteHalf<'a>>,
    ) -> Builder<tokio::net::tcp::ReadHalf<'a>, tokio::net::tcp::WriteHalf<'a>>,
>(
    builder_init: F,
) {
    let port = portpicker::pick_unused_port().expect("no free port found");

    let mut listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
        .await
        .expect("could not open tcp listener");

    let ssh = openssh::Ssh::launch(port).await;

    let (mut stream, _peer_addr) = listener
        .accept()
        .await
        .expect("could not accept a connection");
    let (read, write) = stream.split();

    let builder = Builder::new(read, write, ConnectionRole::Server);

    let mut handler = builder_init(builder)
        .build()
        .await
        .expect("server could not successfully exchange keys with ssh");

    assert_eq!(
        handler.next_packet().await.unwrap(),
        &b"\x05\x00\x00\x00\x0cssh-userauth"[..]
    );

    let output = ssh
        .run_to_completion()
        .await
        .expect("could not read output from ssh");

    assert!(output.contains("SSH2_MSG_NEWKEYS received"));
}

/// Creates a new random `"ssh-ed25519"` host key.
fn random_ed25519_host_key() -> Vec<u8> {
    ed25519_dalek::Keypair::generate(&mut rand::thread_rng())
        .to_bytes()
        .to_vec()
}

/// Tests the default client against the OpenSSH server.
#[tokio::test]
async fn default_client_with_openssh() {
    test_client_against_openssh(|builder| builder).await;
}

/// Tests the default (except for loading a host key) server against the OpenSSH client.
#[tokio::test]
async fn default_server_with_openssh() {
    test_server_against_openssh(|builder| {
        builder
            .load_host_key("ssh-ed25519", &random_ed25519_host_key())
            .expect("host key could not be successfully loaded")
    })
    .await;
}

/// Tests a combination of separate encryption and mac algorithms as server against the OpenSSH client.
#[tokio::test]
async fn separate_encryption_mac_client_with_openssh() {
    test_client_against_openssh(|builder| {
        let mut algorithms = ConnectionAlgorithms::new();
        algorithms
            .add_host_key_algorithm(algorithms::host_key::Ed25519::new())
            .expect("host key algorithm could not be successfully added")
            .add_key_exchange_algorithm(algorithms::key_exchange::Curve25519Sha256::new())
            .expect("key exchange algorithm could not be successfully added")
            .add_encryption_algorithm(algorithms::encryption::None::new())
            .expect("encryption algorithm could not be successfully added")
            .add_encryption_algorithm(algorithms::encryption::Aes128Ctr::new())
            .expect("encryption algorithm could not be successfully added")
            .add_mac_algorithm(algorithms::mac::None::new())
            .expect("mac algorithm could not be successfully added")
            .add_mac_algorithm(algorithms::mac::HmacSha2256::new())
            .expect("mac algorithm could not be successfully added")
            .add_compression_algorithm(algorithms::compression::None::new())
            .expect("compression algorithm could not be successfully added");

        builder.algorithms(algorithms)
    })
    .await;
}

/// Tests a combination of separate encryption and mac algorithms as server against the OpenSSH client.
#[tokio::test]
async fn separate_encryption_mac_server_with_openssh() {
    test_server_against_openssh(|builder| {
        let mut algorithms = ConnectionAlgorithms::new();
        algorithms
            .add_host_key_algorithm(algorithms::host_key::Ed25519::new())
            .expect("host key algorithm could not be successfully added")
            .add_key_exchange_algorithm(algorithms::key_exchange::Curve25519Sha256::new())
            .expect("key exchange algorithm could not be successfully added")
            .add_encryption_algorithm(algorithms::encryption::None::new())
            .expect("encryption algorithm could not be successfully added")
            .add_encryption_algorithm(algorithms::encryption::Aes128Ctr::new())
            .expect("encryption algorithm could not be successfully added")
            .add_mac_algorithm(algorithms::mac::None::new())
            .expect("mac algorithm could not be successfully added")
            .add_mac_algorithm(algorithms::mac::HmacSha2256::new())
            .expect("mac algorithm could not be successfully added")
            .add_compression_algorithm(algorithms::compression::None::new())
            .expect("compression algorithm could not be successfully added");

        builder
            .algorithms(algorithms)
            .load_host_key("ssh-ed25519", &random_ed25519_host_key())
            .expect("host key could not be successfully loaded")
    })
    .await;
}

/// Tests a combination of combined encryption and mac algorithms as server against the OpenSSH client.
#[tokio::test]
async fn combined_encryption_mac_client_with_openssh() {
    test_client_against_openssh(|builder| {
        let mut algorithms = ConnectionAlgorithms::new();
        algorithms
            .add_host_key_algorithm(algorithms::host_key::Ed25519::new())
            .expect("host key algorithm could not be successfully added")
            .add_key_exchange_algorithm(algorithms::key_exchange::Curve25519Sha256::new())
            .expect("key exchange algorithm could not be successfully added")
            .add_encryption_algorithm(algorithms::encryption::None::new())
            .expect("encryption algorithm could not be successfully added")
            .add_encryption_algorithm(algorithms::encryption::ChaCha20Poly1305::new())
            .expect("encryption algorithm could not be successfully added")
            .add_mac_algorithm(algorithms::mac::None::new())
            .expect("mac algorithm could not be successfully added")
            .add_compression_algorithm(algorithms::compression::None::new())
            .expect("compression algorithm could not be successfully added");

        builder.algorithms(algorithms)
    })
    .await;
}

/// Tests a combination of combined encryption and mac algorithms as server against the OpenSSH client.
#[tokio::test]
async fn combined_encryption_mac_server_with_openssh() {
    test_server_against_openssh(|builder| {
        let mut algorithms = ConnectionAlgorithms::new();
        algorithms
            .add_host_key_algorithm(algorithms::host_key::Ed25519::new())
            .expect("host key algorithm could not be successfully added")
            .add_key_exchange_algorithm(algorithms::key_exchange::Curve25519Sha256::new())
            .expect("key exchange algorithm could not be successfully added")
            .add_encryption_algorithm(algorithms::encryption::None::new())
            .expect("encryption algorithm could not be successfully added")
            .add_encryption_algorithm(algorithms::encryption::ChaCha20Poly1305::new())
            .expect("encryption algorithm could not be successfully added")
            .add_mac_algorithm(algorithms::mac::None::new())
            .expect("mac algorithm could not be successfully added")
            .add_compression_algorithm(algorithms::compression::None::new())
            .expect("compression algorithm could not be successfully added");

        builder
            .algorithms(algorithms)
            .load_host_key("ssh-ed25519", &random_ed25519_host_key())
            .expect("host key could not be successfully loaded")
    })
    .await;
}
