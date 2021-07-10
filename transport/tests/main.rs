use russh_transport::{Builder, ConnectionRole};

mod openssh;

// Since tokios into_split method does not seem to work here, a macro is used instead of a function
macro_rules! builder {
    (client <=> sshd; out: { $builder:ident, $sshd:ident}) => {
        let $sshd = openssh::Sshd::launch().await;

        let mut stream =
            tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, $sshd.port))
                .await
                .expect("tcp connection to sshd could not be opened");
        let (read, write) = stream.split();

        let $builder = Builder::new(read, write, ConnectionRole::Client);
    };
    (server <=> ssh; out: { $builder:ident, $ssh:ident}) => {
        let port = portpicker::pick_unused_port().expect("no free port found");

        let mut listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .expect("could not open tcp listener");

        let $ssh = openssh::Ssh::launch(port).await;

        let (mut stream, _peer_addr) = listener
            .accept()
            .await
            .expect("could not accept a connection");
        let (read, write) = stream.split();

        let $builder = Builder::new(read, write, ConnectionRole::Server);
    };
}

#[tokio::test]
async fn default_client_with_openssh() {
    builder!(client <=> sshd;
        out: { builder, sshd }
    );

    let handler = builder
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

#[tokio::test]
async fn default_server_with_openssh() {
    builder!(server <=> ssh;
        out: { builder, ssh }
    );

    let ed25519_key = ed25519_dalek::Keypair::generate(&mut rand::thread_rng()).to_bytes();

    builder
        .load_host_key("ssh-ed25519", &ed25519_key)
        .expect("host key could not be successfully loaded")
        .build()
        .await
        .expect("server could not successfully exchange keys with ssh");

    let output = ssh
        .run_to_completion()
        .await
        .expect("could not read output from ssh");

    assert!(output.contains("SSH2_MSG_NEWKEYS received"));
}
