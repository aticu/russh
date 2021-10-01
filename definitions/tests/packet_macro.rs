use num_bigint::BigInt;
use russh_definitions::{ssh_packet, Compose, Parse};

/// A function for testing that the round trip of composing and parsing results in the same value.
fn roundtrip<'input, 'parse, T: Compose + Parse<'parse> + std::fmt::Debug + Eq>(
    value: &'input T,
    vec: &'parse mut Vec<u8>,
) {
    vec.clear();

    value.compose(vec).unwrap();
    let result = T::parse(vec).unwrap();

    assert_eq!(&result.value, value);
    assert_eq!(&result.rest_input, &[]);
}

#[test]
fn all_types_named_and_const_round_trip() {
    ssh_packet! {
        #[derive(Debug, PartialEq, Eq)]
        struct Packet {
            byte[2]    field1
            byte       field2
            boolean    field3
            uint32     field4
            uint64     field5
            string     field6
            mpint      field7
            name-list  field8
        }

        #[derive(Debug, PartialEq, Eq)]
        struct ConstPacket {
            byte[2]    {[42; 2]}
            byte       {0x42}
            boolean    {true}
            uint32     {1337}
            uint64     {0x1337}
            string     {b"abcdef"}
            mpint      {BigInt::parse_bytes(b"-deadbeef", 16).unwrap()}
            name-list  {["zlib", "none"]}
        }
    }

    assert_eq!(std::mem::size_of::<ConstPacket>(), 0);

    let p = Packet {
        field1: [42; 2],
        field2: 0x42,
        field3: true,
        field4: 1337,
        field5: 0x1337,
        field6: (&b"abcdef"[..]).into(),
        field7: BigInt::parse_bytes(b"-deadbeef", 16).unwrap(),
        field8: vec!["zlib".into(), "none".into()].into(),
        _phantom_lifetime: Default::default(),
    };
    let mut vec = Vec::new();
    roundtrip(&p, &mut vec);

    let pc = ConstPacket {};
    let mut vec2 = Vec::new();
    roundtrip(&pc, &mut vec2);

    assert_eq!(vec.len(), 48);
    assert_eq!(vec, vec2);
}

#[test]
fn cfg_fields() {
    ssh_packet! {
        #[derive(Debug, PartialEq, Eq)]
        struct Packet1 {
            #[cfg(all(foo, not(foo)))]
            uint32   some_field
        }

        #[derive(Debug, PartialEq, Eq)]
        struct Packet2 {
            uint32   some_field
            #[cfg(all(foo, not(foo)))]
            ....     the_rest
        }

        #[derive(Debug, PartialEq, Eq)]
        struct Packet3 {
            #[cfg(all(foo, not(foo)))]
            uint32   {0x12345678}
        }

        #[derive(Debug, PartialEq, Eq)]
        struct Packet4 {
            #[cfg(all(foo, not(foo)))]
            name-list   data
        }
    }

    assert_eq!(std::mem::size_of::<Packet1>(), 0);
    assert_eq!(std::mem::size_of::<Packet4>(), 0);

    let p1 = Packet1 {};
    let mut vec = Vec::new();
    roundtrip(&p1, &mut vec);
    assert_eq!(vec.len(), 0);

    let p2 = Packet2 {
        some_field: 0x12345678,
        _phantom_lifetime: Default::default(),
    };
    let mut vec = Vec::new();
    roundtrip(&p2, &mut vec);
    assert_eq!(vec.len(), 4);

    let result = Packet2::parse(&[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde]).unwrap();
    assert_eq!(result.value, p2);
    assert_eq!(result.rest_input, &[0x9a, 0xbc, 0xde]);

    let p3 = Packet3 {};
    let mut vec = Vec::new();
    roundtrip(&p3, &mut vec);
    assert_eq!(vec.len(), 0);

    let p4 = Packet4 {
        _phantom_lifetime: Default::default(),
    };
    let mut vec = Vec::new();
    roundtrip(&p4, &mut vec);
    assert_eq!(vec.len(), 0);
}

#[test]
fn capturing_of_rest_input() {
    ssh_packet! {
        #[derive(Debug, PartialEq, Eq)]
        struct Packet {
            uint32   some_field
            ....     the_rest
        }
    }

    let result = Packet::parse(&[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde]).unwrap();
    assert_eq!(
        result.value,
        Packet {
            some_field: 0x12345678,
            the_rest: (&[0x9a, 0xbc, 0xde][..]).into(),
            _phantom_lifetime: Default::default(),
        }
    );
    assert_eq!(result.rest_input, &[]);

    roundtrip(&result.value, &mut Vec::new());
}

#[test]
fn mixed_consts_and_named_fields() {
    ssh_packet! {
        #[derive(Debug, PartialEq, Eq)]
        struct Packet1 {
            boolean   field1
            boolean   {false}
            boolean   field2
        }

        #[derive(Debug, PartialEq, Eq)]
        struct Packet2 {
            boolean   {false}
            boolean   field1
            boolean   {false}
        }
    }

    let mut vec = Vec::new();
    let p1 = Packet1::parse(&[1, 0, 1]).unwrap().value;
    roundtrip(&p1, &mut vec);
    assert!(p1.field1 && p1.field2);
    assert_eq!(&vec, &[1, 0, 1]);

    let mut vec = Vec::new();
    let p2 = Packet2::parse(&[0, 1, 0]).unwrap().value;
    roundtrip(&p2, &mut vec);
    assert!(p2.field1);
    assert_eq!(&vec, &[0, 1, 0]);
}

#[test]
fn pub_visibility() {
    mod inner {
        use russh_definitions::ssh_packet;

        ssh_packet! {
            #[derive(Debug, PartialEq, Eq)]
            pub(super) struct Packet {
                boolean   some_field
            }
        }
    }

    let p = inner::Packet { some_field: true };
    roundtrip(&p, &mut Vec::new());
}

#[test]
fn example_kexinit_packet() {
    const SSH_MSG_KEXINIT: u8 = 20;

    ssh_packet! {
        #[derive(Debug, PartialEq, Eq)]
        pub struct KexInit {
            byte         {SSH_MSG_KEXINIT}
            byte[16]     cookie
            name-list    kex_algorithms
            name-list    host_key_algorithms
            name-list    encryption_c2s
            name-list    encryption_s2c
            name-list    mac_c2s
            name-list    mac_s2c
            name-list    compression_c2s
            name-list    compression_s2c
            name-list    languages_c2s
            name-list    languages_s2c
            boolean      first_kex_packet_follows
            uint32       _reserved
        }
    }

    #[rustfmt::skip]
    let input = &[
        SSH_MSG_KEXINIT,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // cookie 0-7
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, // cookie 8-15
        0x00, 0x00, 0x00, 0x11, // kex algorithms
        b'c', b'u', b'r', b'v', b'e', b'2', b'5', b'5', b'1', b'9', b'-',
        b's', b'h', b'a', b'2', b'5', b'6',
        0x00, 0x00, 0x00, 0x13, // host key algorithms
        b's', b's', b'h', b'-', b'r', b's', b'a', b',',
        b's', b's', b'h', b'-', b'e', b'd', b'2', b'5', b'5', b'1', b'9',
        0x00, 0x00, 0x00, 0x0a, // encryption c2s
        b'a', b'e', b's', b'1', b'2', b'8', b'-', b'c', b't', b'r',
        0x00, 0x00, 0x00, 0x0a, // encryption s2c
        b'a', b'e', b's', b'1', b'2', b'8', b'-', b'c', b't', b'r',
        0x00, 0x00, 0x00, 0x09, // mac c2s
        b'h', b'm', b'a', b'c', b'-', b's', b'h', b'a', b'1',
        0x00, 0x00, 0x00, 0x09, // mac s2c
        b'h', b'm', b'a', b'c', b'-', b's', b'h', b'a', b'1',
        0x00, 0x00, 0x00, 0x1a, // compression c2s
        b'n', b'o', b'n', b'e', b',',
        b'z', b'l', b'i', b'b', b'@', b'o', b'p', b'e', b'n', b's', b's', b'h', b'.',
        b'c', b'o', b'm', b',',
        b'z', b'l', b'i', b'b',
        0x00, 0x00, 0x00, 0x09, // compression s2c
        b'n', b'o', b'n', b'e', b',',
        b'z', b'l', b'i', b'b',
        0x00, 0x00, 0x00, 0x00,// languages c2s
        0x00, 0x00, 0x00, 0x00,// languages s2c
        0x00, // first kex packet follows
        0x00, 0x00, 0x00, 0x00,// reserved 0
        ];

    let result = KexInit::parse(input).unwrap();
    assert_eq!(result.rest_input, &[]);
    assert_eq!(
        result.value,
        KexInit {
            cookie: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            kex_algorithms: vec!["curve25519-sha256".into()].into(),
            host_key_algorithms: vec!["ssh-rsa".into(), "ssh-ed25519".into()].into(),
            encryption_c2s: vec!["aes128-ctr".into()].into(),
            encryption_s2c: vec!["aes128-ctr".into()].into(),
            mac_c2s: vec!["hmac-sha1".into()].into(),
            mac_s2c: vec!["hmac-sha1".into()].into(),
            compression_c2s: vec!["none".into(), "zlib@openssh.com".into(), "zlib".into()].into(),
            compression_s2c: vec!["none".into(), "zlib".into()].into(),
            languages_c2s: vec![].into(),
            languages_s2c: vec![].into(),
            first_kex_packet_follows: false,
            _reserved: 0,
            _phantom_lifetime: Default::default(),
        }
    );

    let mut vec = Vec::new();
    roundtrip(&result.value, &mut vec);
    assert_eq!(&vec, input);

    use std::borrow::Cow;
    let result = KexInit::parse(input).unwrap().value;
    assert!(result
        .kex_algorithms
        .iter()
        .all(|s| matches!(s, Cow::Borrowed(_))));
    assert!(result
        .host_key_algorithms
        .iter()
        .all(|s| matches!(s, Cow::Borrowed(_))));
    assert!(result
        .encryption_c2s
        .iter()
        .all(|s| matches!(s, Cow::Borrowed(_))));
    assert!(result
        .encryption_s2c
        .iter()
        .all(|s| matches!(s, Cow::Borrowed(_))));
    assert!(result.mac_c2s.iter().all(|s| matches!(s, Cow::Borrowed(_))));
    assert!(result.mac_s2c.iter().all(|s| matches!(s, Cow::Borrowed(_))));
    assert!(result
        .compression_c2s
        .iter()
        .all(|s| matches!(s, Cow::Borrowed(_))));
    assert!(result
        .compression_s2c
        .iter()
        .all(|s| matches!(s, Cow::Borrowed(_))));
    assert!(result
        .languages_c2s
        .iter()
        .all(|s| matches!(s, Cow::Borrowed(_))));
    assert!(result
        .languages_s2c
        .iter()
        .all(|s| matches!(s, Cow::Borrowed(_))));
}

#[test]
fn example_channel_open_packet() {
    const SSH_MSG_CHANNEL_OPEN: u8 = 90;

    ssh_packet! {
        #[derive(Debug, PartialEq, Eq)]
        struct SessionChannelOpen {
            byte      {SSH_MSG_CHANNEL_OPEN}
            string    {b"session"}
            uint32    sender_channel
            uint32    initial_window_size
            uint32    maximum_packet_size
        }
    }

    #[rustfmt::skip]
    let input = &[
        SSH_MSG_CHANNEL_OPEN,
        0x00, 0x00, 0x00, 0x07, b's', b'e', b's', b's', b'i', b'o', b'n', // "session"
        0x00, 0x00, 0x00, 0x01, // sender channel
        0x00, 0x00, 0x01, 0x00, // initial window size
        0x00, 0x00, 0x04, 0x00, // maximum packet size
    ];

    let result = SessionChannelOpen::parse(input).unwrap();
    assert_eq!(result.rest_input, &[]);
    assert_eq!(
        result.value,
        SessionChannelOpen {
            sender_channel: 1,
            initial_window_size: 256,
            maximum_packet_size: 1024,
        }
    );

    let mut vec = Vec::new();
    roundtrip(&result.value, &mut vec);
    assert_eq!(&vec, input);
}
