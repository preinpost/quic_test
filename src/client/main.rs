use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::time::Instant;
use quiche::{ConnectionId, SendInfo};
use quiche::Error::Done;
use env_logger::Env;
use ring::rand::{SecureRandom, SystemRandom};
use log::{debug, error, info, LevelFilter, trace, warn};

const MAX_DATAGRAM_SIZE: usize = 1350;

fn main() -> std::io::Result<()> {

    let mut buf = [0; 65535];

    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .init();

    let mut out = [0; MAX_DATAGRAM_SIZE];

    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    config.set_application_protos(quiche::h3::APPLICATION_PROTOCOL).unwrap();

    let mut http3_conn = None;

    // Client connection.
    let socket = UdpSocket::bind("0.0.0.0:0").expect("couldn't bind to address");
    let peer_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127,0,0,1)), 8080);


    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
    SystemRandom::new().fill(&mut scid[..]).unwrap();

    let scid = quiche::ConnectionId::from_ref(&scid);

    // Get local address.
    let local_addr = socket.local_addr().unwrap();

    // Create a QUIC connection and initiate handshake.
    let mut conn =
        quiche::connect(Some("echo"), &scid, local_addr, peer_addr, &mut config)
            .unwrap();

    info!(
        "connecting to {:} from {:} with scid {}",
        peer_addr,
        socket.local_addr().unwrap(),
        hex_dump(&scid)
    );

    let msg = "hello";

    // for (i, &byte) in msg.as_bytes().iter().enumerate() {
    //     out[i] = byte;
    // }

    let (write, send_info) = conn.send(&mut out).expect("initial send failed");

    while let Err(e) = socket.send_to(&out[..write], send_info.to) {
        if e.kind() == std::io::ErrorKind::WouldBlock {
            debug!("send() would block");
            continue;
        }

        panic!("send() failed: {:?}", e);
    }

    debug!("written {}", write);

    let h3_config = quiche::h3::Config::new().unwrap();

    // Prepare request.
    let req = vec![
        quiche::h3::Header::new(b":method", b"GET"),
        quiche::h3::Header::new(b"user-agent", b"quiche"),
    ];

    let req_start = std::time::Instant::now();

    let mut req_sent = false;


    let (len, from) = match socket.recv_from(&mut buf) {
        Ok(v) => v,

        Err(e) => {
            // There are no more UDP packets to read, so end the read
            // loop.
            if e.kind() == std::io::ErrorKind::WouldBlock {
                debug!("recv() would block");
            }

            panic!("recv() failed: {:?}", e);
        },
    };

    debug!("got {} bytes", len);

    let recv_info = quiche::RecvInfo {
        to: local_addr,
        from,
    };

    // Process potentially coalesced packets.
    let read = match conn.recv(&mut buf[..len], recv_info) {
        Ok(v) => v,

        Err(e) => {
            error!("recv failed: {:?}", e);
            0
        },
    };

    debug!("processed {} bytes", read);

    if conn.is_closed() {
        info!("connection closed, {:?}", conn.stats());
    }

    // Create a new HTTP/3 connection once the QUIC connection is established.
    if conn.is_established() && http3_conn.is_none() {
        http3_conn = Some(
            quiche::h3::Connection::with_transport(&mut conn, &h3_config)
                .expect("Unable to create HTTP/3 connection, check the server's uni stream limit and window size"),
        );
    }

    // Send HTTP requests once the QUIC connection is established, and until
    // all requests have been sent.
    if let Some(h3_conn) = &mut http3_conn {
        if !req_sent {
            info!("sending HTTP request {:?}", req);

            h3_conn.send_request(&mut conn, &req, true).unwrap();

            req_sent = true;
        }
    }

    Ok(())
}

fn hex_dump(buf: &[u8]) -> String {
    let vec: Vec<String> = buf.iter().map(|b| format!("{b:02x}")).collect();

    vec.join("")
}