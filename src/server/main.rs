use std::net;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use log::{debug, error, info, trace, warn};
use quiche::ConnectionId;
use ring::rand::SystemRandom;

const MAX_DATAGRAM_SIZE: usize = 1350;

fn main() -> std::io::Result<()> {

    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    env_logger::builder()
        .filter_level(log::LevelFilter::Trace)
        .init();

    let pem_path = "keypair.pem";

    // Server connection.
    let socket = UdpSocket::bind("127.0.0.1:8080").expect("server binding error");

    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

    config
        .load_priv_key_from_pem_file(pem_path).expect("pem not found");

    config
        .load_cert_chain_from_pem_file("cert.crt")
        .expect("crt not found");

    config
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .unwrap();

    config.set_max_idle_timeout(5000);
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_disable_active_migration(true);
    config.enable_early_data();

    let h3_config = quiche::h3::Config::new().unwrap();

    let rng = SystemRandom::new();
    let conn_id_seed =
        ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();

    let local_addr = socket.local_addr().unwrap();

    info!("init server");

    'read: loop {
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

        let pkt_buf = &mut buf[..len];

        // Parse the QUIC packet's header.
        let hdr = match quiche::Header::from_slice(
            pkt_buf,
            quiche::MAX_CONN_ID_LEN,
        ) {
            Ok(v) => v,

            Err(e) => {
                error!("Parsing packet header failed: {:?}", e);
                continue 'read;
            },
        };

        trace!("got packet {:?}", hdr);

        let conn_id = ring::hmac::sign(&conn_id_seed, &hdr.dcid);
        let conn_id = &conn_id.as_ref()[..quiche::MAX_CONN_ID_LEN];
        // let conn_id = conn_id.to_vec().into();

        let mut scid = [0; quiche::MAX_CONN_ID_LEN];
        scid.copy_from_slice(&conn_id);

        let scid = quiche::ConnectionId::from_ref(&scid);

        // Token is always present in Initial packets.
        let token = hdr.token.as_ref().unwrap();
        debug!("token = {:?}", token);


        // Do stateless retry if the client didn't send a token.
        if token.is_empty() {
            warn!("Doing stateless retry");

            let new_token = mint_token(&hdr, &from);

            debug!("new token = {:?}", new_token);

            let len = quiche::retry(
                &hdr.scid,
                &hdr.dcid,
                &scid,
                &new_token,
                hdr.version,
                &mut out,
            )
                .unwrap();

            let out = &out[..len];

            if let Err(e) = socket.send_to(out, from) {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    debug!("send() would block");
                }

                panic!("send() failed: {:?}", e);
            }
            continue 'read;
        }

        let odcid = validate_token(&from, token);


        // The token was not valid, meaning the retry failed, so
        // drop the packet.
        if odcid.is_none() {
            error!("Invalid address validation token");
            continue 'read;
        }

        if scid.len() != hdr.dcid.len() {
            error!("Invalid destination connection ID");
            continue 'read;
        }

        // Reuse the source connection ID we sent in the Retry packet,
        // instead of changing it again.
        let scid = hdr.dcid.clone();

        debug!("New connection: dcid={:?} scid={:?}", hdr.dcid, scid);


        let mut conn = quiche::accept(
            &scid,
            odcid.as_ref(),
            local_addr,
            from,
            &mut config,
        )
            .unwrap();


        let recv_info = quiche::RecvInfo {
            to: socket.local_addr().unwrap(),
            from,
        };

        // Process potentially coalesced packets.
        let read = match conn.recv(pkt_buf, recv_info) {
            Ok(v) => v,

            Err(e) => {
                error!("{} recv failed: {:?}", conn.trace_id(), e);
                continue 'read;
            },
        };

        debug!("{} processed {} bytes", conn.trace_id(), read);

    }
}

fn mint_token(hdr: &quiche::Header, src: &net::SocketAddr) -> Vec<u8> {
    let mut token = Vec::new();

    token.extend_from_slice(b"quiche");

    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    token.extend_from_slice(&addr);
    token.extend_from_slice(&hdr.dcid);

    token
}

fn validate_token<'a>(
    src: &net::SocketAddr, token: &'a [u8],
) -> Option<quiche::ConnectionId<'a>> {
    if token.len() < 6 {
        return None;
    }

    if &token[..6] != b"quiche" {
        return None;
    }

    let token = &token[6..];

    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    if token.len() < addr.len() || &token[..addr.len()] != addr.as_slice() {
        return None;
    }

    Some(quiche::ConnectionId::from_ref(&token[addr.len()..]))
}