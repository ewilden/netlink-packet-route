use netlink_packet_core::{NetlinkHeader, NetlinkMessage};
use netlink_packet_utils::Emitable;

use crate::{
    neighbour_discovery_user_option::{
        header::{
            NeighbourDiscoveryIcmpType, NeighbourDiscoveryUserOptionHeader,
        },
        nla::Nla,
    },
    AddressFamily, RouteNetlinkMessage,
};

use super::NeighbourDiscoveryUserOptionMessage;

#[test]
fn nduseropt() {
    #[rustfmt::skip]
    let data: Vec<u8> = vec![
        // netlink message length + padding
        0x6c, 0x00, 0x00, 0x00,

        // netlink message type (RTM_NEW_NDUSEROPT)
        0x44, 0x00,
        // flags
        0x00, 0x00,
        // seq number
        0x00, 0x00,
        // port number
        0x00, 0x00,

        // family
        0x00, 0x00, 0x00, 0x00,

        // address family (AF_INET6)
        0x0a,


        0x00, 0x38, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

        // === RDNSS option begins here ===

        // RDNSS option type
        0x19,

        // Length of option (in units of 8 octets, including type and length)
        0x07,

        // Padding
        0x00, 0x00,

        // Lifetime for RDNSS addresses
        0x00, 0x12, 0x75, 0x00,

        // First RDNSS address
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,

        // Second RDNSS address
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x53,

        // Third RDNSS address
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x53,

        // === RDNSS option ends here ===

        // NLA header
        0x14, 0x00, 0x01, 0x00,


        // NLA (source link local address)
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ];

    let actual: NetlinkMessage<RouteNetlinkMessage> =
        NetlinkMessage::deserialize(&data[..])
            .expect("deserialize netlink message");

    let want: NetlinkMessage<RouteNetlinkMessage> = NetlinkMessage::new(
        {
            let mut header = NetlinkHeader::default();
            header.length = 0x6c;
            header.message_type = 0x44;
            header
        },
        netlink_packet_core::NetlinkPayload::InnerMessage(
            RouteNetlinkMessage::NewNeighbourDiscoveryUserOption(
                NeighbourDiscoveryUserOptionMessage {
                    header: NeighbourDiscoveryUserOptionHeader {
                        family: AddressFamily::Inet6,
                        interface_index: 2,
                        icmp_type:
                            NeighbourDiscoveryIcmpType::RouterAdvertisement,
                    },
                    option_body: vec![
                        0x19, 0x7, 0x0, 0x0, 0x0, 0x12, 0x75, 0x0, 0x20,
                        0x1, 0xd, 0xb8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                        0x0, 0x0, 0x0, 0x0, 0x1, 0x20, 0x1, 0xd, 0xb8, 0x0,
                        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1,
                        0x53, 0x20, 0x1, 0xd, 0xb8, 0x0, 0x0, 0x0, 0x0,
                        0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x53
                    ],
                    attributes: vec![Nla::SourceLinkLocalAddress(vec![
                        0xfe, 0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
                        0x0, 0x0, 0x0, 0x0, 0x0, 0x1
                    ])]
                }
            )
        )
    );

    assert_eq!(
        actual,
        want,
    );

    let mut actual_buf = vec![0u8; actual.buffer_len()];
    actual.emit(&mut actual_buf);

    let mut want_buf = vec![0u8; want.buffer_len()];
    want.emit(&mut want_buf);

    assert_eq!(actual_buf, want_buf);
    assert_eq!(actual_buf, data);
}
