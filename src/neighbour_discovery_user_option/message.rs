// SPDX-License-Identifier: MIT

use anyhow::Context as _;
use netlink_packet_utils::{
    traits::{Emitable, Parseable},
    DecodeError,
};

use super::{
    buffer::{
        NeighbourDiscoveryUserOptionMessageBuffer,
        NEIGHBOUR_DISCOVERY_USER_OPTION_HEADER_LEN,
    },
    header::NeighbourDiscoveryUserOptionHeader,
    nla::Nla,
};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum NeighbourDiscoveryIcmpType {
    RouterSolicitation,
    RouterAdvertisement,
    NeighbourSolicitation,
    NeighbourAdvertisement,
    Redirect,
    Other(u8),
}

impl From<u8> for NeighbourDiscoveryIcmpType {
    fn from(value: u8) -> Self {
        match value {
            133 => NeighbourDiscoveryIcmpType::RouterSolicitation,
            134 => NeighbourDiscoveryIcmpType::RouterAdvertisement,
            135 => NeighbourDiscoveryIcmpType::NeighbourSolicitation,
            136 => NeighbourDiscoveryIcmpType::NeighbourAdvertisement,
            137 => NeighbourDiscoveryIcmpType::Redirect,
            _ => NeighbourDiscoveryIcmpType::Other(value),
        }
    }
}

impl From<NeighbourDiscoveryIcmpType> for u8 {
    fn from(value: NeighbourDiscoveryIcmpType) -> Self {
        match value {
            NeighbourDiscoveryIcmpType::RouterSolicitation => 133,
            NeighbourDiscoveryIcmpType::RouterAdvertisement => 134,
            NeighbourDiscoveryIcmpType::NeighbourSolicitation => 135,
            NeighbourDiscoveryIcmpType::NeighbourAdvertisement => 136,
            NeighbourDiscoveryIcmpType::Redirect => 137,
            NeighbourDiscoveryIcmpType::Other(value) => value,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct NeighbourDiscoveryUserOptionMessage {
    /// The header of the ND_USEROPT message.
    pub header: NeighbourDiscoveryUserOptionHeader,

    /// The body of the NDP option as it was on the wire.
    pub option_body: Vec<u8>,

    pub attributes: Vec<Nla>,
}

impl NeighbourDiscoveryUserOptionMessage {
    pub fn new(
        header: NeighbourDiscoveryUserOptionHeader,
        option_body: Vec<u8>,
        attributes: Vec<Nla>,
    ) -> Self {
        Self {
            header,
            option_body,
            attributes,
        }
    }
}

impl Emitable for NeighbourDiscoveryUserOptionMessage {
    fn buffer_len(&self) -> usize {
        NEIGHBOUR_DISCOVERY_USER_OPTION_HEADER_LEN
            + self.option_body.len()
            + self
                .attributes
                .iter()
                .map(|nla| nla.buffer_len())
                .sum::<usize>()
    }

    fn emit(&self, buffer: &mut [u8]) {
        let Self {
            header:
                NeighbourDiscoveryUserOptionHeader {
                    family,
                    interface_index,
                    icmp_type,
                },
            option_body,
            attributes,
        } = self;

        let mut packet = NeighbourDiscoveryUserOptionMessageBuffer::new(buffer);

        packet.set_address_family((*family).into());

        let payload = packet.payload_mut();
        payload[..option_body.len()].copy_from_slice(&option_body[..]);
        attributes
            .as_slice()
            .emit(&mut payload[option_body.len()..]);

        packet
            .set_options_length(u16::try_from(option_body.len()).expect(
                "neighbor discovery options length doesn't fit in u16",
            ));
        packet.set_interface_index(*interface_index);
        packet.set_icmp_type((*icmp_type).into());

        // All existing options use code 0.
        packet.set_icmp_code(0);
    }
}

impl<'a, T: AsRef<[u8]> + 'a>
    Parseable<NeighbourDiscoveryUserOptionMessageBuffer<&'a T>>
    for NeighbourDiscoveryUserOptionMessage
{
    fn parse(
        buf: &NeighbourDiscoveryUserOptionMessageBuffer<&'a T>,
    ) -> Result<Self, DecodeError> {
        let header = NeighbourDiscoveryUserOptionHeader::parse(buf).context(
            "failed to parse NeighbourDiscoveryUserOption message header",
        )?;

        let mut nlas = Vec::new();
        for nla_buf in buf.nlas() {
            nlas.push(Nla::parse(&nla_buf?)?);
        }

        Ok(NeighbourDiscoveryUserOptionMessage {
            header,
            option_body: buf.option_body().to_vec(),
            attributes: nlas,
        })
    }
}
