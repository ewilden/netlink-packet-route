// SPDX-License-Identifier: MIT

use netlink_packet_utils::Parseable;

use crate::AddressFamily;

use super::buffer::NeighbourDiscoveryUserOptionMessageBuffer;

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

impl<T: AsRef<[u8]>> Parseable<NeighbourDiscoveryUserOptionMessageBuffer<T>>
    for NeighbourDiscoveryUserOptionHeader
{
    fn parse(
        buf: &NeighbourDiscoveryUserOptionMessageBuffer<T>,
    ) -> Result<Self, netlink_packet_utils::DecodeError> {
        Ok(Self {
            family: buf.address_family().into(),
            interface_index: buf.interface_index(),
            icmp_type: buf.icmp_type().into(),
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct NeighbourDiscoveryUserOptionHeader {
    /// Address family of the ND user option. Either [`AF_INET`] or
    /// [`AF_INET6`].
    pub family: AddressFamily,
    /// The index of this ND user option's interface.
    pub interface_index: u32,
    /// The ICMP message type associated with this ND user option. As defined
    /// in RFC 792 for ICMPv4, and RFC 4443 for ICMPv6.
    pub icmp_type: NeighbourDiscoveryIcmpType,
}

impl NeighbourDiscoveryUserOptionHeader {
    pub fn new(
        family: AddressFamily,
        interface_index: u32,
        icmp_type: NeighbourDiscoveryIcmpType,
    ) -> Self {
        Self {
            family,
            interface_index,
            icmp_type,
        }
    }
}
