// SPDX-License-Identifier: MIT

use netlink_packet_utils::{
    nla::{NlaBuffer, NlasIterator},
    DecodeError,
};

pub const NEIGHBOUR_DISCOVERY_USER_OPTION_HEADER_LEN: usize = 16;

buffer!(NeighbourDiscoveryUserOptionMessageBuffer(NEIGHBOUR_DISCOVERY_USER_OPTION_HEADER_LEN) {
    address_family: (u8, 0),
    padding_1: (u8, 1),
    options_length: (u16, 2..4),
    interface_index: (u32, 4..8),
    icmp_type: (u8, 8),
    icmp_code: (u8, 9),
    padding_2: (u16, 10..12),
    padding_3: (u32, 12..16),
    payload: (slice, NEIGHBOUR_DISCOVERY_USER_OPTION_HEADER_LEN..),
});

impl<'a, T: AsRef<[u8]> + ?Sized>
    NeighbourDiscoveryUserOptionMessageBuffer<&'a T>
{
    pub fn option_body(&self) -> &[u8] {
        &self.payload()[..self.options_length() as usize]
    }

    pub fn nlas(
        &self,
    ) -> impl Iterator<Item = Result<NlaBuffer<&'a [u8]>, DecodeError>> {
        NlasIterator::new(&self.payload()[self.options_length() as usize..])
    }
}
