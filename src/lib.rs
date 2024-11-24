use nom::{
    bytes::complete::{tag, take},
    combinator::{map, verify},
    number::complete::{be_u16, be_u8},
    IResult,
};
use std::net::{Ipv4Addr, Ipv6Addr};

// Proxy Protocol v2 header
#[derive(Debug, PartialEq)]
pub struct PPv2Header {
    pub version: u8,
    pub command: u8,
    pub protocol: u8,
    pub address_family: u8,
    pub length: u16,
}

// IPv4 Address Section
#[derive(Debug, PartialEq)]
pub struct IPv4Address {
    pub source_ip: Ipv4Addr,
    pub destination_ip: Ipv4Addr,
    pub source_port: u16,
    pub destination_port: u16,
}

// IPv6 Address Section
#[derive(Debug, PartialEq)]
pub struct IPv6Address {
    pub source_ip: Ipv6Addr,
    pub destination_ip: Ipv6Addr,
    pub source_port: u16,
    pub destination_port: u16,
}

// Parser for the fixed signature
pub fn parse_signature(input: &[u8]) -> IResult<&[u8], &[u8]> {
    tag(&[
        0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
    ])(input)
}

// Parser for the PPv2 header
pub fn parse_header(input: &[u8]) -> IResult<&[u8], PPv2Header> {
    let (input, _) = parse_signature(input)?;
    let (input, version_command) = verify(be_u8, |&v| (v >> 4) == 2)(input)?;
    let (input, proto_family) = be_u8(input)?;
    let (input, length) = be_u16(input)?;

    let version = version_command >> 4;
    let command = version_command & 0x0F;
    let protocol = proto_family & 0x0F;
    let address_family = proto_family >> 4;

    Ok((
        input,
        PPv2Header {
            version,
            command,
            protocol,
            address_family,
            length,
        },
    ))
}

// Parser for an IPv4 address section
pub fn parse_ipv4_address(input: &[u8]) -> IResult<&[u8], IPv4Address> {
    let (input, source_ip) = map(take(4usize), |b: &[u8]| {
        Ipv4Addr::new(b[0], b[1], b[2], b[3])
    })(input)?;
    let (input, destination_ip) = map(take(4usize), |b: &[u8]| {
        Ipv4Addr::new(b[0], b[1], b[2], b[3])
    })(input)?;
    let (input, source_port) = be_u16(input)?;
    let (input, destination_port) = be_u16(input)?;

    Ok((
        input,
        IPv4Address {
            source_ip,
            destination_ip,
            source_port,
            destination_port,
        },
    ))
}

// Parser for an IPv6 address section
pub fn parse_ipv6_address(input: &[u8]) -> IResult<&[u8], IPv6Address> {
    let (input, source_ip) = map(take(16usize), |b: &[u8]| {
        Ipv6Addr::new(
            (b[0] as u16) << 8 | b[1] as u16,
            (b[2] as u16) << 8 | b[3] as u16,
            (b[4] as u16) << 8 | b[5] as u16,
            (b[6] as u16) << 8 | b[7] as u16,
            (b[8] as u16) << 8 | b[9] as u16,
            (b[10] as u16) << 8 | b[11] as u16,
            (b[12] as u16) << 8 | b[13] as u16,
            (b[14] as u16) << 8 | b[15] as u16,
        )
    })(input)?;
    let (input, destination_ip) = map(take(16usize), |b: &[u8]| {
        Ipv6Addr::new(
            (b[0] as u16) << 8 | b[1] as u16,
            (b[2] as u16) << 8 | b[3] as u16,
            (b[4] as u16) << 8 | b[5] as u16,
            (b[6] as u16) << 8 | b[7] as u16,
            (b[8] as u16) << 8 | b[9] as u16,
            (b[10] as u16) << 8 | b[11] as u16,
            (b[12] as u16) << 8 | b[13] as u16,
            (b[14] as u16) << 8 | b[15] as u16,
        )
    })(input)?;
    let (input, source_port) = be_u16(input)?;
    let (input, destination_port) = be_u16(input)?;

    Ok((
        input,
        IPv6Address {
            source_ip,
            destination_ip,
            source_port,
            destination_port,
        },
    ))
}


#[cfg(test)]
mod test {
    use crate::{parse_header, PPv2Header};

    #[test]
    pub fn test_ppv2_simple() {
        // Example PPv2 binary data for IPv4
        let example_data = [
            0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54,
            0x0A, // Signature
            0x21, // Version 2, PROXY command
            0x11, // TCP over IPv4
            0x00, 0x0C, // Length: 12 bytes (IPv4 address)
            192, 168, 1, 1, // Source IP
            192, 168, 1, 2, // Destination IP
            0x1F, 0x90, // Source Port: 8080
            0x00, 0x50, // Destination Port: 80
        ];

        let (_, header) = parse_header(&example_data).unwrap();
        assert_eq!(
            header,
            PPv2Header {
                version: 2,
                command: 1,
                protocol: 1,
                address_family: 1,
                length: 12
            }
        );
    }
}
