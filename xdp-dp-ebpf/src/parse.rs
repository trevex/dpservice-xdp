pub const ETH_LEN: usize = 14;
pub const IPV6_LEN: usize = 40;
pub const ETH_P_IP: u16 = 0x0800;
pub const ETH_P_IPV6: u16 = 0x86DD;
pub const ETH_P_ARP: u16 = 0x0806;
pub const IPPROTO_IPIP: u8 = 4; // IPv4 encapsulated in IPv6 (outer next-header)

#[inline(always)]
pub unsafe fn write6(dst: *mut u8, src: &[u8; 6]) {
    let mut i = 0;
    while i < 6 {
        *dst.add(i) = src[i];
        i += 1;
    }
}

#[inline(always)]
pub unsafe fn write16(dst: *mut u8, src: &[u8; 16]) {
    let mut i = 0;
    while i < 16 {
        *dst.add(i) = src[i];
        i += 1;
    }
}
