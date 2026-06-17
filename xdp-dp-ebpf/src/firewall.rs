use xdp_dp_common::{
    fw_rule_matches, FwMeta, FwRule, FwRuleKey, FW_ACTION_ACCEPT, FW_ACTION_DROP, FW_DIR_EGRESS,
    FW_MAX_RULES,
};

use crate::maps::{FW_CONFIG, FW_META, FW_RULES};
use crate::parse::l4_ports;

/// Whether enforcement is enabled (FW_CONFIG[0] != 0; default true when unset).
#[inline(always)]
pub fn fw_enforcing() -> bool {
    match FW_CONFIG.get(0) {
        Some(v) => *v != 0,
        None => true,
    }
}

/// Extract ICMP (type, code) for an IPv4 packet at `ip_off` (0,0 if not ICMP / OOB / has options).
#[inline(always)]
fn icmp_type_code(data: usize, data_end: usize, ip_off: usize) -> (u16, u16) {
    let p = data as *const u8;
    if data + ip_off + 20 > data_end {
        return (0, 0);
    }
    if unsafe { *p.add(ip_off) } & 0x0f != 5 || unsafe { *p.add(ip_off + 9) } != 1 {
        return (0, 0);
    }
    let l4 = ip_off + 20;
    if data + l4 + 2 > data_end {
        return (0, 0);
    }
    (unsafe { *p.add(l4) } as u16, unsafe { *p.add(l4 + 1) }
        as u16)
}

/// Evaluate the firewall for the IPv4 packet at `ip_off` against interface `ifindex` in `dir`
/// (FW_DIR_*). Whitelist: zero rules in this direction => ACCEPT; else the first matching rule's
/// action; no match => DROP. Returns FW_ACTION_ACCEPT / FW_ACTION_DROP.
#[inline(always)]
pub fn fw_eval_dir(data: usize, data_end: usize, ip_off: usize, ifindex: u32, dir: u8) -> u8 {
    let meta: FwMeta = match unsafe { FW_META.get(&ifindex) } {
        Some(m) => *m,
        None => return FW_ACTION_ACCEPT,
    };
    let count = if dir == FW_DIR_EGRESS {
        meta.egress_count
    } else {
        meta.ingress_count
    };
    if count == 0 {
        return FW_ACTION_ACCEPT;
    }
    if data + ip_off + 20 > data_end {
        return FW_ACTION_ACCEPT;
    }
    let p = data as *const u8;
    let src = unsafe { core::ptr::read_unaligned(p.add(ip_off + 12) as *const [u8; 4]) };
    let dst = unsafe { core::ptr::read_unaligned(p.add(ip_off + 16) as *const [u8; 4]) };
    let (proto, sport, dport) = match l4_ports(data, data_end, ip_off) {
        Some(v) => v,
        None => (unsafe { *p.add(ip_off + 9) }, 0u16, 0u16),
    };
    let (itype, icode) = icmp_type_code(data, data_end, ip_off);
    let mut idx: u32 = 0;
    while idx < FW_MAX_RULES {
        if let Some(r) = unsafe { FW_RULES.get(&FwRuleKey { ifindex, idx }) } {
            let r: FwRule = *r;
            if r.direction == dir
                && fw_rule_matches(&r, &src, &dst, proto, sport, dport, itype, icode)
            {
                return r.action;
            }
        }
        idx += 1;
    }
    FW_ACTION_DROP
}
