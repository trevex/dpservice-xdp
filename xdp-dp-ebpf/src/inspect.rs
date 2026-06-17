use aya_ebpf::{bindings::xdp_action, programs::XdpContext};

use crate::maps::INSPECT;

pub fn try_inspect(ctx: &XdpContext) -> u32 {
    let data = ctx.data();
    let data_end = ctx.data_end();
    let pkt_len = (data_end - data) as u32;

    // We can only safely read up to min(pkt_len, 32) bytes.
    let copy_len = if pkt_len < 32 { pkt_len } else { 32 };

    if let Some(entry) = INSPECT.get_ptr_mut(0) {
        unsafe {
            (*entry).len = pkt_len;
            (*entry).seen = (*entry).seen.wrapping_add(1);

            // Copy up to 32 bytes; the verifier needs a bounds-checked loop.
            let src = data as *const u8;
            let mut i = 0u32;
            while i < 32 {
                if i < copy_len && data + i as usize + 1 <= data_end {
                    (*entry).bytes[i as usize] = *src.add(i as usize);
                } else {
                    (*entry).bytes[i as usize] = 0;
                }
                i += 1;
            }
        }
    }

    xdp_action::XDP_PASS
}
