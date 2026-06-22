//! Context-neutral verdict returned by the pure datapath core. Each glue layer (XDP, tc) maps
//! it to that program type's concrete return code and performs the redirect/tail-call. Keeping
//! this enum free of `xdp_action`/`TC_ACT_*` constants is what lets one core serve both.

/// `ifindex` payloads are interface indices; `Reflect` means "send the (rewritten in place)
/// packet back out the interface it arrived on" (a responder reply to the guest).
pub enum Verdict {
    Pass,
    Drop,
    Redirect(u32),
    Reflect,
    TailCallDhcp,
}
