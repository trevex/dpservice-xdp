use aya_ebpf::{
    macros::map,
    maps::{Array, HashMap, LruHashMap},
};
use xdp_dp_common::{
    Config, CtKey, CtVal, IfaceKey, IfaceValue, InspectEntry, LbKey, LbValue, Local, MaglevKey,
    NatCtVal, NatKey, NatValue, PortMeta, RouteKey, RouteValue, VipKey,
};

#[map]
pub static INTERFACES: HashMap<IfaceKey, IfaceValue> = HashMap::with_max_entries(1024, 0);
#[map]
pub static ROUTES: HashMap<RouteKey, RouteValue> = HashMap::with_max_entries(4096, 0);
#[map]
pub static CONFIG: Array<Config> = Array::with_max_entries(1, 0);
#[map]
pub static PORT_META: HashMap<u32, PortMeta> = HashMap::with_max_entries(1024, 0);
#[map]
pub static LOCAL: Array<Local> = Array::with_max_entries(1, 0);
#[map]
pub static INSPECT: Array<InspectEntry> = Array::with_max_entries(1, 0);
/// 1:1 VIP map. Value is the mapped IPv4 counterpart: (vni,G)->V for egress SNAT, (vni,V)->G for
/// ingress DNAT.
#[map]
pub static VIPS: HashMap<VipKey, [u8; 4]> = HashMap::with_max_entries(1024, 0);
#[map]
pub static LB: HashMap<LbKey, LbValue> = HashMap::with_max_entries(1024, 0);
#[map]
pub static MAGLEV: HashMap<MaglevKey, [u8; 4]> = HashMap::with_max_entries(65536, 0);
#[map]
pub static CONNTRACK: LruHashMap<CtKey, CtVal> = LruHashMap::with_max_entries(65536, 0);
#[map]
pub static NAT: HashMap<NatKey, NatValue> = HashMap::with_max_entries(1024, 0);
#[map]
pub static NAT_CT: LruHashMap<CtKey, NatCtVal> = LruHashMap::with_max_entries(65536, 0);
