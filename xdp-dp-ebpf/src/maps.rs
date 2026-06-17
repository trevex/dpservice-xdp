use aya_ebpf::{
    macros::map,
    maps::{Array, HashMap},
};
use xdp_dp_common::{Config, IfaceKey, IfaceValue, PortMeta, RouteKey, RouteValue};

#[map]
pub static INTERFACES: HashMap<IfaceKey, IfaceValue> = HashMap::with_max_entries(1024, 0);
#[map]
pub static ROUTES: HashMap<RouteKey, RouteValue> = HashMap::with_max_entries(4096, 0);
#[map]
pub static CONFIG: Array<Config> = Array::with_max_entries(1, 0);
#[map]
pub static PORT_META: HashMap<u32, PortMeta> = HashMap::with_max_entries(1024, 0);
