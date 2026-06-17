use std::sync::Arc;

use tonic::{Request, Response, Status};

use crate::control::Control;
use crate::pb::dpd_kironcore_server::DpdKironcore;
use crate::pb::{
    self, CaptureStartRequest, CaptureStartResponse, CaptureStatusRequest, CaptureStatusResponse,
    CaptureStopRequest, CaptureStopResponse, CheckInitializedRequest, CheckInitializedResponse,
    CheckVniInUseRequest, CheckVniInUseResponse, CreateFirewallRuleRequest,
    CreateFirewallRuleResponse, CreateInterfaceRequest, CreateInterfaceResponse,
    CreateLoadBalancerPrefixRequest, CreateLoadBalancerPrefixResponse, CreateLoadBalancerRequest,
    CreateLoadBalancerResponse, CreateLoadBalancerTargetRequest, CreateLoadBalancerTargetResponse,
    CreateNatRequest, CreateNatResponse, CreateNeighborNatRequest, CreateNeighborNatResponse,
    CreatePrefixRequest, CreatePrefixResponse, CreateRouteRequest, CreateRouteResponse,
    CreateVipRequest, CreateVipResponse, DeleteFirewallRuleRequest, DeleteFirewallRuleResponse,
    DeleteInterfaceRequest, DeleteInterfaceResponse, DeleteLoadBalancerPrefixRequest,
    DeleteLoadBalancerPrefixResponse, DeleteLoadBalancerRequest, DeleteLoadBalancerResponse,
    DeleteLoadBalancerTargetRequest, DeleteLoadBalancerTargetResponse, DeleteNatRequest,
    DeleteNatResponse, DeleteNeighborNatRequest, DeleteNeighborNatResponse, DeletePrefixRequest,
    DeletePrefixResponse, DeleteRouteRequest, DeleteRouteResponse, DeleteVipRequest,
    DeleteVipResponse, FirewallAction, FirewallRule, GetFirewallRuleRequest,
    GetFirewallRuleResponse, GetInterfaceRequest, GetInterfaceResponse, GetLoadBalancerRequest,
    GetLoadBalancerResponse, GetNatRequest, GetNatResponse, GetVersionRequest, GetVersionResponse,
    GetVipRequest, GetVipResponse, InitializeRequest, InitializeResponse, IpAddress, IpVersion,
    ListFirewallRulesRequest, ListFirewallRulesResponse, ListInterfacesRequest,
    ListInterfacesResponse, ListLoadBalancerPrefixesRequest, ListLoadBalancerPrefixesResponse,
    ListLoadBalancerTargetsRequest, ListLoadBalancerTargetsResponse, ListLoadBalancersRequest,
    ListLoadBalancersResponse, ListLocalNatsRequest, ListLocalNatsResponse,
    ListNeighborNatsRequest, ListNeighborNatsResponse, ListPrefixesRequest, ListPrefixesResponse,
    ListRoutesRequest, ListRoutesResponse, Prefix, ProtocolFilter, ResetVniRequest,
    ResetVniResponse, Status as DpStatus, TrafficDirection,
};
use crate::state::State;

pub struct Service {
    pub state: Arc<State>,
    /// Live datapath control; `None` when serving without a loaded eBPF object.
    pub control: Option<Arc<Control>>,
    /// This server's underlay IPv6 address, returned in CreateInterface responses.
    pub underlay: [u8; 16],
}

fn ok() -> Option<DpStatus> {
    Some(DpStatus {
        code: 0,
        message: "OK".into(),
    })
}

// ---------------------------------------------------------------------------
// Address-decoding helpers
// ---------------------------------------------------------------------------

/// Convert a `Vec<u8>` into a `[u8; 4]`, returning `Status::invalid_argument` on wrong length.
fn decode_ipv4(bytes: &[u8]) -> Result<[u8; 4], Status> {
    bytes.try_into().map_err(|_| {
        Status::invalid_argument(format!("expected 4-byte IPv4, got {} bytes", bytes.len()))
    })
}

/// Convert a `Vec<u8>` into a `[u8; 16]`, returning `Status::invalid_argument` on wrong length.
fn decode_ipv6(bytes: &[u8]) -> Result<[u8; 16], Status> {
    bytes.try_into().map_err(|_| {
        Status::invalid_argument(format!("expected 16-byte IPv6, got {} bytes", bytes.len()))
    })
}

// ---------------------------------------------------------------------------
// Firewall helpers
// ---------------------------------------------------------------------------

/// Convert a prefix length (0-32) into a big-endian netmask.
fn mask_from_len(len: u32) -> [u8; 4] {
    let len = len.min(32);
    let m: u32 = if len == 0 { 0 } else { u32::MAX << (32 - len) };
    m.to_be_bytes()
}

/// Synthesise a unique rule id from the current wall-clock nanos.
fn gen_rule_id() -> Vec<u8> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    format!("fw-{nanos}").into_bytes()
}

/// Decode a proto `FirewallRule` into the eBPF-level `FwRule`.
fn decode_fw_rule(r: &FirewallRule) -> Result<xdp_dp_common::FwRule, Status> {
    use pb::protocol_filter::Filter;
    use xdp_dp_common::{FW_ACTION_ACCEPT, FW_ACTION_DROP, FW_DIR_EGRESS, FW_DIR_INGRESS};

    let direction = if r.direction == TrafficDirection::Egress as i32 {
        FW_DIR_EGRESS
    } else {
        FW_DIR_INGRESS
    };
    let action = if r.action == FirewallAction::Accept as i32 {
        FW_ACTION_ACCEPT
    } else {
        FW_ACTION_DROP
    };

    let (src_ip, src_mask) = match &r.source_prefix {
        Some(Prefix {
            ip: Some(addr),
            length,
            ..
        }) => (decode_ipv4(&addr.address)?, mask_from_len(*length)),
        _ => ([0u8; 4], [0u8; 4]),
    };
    let (dst_ip, dst_mask) = match &r.destination_prefix {
        Some(Prefix {
            ip: Some(addr),
            length,
            ..
        }) => (decode_ipv4(&addr.address)?, mask_from_len(*length)),
        _ => ([0u8; 4], [0u8; 4]),
    };

    let (proto, src_port_min, src_port_max, dst_port_min, dst_port_max, icmp_type, icmp_code) =
        match r.protocol_filter.as_ref().and_then(|pf| pf.filter.as_ref()) {
            None => (0u8, 0u16, 65535u16, 0u16, 65535u16, 0xffffu16, 0xffffu16),
            Some(Filter::Tcp(f)) => (
                6u8,
                if f.src_port_lower < 0 {
                    0
                } else {
                    f.src_port_lower as u16
                },
                if f.src_port_upper < 0 {
                    65535
                } else {
                    f.src_port_upper as u16
                },
                if f.dst_port_lower < 0 {
                    0
                } else {
                    f.dst_port_lower as u16
                },
                if f.dst_port_upper < 0 {
                    65535
                } else {
                    f.dst_port_upper as u16
                },
                0xffffu16,
                0xffffu16,
            ),
            Some(Filter::Udp(f)) => (
                17u8,
                if f.src_port_lower < 0 {
                    0
                } else {
                    f.src_port_lower as u16
                },
                if f.src_port_upper < 0 {
                    65535
                } else {
                    f.src_port_upper as u16
                },
                if f.dst_port_lower < 0 {
                    0
                } else {
                    f.dst_port_lower as u16
                },
                if f.dst_port_upper < 0 {
                    65535
                } else {
                    f.dst_port_upper as u16
                },
                0xffffu16,
                0xffffu16,
            ),
            Some(Filter::Icmp(f)) => (
                1u8,
                0u16,
                65535u16,
                0u16,
                65535u16,
                if f.icmp_type < 0 {
                    0xffff
                } else {
                    f.icmp_type as u16
                },
                if f.icmp_code < 0 {
                    0xffff
                } else {
                    f.icmp_code as u16
                },
            ),
        };

    Ok(xdp_dp_common::FwRule {
        src_ip,
        src_mask,
        dst_ip,
        dst_mask,
        src_port_min,
        src_port_max,
        dst_port_min,
        dst_port_max,
        icmp_type,
        icmp_code,
        proto,
        action,
        direction,
        enabled: 1,
    })
}

/// Re-encode an eBPF `FwRule` back into a proto `FirewallRule`.
fn encode_fw_rule(rule_id: Vec<u8>, r: xdp_dp_common::FwRule) -> FirewallRule {
    use pb::protocol_filter::Filter;
    use xdp_dp_common::{FW_ACTION_ACCEPT, FW_DIR_EGRESS};

    let direction = if r.direction == FW_DIR_EGRESS {
        TrafficDirection::Egress as i32
    } else {
        TrafficDirection::Ingress as i32
    };
    let action = if r.action == FW_ACTION_ACCEPT {
        FirewallAction::Accept as i32
    } else {
        FirewallAction::Drop as i32
    };

    let source_prefix = if r.src_ip != [0u8; 4] || r.src_mask != [0u8; 4] {
        Some(Prefix {
            ip: Some(IpAddress {
                ipver: IpVersion::Ipv4 as i32,
                address: r.src_ip.to_vec(),
            }),
            length: u32::from_be_bytes(r.src_mask).count_ones(),
            underlay_route: Vec::new(),
        })
    } else {
        None
    };
    let destination_prefix = if r.dst_ip != [0u8; 4] || r.dst_mask != [0u8; 4] {
        Some(Prefix {
            ip: Some(IpAddress {
                ipver: IpVersion::Ipv4 as i32,
                address: r.dst_ip.to_vec(),
            }),
            length: u32::from_be_bytes(r.dst_mask).count_ones(),
            underlay_route: Vec::new(),
        })
    } else {
        None
    };

    let protocol_filter = match r.proto {
        6 => Some(ProtocolFilter {
            filter: Some(Filter::Tcp(pb::TcpFilter {
                src_port_lower: r.src_port_min as i32,
                src_port_upper: r.src_port_max as i32,
                dst_port_lower: r.dst_port_min as i32,
                dst_port_upper: r.dst_port_max as i32,
            })),
        }),
        17 => Some(ProtocolFilter {
            filter: Some(Filter::Udp(pb::UdpFilter {
                src_port_lower: r.src_port_min as i32,
                src_port_upper: r.src_port_max as i32,
                dst_port_lower: r.dst_port_min as i32,
                dst_port_upper: r.dst_port_max as i32,
            })),
        }),
        1 => Some(ProtocolFilter {
            filter: Some(Filter::Icmp(pb::IcmpFilter {
                icmp_type: if r.icmp_type == 0xffff {
                    -1
                } else {
                    r.icmp_type as i32
                },
                icmp_code: if r.icmp_code == 0xffff {
                    -1
                } else {
                    r.icmp_code as i32
                },
            })),
        }),
        _ => None,
    };

    FirewallRule {
        id: rule_id,
        direction,
        action,
        priority: 1000,
        source_prefix,
        destination_prefix,
        protocol_filter,
    }
}

#[tonic::async_trait]
impl DpdKironcore for Service {
    async fn initialize(
        &self,
        _req: Request<InitializeRequest>,
    ) -> Result<Response<InitializeResponse>, Status> {
        let uuid = self.state.initialize();
        Ok(Response::new(InitializeResponse { status: ok(), uuid }))
    }

    async fn check_initialized(
        &self,
        _req: Request<CheckInitializedRequest>,
    ) -> Result<Response<CheckInitializedResponse>, Status> {
        let uuid = self.state.check_initialized().unwrap_or_default();
        Ok(Response::new(CheckInitializedResponse {
            status: ok(),
            uuid,
        }))
    }

    async fn get_version(
        &self,
        req: Request<GetVersionRequest>,
    ) -> Result<Response<GetVersionResponse>, Status> {
        let r = req.into_inner();
        Ok(Response::new(GetVersionResponse {
            status: ok(),
            service_protocol: r.client_protocol,
            service_version: env!("CARGO_PKG_VERSION").into(),
        }))
    }

    // --- CreateInterface ---

    async fn create_interface(
        &self,
        req: Request<CreateInterfaceRequest>,
    ) -> Result<Response<CreateInterfaceResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;

        let r = req.into_inner();

        // Extract IPv4 from ipv4_config.primary_address
        let ipv4_config = r
            .ipv4_config
            .ok_or_else(|| Status::invalid_argument("ipv4_config is required"))?;
        let ipv4 = decode_ipv4(&ipv4_config.primary_address)?;

        // Derive gateway: same /24 prefix but last octet = 1
        let gateway_ipv4 = [ipv4[0], ipv4[1], ipv4[2], 1];

        let interface_id = r.interface_id;
        let device = r.device_name;
        let vni = r.vni;
        // Per-interface underlay /128 from this hypervisor's /64: prefix[0..8] ++ vni ++ ipv4.
        // Unique per (vni, ipv4); deterministic so the route side can reproduce it.
        let mut underlay = self.underlay;
        underlay[8..12].copy_from_slice(&vni.to_be_bytes());
        underlay[12..16].copy_from_slice(&ipv4);

        control
            .create_interface(&interface_id, &device, vni, ipv4, gateway_ipv4, underlay)
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(CreateInterfaceResponse {
            status: ok(),
            underlay_route: underlay.to_vec(),
            vf: None,
        }))
    }

    // --- CreateRoute ---

    async fn create_route(
        &self,
        req: Request<CreateRouteRequest>,
    ) -> Result<Response<CreateRouteResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;

        let r = req.into_inner();
        let vni = r.vni;

        let route = r
            .route
            .ok_or_else(|| Status::invalid_argument("route is required"))?;

        // Decode prefix IPv4
        let prefix = route
            .prefix
            .ok_or_else(|| Status::invalid_argument("route.prefix is required"))?;
        let prefix_len = prefix.length;
        let prefix_ip = prefix
            .ip
            .ok_or_else(|| Status::invalid_argument("route.prefix.ip is required"))?;
        let ipv4 = decode_ipv4(&prefix_ip.address)?;

        // Decode nexthop IPv6
        let nexthop_addr = route
            .nexthop_address
            .ok_or_else(|| Status::invalid_argument("route.nexthop_address is required"))?;
        let nexthop_ipv6 = decode_ipv6(&nexthop_addr.address)?;

        control
            .create_route(vni, ipv4, prefix_len, nexthop_ipv6, false)
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(CreateRouteResponse { status: ok() }))
    }

    // --- stubs ---

    async fn list_interfaces(
        &self,
        _req: Request<ListInterfacesRequest>,
    ) -> Result<Response<ListInterfacesResponse>, Status> {
        Err(Status::unimplemented("not implemented"))
    }

    async fn get_interface(
        &self,
        _req: Request<GetInterfaceRequest>,
    ) -> Result<Response<GetInterfaceResponse>, Status> {
        Err(Status::unimplemented("not implemented"))
    }

    async fn delete_interface(
        &self,
        _req: Request<DeleteInterfaceRequest>,
    ) -> Result<Response<DeleteInterfaceResponse>, Status> {
        Err(Status::unimplemented("not implemented"))
    }

    async fn list_prefixes(
        &self,
        req: Request<ListPrefixesRequest>,
    ) -> Result<Response<ListPrefixesResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        let r = req.into_inner();
        let prefixes = control
            .list_prefixes(&r.interface_id)
            .into_iter()
            .map(|(ip, len)| Prefix {
                ip: Some(IpAddress {
                    ipver: IpVersion::Ipv4 as i32,
                    address: ip.to_vec(),
                }),
                length: len,
                underlay_route: Vec::new(),
            })
            .collect();
        Ok(Response::new(ListPrefixesResponse {
            status: ok(),
            prefixes,
        }))
    }

    async fn create_prefix(
        &self,
        req: Request<CreatePrefixRequest>,
    ) -> Result<Response<CreatePrefixResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        let r = req.into_inner();
        let pfx = r
            .prefix
            .ok_or_else(|| Status::invalid_argument("prefix is required"))?;
        let addr = pfx
            .ip
            .ok_or_else(|| Status::invalid_argument("prefix.ip is required"))?;
        let ip = decode_ipv4(&addr.address)?;
        control
            .add_prefix(&r.interface_id, ip, pfx.length)
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(CreatePrefixResponse {
            status: ok(),
            underlay_route: self.underlay.to_vec(),
        }))
    }

    async fn delete_prefix(
        &self,
        req: Request<DeletePrefixRequest>,
    ) -> Result<Response<DeletePrefixResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        let r = req.into_inner();
        let pfx = r
            .prefix
            .ok_or_else(|| Status::invalid_argument("prefix is required"))?;
        let addr = pfx
            .ip
            .ok_or_else(|| Status::invalid_argument("prefix.ip is required"))?;
        let ip = decode_ipv4(&addr.address)?;
        control
            .del_prefix(&r.interface_id, ip, pfx.length)
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(DeletePrefixResponse { status: ok() }))
    }

    async fn list_load_balancer_prefixes(
        &self,
        _req: Request<ListLoadBalancerPrefixesRequest>,
    ) -> Result<Response<ListLoadBalancerPrefixesResponse>, Status> {
        Err(Status::unimplemented("not implemented"))
    }

    async fn create_load_balancer_prefix(
        &self,
        _req: Request<CreateLoadBalancerPrefixRequest>,
    ) -> Result<Response<CreateLoadBalancerPrefixResponse>, Status> {
        // PoC: LB prefixes are an announce-only concept; accept and return OK. The datapath does
        // not need per-prefix state for the single-tenant local-backend PoC.
        Ok(Response::new(CreateLoadBalancerPrefixResponse {
            status: ok(),
            underlay_route: self.underlay.to_vec(),
        }))
    }

    async fn delete_load_balancer_prefix(
        &self,
        _req: Request<DeleteLoadBalancerPrefixRequest>,
    ) -> Result<Response<DeleteLoadBalancerPrefixResponse>, Status> {
        Err(Status::unimplemented("not implemented"))
    }

    async fn create_vip(
        &self,
        req: Request<CreateVipRequest>,
    ) -> Result<Response<CreateVipResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        let r = req.into_inner();
        let vip_addr = r
            .vip_ip
            .ok_or_else(|| Status::invalid_argument("vip_ip is required"))?;
        let vip = decode_ipv4(&vip_addr.address)?;
        control
            .create_vip(&r.interface_id, vip)
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(CreateVipResponse {
            status: ok(),
            underlay_route: self.underlay.to_vec(),
        }))
    }

    async fn get_vip(
        &self,
        req: Request<GetVipRequest>,
    ) -> Result<Response<GetVipResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        let r = req.into_inner();
        let vip_ip = control.get_vip(&r.interface_id).map(|addr| IpAddress {
            ipver: IpVersion::Ipv4 as i32,
            address: addr.to_vec(),
        });
        Ok(Response::new(GetVipResponse {
            status: ok(),
            vip_ip,
            underlay_route: self.underlay.to_vec(),
        }))
    }

    async fn delete_vip(
        &self,
        req: Request<DeleteVipRequest>,
    ) -> Result<Response<DeleteVipResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        let r = req.into_inner();
        control
            .delete_vip(&r.interface_id)
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(DeleteVipResponse { status: ok() }))
    }

    async fn create_load_balancer(
        &self,
        req: Request<CreateLoadBalancerRequest>,
    ) -> Result<Response<CreateLoadBalancerResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        let r = req.into_inner();
        let lb_addr = r
            .loadbalanced_ip
            .ok_or_else(|| Status::invalid_argument("loadbalanced_ip is required"))?;
        let ip = decode_ipv4(&lb_addr.address)?;
        let ports: Vec<(u16, u8)> = r
            .loadbalanced_ports
            .iter()
            .map(|p| (p.port as u16, p.protocol as u8))
            .collect();
        // Derive a deterministic LB underlay /128: same scheme as create_interface
        // (hypervisor_prefix[0..8] ++ vni_be(4) ++ ipv4(4)).
        let mut lb_underlay = self.underlay;
        lb_underlay[8..12].copy_from_slice(&r.vni.to_be_bytes());
        lb_underlay[12..16].copy_from_slice(&ip);
        control
            .create_lb(&r.loadbalancer_id, r.vni, ip, lb_underlay, ports)
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(CreateLoadBalancerResponse {
            status: ok(),
            underlay_route: lb_underlay.to_vec(),
        }))
    }

    async fn get_load_balancer(
        &self,
        _req: Request<GetLoadBalancerRequest>,
    ) -> Result<Response<GetLoadBalancerResponse>, Status> {
        Err(Status::unimplemented("not implemented"))
    }

    async fn delete_load_balancer(
        &self,
        req: Request<DeleteLoadBalancerRequest>,
    ) -> Result<Response<DeleteLoadBalancerResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        let r = req.into_inner();
        control
            .delete_lb(&r.loadbalancer_id)
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(DeleteLoadBalancerResponse { status: ok() }))
    }

    async fn list_load_balancers(
        &self,
        _req: Request<ListLoadBalancersRequest>,
    ) -> Result<Response<ListLoadBalancersResponse>, Status> {
        Err(Status::unimplemented("not implemented"))
    }

    async fn create_load_balancer_target(
        &self,
        _req: Request<CreateLoadBalancerTargetRequest>,
    ) -> Result<Response<CreateLoadBalancerTargetResponse>, Status> {
        // M9: LB backends are now underlay /128 addresses, but the proto target_ip is an IPv4
        // with no VNI field — not enough information to synthesize a backend underlay via gRPC.
        // LB backend underlay programming via gRPC lands with the ioiab integration (M10+).
        // The CLI bringup path (--lb-target) is used for M9.
        Err(Status::unimplemented(
            "LB target programming via gRPC requires ioiab integration (M10+); use --lb-target CLI flag",
        ))
    }

    async fn list_load_balancer_targets(
        &self,
        _req: Request<ListLoadBalancerTargetsRequest>,
    ) -> Result<Response<ListLoadBalancerTargetsResponse>, Status> {
        Err(Status::unimplemented("not implemented"))
    }

    async fn delete_load_balancer_target(
        &self,
        _req: Request<DeleteLoadBalancerTargetRequest>,
    ) -> Result<Response<DeleteLoadBalancerTargetResponse>, Status> {
        Err(Status::unimplemented("not implemented"))
    }

    async fn create_nat(
        &self,
        req: Request<CreateNatRequest>,
    ) -> Result<Response<CreateNatResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        let r = req.into_inner();
        let nat_addr = r
            .nat_ip
            .ok_or_else(|| Status::invalid_argument("nat_ip is required"))?;
        let nat_ip = decode_ipv4(&nat_addr.address)?;
        control
            .create_nat(
                &r.interface_id,
                nat_ip,
                r.min_port as u16,
                r.max_port as u16,
            )
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(CreateNatResponse {
            status: ok(),
            underlay_route: self.underlay.to_vec(),
        }))
    }

    async fn get_nat(
        &self,
        req: Request<GetNatRequest>,
    ) -> Result<Response<GetNatResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        let r = req.into_inner();
        let (nat_ip, min_port, max_port) =
            control.get_nat(&r.interface_id).unwrap_or(([0u8; 4], 0, 0));
        Ok(Response::new(GetNatResponse {
            status: ok(),
            nat_ip: Some(IpAddress {
                ipver: IpVersion::Ipv4 as i32,
                address: nat_ip.to_vec(),
            }),
            min_port: min_port as u32,
            max_port: max_port as u32,
            underlay_route: self.underlay.to_vec(),
        }))
    }

    async fn delete_nat(
        &self,
        req: Request<DeleteNatRequest>,
    ) -> Result<Response<DeleteNatResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        let r = req.into_inner();
        control
            .delete_nat(&r.interface_id)
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(DeleteNatResponse { status: ok() }))
    }

    async fn list_local_nats(
        &self,
        _req: Request<ListLocalNatsRequest>,
    ) -> Result<Response<ListLocalNatsResponse>, Status> {
        // PoC: the datapath NAT map is authoritative; an enumerating lister is a follow-on.
        Ok(Response::new(ListLocalNatsResponse {
            status: ok(),
            nat_entries: Vec::new(),
        }))
    }

    async fn create_neighbor_nat(
        &self,
        _req: Request<CreateNeighborNatRequest>,
    ) -> Result<Response<CreateNeighborNatResponse>, Status> {
        // Distributed (multi-node) NAT return is out of scope for the single-node PoC; accept + OK.
        Ok(Response::new(CreateNeighborNatResponse { status: ok() }))
    }

    async fn delete_neighbor_nat(
        &self,
        _req: Request<DeleteNeighborNatRequest>,
    ) -> Result<Response<DeleteNeighborNatResponse>, Status> {
        Err(Status::unimplemented("not implemented"))
    }

    async fn list_neighbor_nats(
        &self,
        _req: Request<ListNeighborNatsRequest>,
    ) -> Result<Response<ListNeighborNatsResponse>, Status> {
        Err(Status::unimplemented("not implemented"))
    }

    async fn list_routes(
        &self,
        _req: Request<ListRoutesRequest>,
    ) -> Result<Response<ListRoutesResponse>, Status> {
        Err(Status::unimplemented("not implemented"))
    }

    async fn delete_route(
        &self,
        _req: Request<DeleteRouteRequest>,
    ) -> Result<Response<DeleteRouteResponse>, Status> {
        Err(Status::unimplemented("not implemented"))
    }

    async fn check_vni_in_use(
        &self,
        _req: Request<CheckVniInUseRequest>,
    ) -> Result<Response<CheckVniInUseResponse>, Status> {
        Err(Status::unimplemented("not implemented"))
    }

    async fn reset_vni(
        &self,
        _req: Request<ResetVniRequest>,
    ) -> Result<Response<ResetVniResponse>, Status> {
        Err(Status::unimplemented("not implemented"))
    }

    async fn list_firewall_rules(
        &self,
        req: Request<ListFirewallRulesRequest>,
    ) -> Result<Response<ListFirewallRulesResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        let r = req.into_inner();
        let pairs = control.list_fw_rules(&r.interface_id);
        let rules = pairs
            .into_iter()
            .map(|(id, rule)| encode_fw_rule(id, rule))
            .collect();
        Ok(Response::new(ListFirewallRulesResponse {
            status: ok(),
            rules,
        }))
    }

    async fn create_firewall_rule(
        &self,
        req: Request<CreateFirewallRuleRequest>,
    ) -> Result<Response<CreateFirewallRuleResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        let r = req.into_inner();
        let pbrule = r
            .rule
            .ok_or_else(|| Status::invalid_argument("rule is required"))?;
        let rule_id = if pbrule.id.is_empty() {
            gen_rule_id()
        } else {
            pbrule.id.clone()
        };
        let fw = decode_fw_rule(&pbrule)?;
        control
            .add_fw_rule(&r.interface_id, rule_id.clone(), fw)
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(CreateFirewallRuleResponse {
            status: ok(),
            rule_id,
        }))
    }

    async fn get_firewall_rule(
        &self,
        req: Request<GetFirewallRuleRequest>,
    ) -> Result<Response<GetFirewallRuleResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        let r = req.into_inner();
        let rule = control
            .get_fw_rule(&r.interface_id, &r.rule_id)
            .map(|fw| encode_fw_rule(r.rule_id, fw));
        Ok(Response::new(GetFirewallRuleResponse {
            status: ok(),
            rule,
        }))
    }

    async fn delete_firewall_rule(
        &self,
        req: Request<DeleteFirewallRuleRequest>,
    ) -> Result<Response<DeleteFirewallRuleResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        let r = req.into_inner();
        control
            .del_fw_rule(&r.interface_id, &r.rule_id)
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(DeleteFirewallRuleResponse { status: ok() }))
    }

    async fn capture_start(
        &self,
        _req: Request<CaptureStartRequest>,
    ) -> Result<Response<CaptureStartResponse>, Status> {
        Err(Status::unimplemented("not implemented"))
    }

    async fn capture_stop(
        &self,
        _req: Request<CaptureStopRequest>,
    ) -> Result<Response<CaptureStopResponse>, Status> {
        Err(Status::unimplemented("not implemented"))
    }

    async fn capture_status(
        &self,
        _req: Request<CaptureStatusRequest>,
    ) -> Result<Response<CaptureStatusResponse>, Status> {
        Err(Status::unimplemented("not implemented"))
    }
}

// ---------------------------------------------------------------------------
// Unit tests for address-decoding helpers (no root required)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::{decode_ipv4, decode_ipv6};

    #[test]
    fn decode_ipv4_valid() {
        assert_eq!(decode_ipv4(&[10, 0, 0, 5]).unwrap(), [10u8, 0, 0, 5]);
    }

    #[test]
    fn decode_ipv4_rejects_wrong_length() {
        assert!(decode_ipv4(&[10, 0, 0]).is_err());
        assert!(decode_ipv4(&[10, 0, 0, 5, 6]).is_err());
    }

    #[test]
    fn decode_ipv6_valid() {
        let mut b = [0u8; 16];
        b[0] = 0xfd;
        b[15] = 0x01;
        assert_eq!(decode_ipv6(&b).unwrap(), b);
    }

    #[test]
    fn decode_ipv6_rejects_wrong_length() {
        assert!(decode_ipv6(&[0u8; 4]).is_err());
        assert!(decode_ipv6(&[0u8; 17]).is_err());
    }
}
