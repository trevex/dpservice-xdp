use std::sync::Arc;

use tonic::{Request, Response, Status};

use crate::control::Control;
use crate::pb::dpd_kironcore_server::DpdKironcore;
use crate::pb::{
    CaptureStartRequest, CaptureStartResponse, CaptureStatusRequest, CaptureStatusResponse,
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
    DeleteVipResponse, GetFirewallRuleRequest, GetFirewallRuleResponse, GetInterfaceRequest,
    GetInterfaceResponse, GetLoadBalancerRequest, GetLoadBalancerResponse, GetNatRequest,
    GetNatResponse, GetVersionRequest, GetVersionResponse, GetVipRequest, GetVipResponse,
    InitializeRequest, InitializeResponse, IpAddress, IpVersion, ListFirewallRulesRequest,
    ListFirewallRulesResponse, ListInterfacesRequest, ListInterfacesResponse,
    ListLoadBalancerPrefixesRequest, ListLoadBalancerPrefixesResponse,
    ListLoadBalancerTargetsRequest, ListLoadBalancerTargetsResponse, ListLoadBalancersRequest,
    ListLoadBalancersResponse, ListLocalNatsRequest, ListLocalNatsResponse,
    ListNeighborNatsRequest, ListNeighborNatsResponse, ListPrefixesRequest, ListPrefixesResponse,
    ListRoutesRequest, ListRoutesResponse, ResetVniRequest, ResetVniResponse, Status as DpStatus,
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
        let underlay = self.underlay;

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
        _req: Request<ListPrefixesRequest>,
    ) -> Result<Response<ListPrefixesResponse>, Status> {
        Err(Status::unimplemented("not implemented"))
    }

    async fn create_prefix(
        &self,
        _req: Request<CreatePrefixRequest>,
    ) -> Result<Response<CreatePrefixResponse>, Status> {
        Err(Status::unimplemented("not implemented"))
    }

    async fn delete_prefix(
        &self,
        _req: Request<DeletePrefixRequest>,
    ) -> Result<Response<DeletePrefixResponse>, Status> {
        Err(Status::unimplemented("not implemented"))
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
        control
            .create_lb(&r.loadbalancer_id, r.vni, ip, ports)
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(CreateLoadBalancerResponse {
            status: ok(),
            underlay_route: self.underlay.to_vec(),
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
        req: Request<CreateLoadBalancerTargetRequest>,
    ) -> Result<Response<CreateLoadBalancerTargetResponse>, Status> {
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("datapath not initialized"))?;
        let r = req.into_inner();
        let tgt = r
            .target_ip
            .ok_or_else(|| Status::invalid_argument("target_ip is required"))?;
        let backend = decode_ipv4(&tgt.address)?;
        control
            .add_lb_target(&r.loadbalancer_id, backend)
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(CreateLoadBalancerTargetResponse {
            status: ok(),
        }))
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
        _req: Request<CreateNatRequest>,
    ) -> Result<Response<CreateNatResponse>, Status> {
        Err(Status::unimplemented("not implemented"))
    }

    async fn get_nat(
        &self,
        _req: Request<GetNatRequest>,
    ) -> Result<Response<GetNatResponse>, Status> {
        Err(Status::unimplemented("not implemented"))
    }

    async fn delete_nat(
        &self,
        _req: Request<DeleteNatRequest>,
    ) -> Result<Response<DeleteNatResponse>, Status> {
        Err(Status::unimplemented("not implemented"))
    }

    async fn list_local_nats(
        &self,
        _req: Request<ListLocalNatsRequest>,
    ) -> Result<Response<ListLocalNatsResponse>, Status> {
        Err(Status::unimplemented("not implemented"))
    }

    async fn create_neighbor_nat(
        &self,
        _req: Request<CreateNeighborNatRequest>,
    ) -> Result<Response<CreateNeighborNatResponse>, Status> {
        Err(Status::unimplemented("not implemented"))
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
        _req: Request<ListFirewallRulesRequest>,
    ) -> Result<Response<ListFirewallRulesResponse>, Status> {
        Err(Status::unimplemented("not implemented"))
    }

    async fn create_firewall_rule(
        &self,
        _req: Request<CreateFirewallRuleRequest>,
    ) -> Result<Response<CreateFirewallRuleResponse>, Status> {
        Err(Status::unimplemented("not implemented"))
    }

    async fn get_firewall_rule(
        &self,
        _req: Request<GetFirewallRuleRequest>,
    ) -> Result<Response<GetFirewallRuleResponse>, Status> {
        Err(Status::unimplemented("not implemented"))
    }

    async fn delete_firewall_rule(
        &self,
        _req: Request<DeleteFirewallRuleRequest>,
    ) -> Result<Response<DeleteFirewallRuleResponse>, Status> {
        Err(Status::unimplemented("not implemented"))
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
