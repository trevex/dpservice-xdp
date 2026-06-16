use std::sync::Arc;

use tonic::{Request, Response, Status};

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
    InitializeRequest, InitializeResponse, ListFirewallRulesRequest, ListFirewallRulesResponse,
    ListInterfacesRequest, ListInterfacesResponse, ListLoadBalancerPrefixesRequest,
    ListLoadBalancerPrefixesResponse, ListLoadBalancerTargetsRequest,
    ListLoadBalancerTargetsResponse, ListLoadBalancersRequest, ListLoadBalancersResponse,
    ListLocalNatsRequest, ListLocalNatsResponse, ListNeighborNatsRequest, ListNeighborNatsResponse,
    ListPrefixesRequest, ListPrefixesResponse, ListRoutesRequest, ListRoutesResponse,
    ResetVniRequest, ResetVniResponse, Status as DpStatus,
};
use crate::state::State;

pub struct Service {
    pub state: Arc<State>,
}

fn ok() -> Option<DpStatus> {
    Some(DpStatus {
        code: 0,
        message: "OK".into(),
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

    async fn create_interface(
        &self,
        _req: Request<CreateInterfaceRequest>,
    ) -> Result<Response<CreateInterfaceResponse>, Status> {
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
        Err(Status::unimplemented("not implemented"))
    }

    async fn delete_load_balancer_prefix(
        &self,
        _req: Request<DeleteLoadBalancerPrefixRequest>,
    ) -> Result<Response<DeleteLoadBalancerPrefixResponse>, Status> {
        Err(Status::unimplemented("not implemented"))
    }

    async fn create_vip(
        &self,
        _req: Request<CreateVipRequest>,
    ) -> Result<Response<CreateVipResponse>, Status> {
        Err(Status::unimplemented("not implemented"))
    }

    async fn get_vip(
        &self,
        _req: Request<GetVipRequest>,
    ) -> Result<Response<GetVipResponse>, Status> {
        Err(Status::unimplemented("not implemented"))
    }

    async fn delete_vip(
        &self,
        _req: Request<DeleteVipRequest>,
    ) -> Result<Response<DeleteVipResponse>, Status> {
        Err(Status::unimplemented("not implemented"))
    }

    async fn create_load_balancer(
        &self,
        _req: Request<CreateLoadBalancerRequest>,
    ) -> Result<Response<CreateLoadBalancerResponse>, Status> {
        Err(Status::unimplemented("not implemented"))
    }

    async fn get_load_balancer(
        &self,
        _req: Request<GetLoadBalancerRequest>,
    ) -> Result<Response<GetLoadBalancerResponse>, Status> {
        Err(Status::unimplemented("not implemented"))
    }

    async fn delete_load_balancer(
        &self,
        _req: Request<DeleteLoadBalancerRequest>,
    ) -> Result<Response<DeleteLoadBalancerResponse>, Status> {
        Err(Status::unimplemented("not implemented"))
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
        Err(Status::unimplemented("not implemented"))
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

    async fn create_route(
        &self,
        _req: Request<CreateRouteRequest>,
    ) -> Result<Response<CreateRouteResponse>, Status> {
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
