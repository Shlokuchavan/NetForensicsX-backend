
from fastapi import APIRouter

from app.api.routes.cases import router as cases_router
from app.api.routes.evidence import router as evidence_router
from app.api.routes.flows import router as flows_router
from app.api.routes.hosts import router as hosts_router
from app.api.routes.topology import router as topology_router
from app.api.routes.dns import router as dns_router
from app.api.routes.http import router as http_router
from app.api.routes.tls import router as tls_router
from app.api.routes.detections import router as detections_router
from app.api.routes.iocs import router as iocs_router
from app.api.routes.timeline import router as timeline_router
from app.api.routes.mitre import router as mitre_router

from app.api.routes import network_graph, reports, case_activity

from app.api.routes.file_forensics import router as file_forensics_router
from app.api.routes.incident_reasoning import router as incident_reasoning_router


api_router = APIRouter(prefix="/api/v1")


def add_routes(source_router: APIRouter) -> None:
    for route in source_router.routes:
        api_router.add_api_route(
            route.path,
            route.endpoint,
            methods=list(route.methods or []),
            response_model=getattr(route, "response_model", None),
            status_code=getattr(route, "status_code", None),
            tags=list(getattr(route, "tags", None) or []),
            dependencies=list(getattr(route, "dependencies", None) or []),
            summary=getattr(route, "summary", None),
            description=getattr(route, "description", None),
            response_description=getattr(
                route, "response_description", "Successful Response"
            ),
            deprecated=getattr(route, "deprecated", None),
            operation_id=getattr(route, "operation_id", None),
        )


add_routes(cases_router)
add_routes(evidence_router)
add_routes(flows_router)
add_routes(hosts_router)
add_routes(topology_router)
add_routes(dns_router)
add_routes(http_router)
add_routes(tls_router)
add_routes(detections_router)
add_routes(iocs_router)
add_routes(timeline_router)
add_routes(mitre_router)

add_routes(file_forensics_router)
add_routes(incident_reasoning_router)

# Register these modules only if they actually expose an APIRouter.
for route_module in (network_graph, reports, case_activity):
    module_router = getattr(route_module, "router", None)
    if isinstance(module_router, APIRouter):
        add_routes(module_router)