from pydantic import BaseModel


class TopologyNode(BaseModel):
    id: str
    label: str

    packets: int
    bytes: int

    connections: int


class TopologyEdge(BaseModel):
    id: str

    source: str
    target: str

    protocol: str

    source_port: int | None
    destination_port: int | None

    packets: int
    bytes: int


class NetworkTopologyResponse(BaseModel):
    evidence_id: str

    nodes: list[TopologyNode]
    edges: list[TopologyEdge]

    node_count: int
    edge_count: int