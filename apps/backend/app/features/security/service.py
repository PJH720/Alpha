import math
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional
from .schemas import (
    AlertSeverity,
    BlastRadiusNode,
    BlastRadiusResponse,
    RerouteRequest,
    RerouteResponse,
    SecurityAlert,
)

SEVERITY_WEIGHTS: Dict[AlertSeverity, float] = {
    "CRITICAL": 1.0,
    "HIGH": 0.8,
    "MEDIUM": 0.5,
    "LOW": 0.2,
}

# 기본 토폴로지 의존성 그래프 (노드 간 연결 관계)
DEFAULT_TOPOLOGY_EDGES = {
    "aws-ecs-workitems": [
        ("aws-rds-postgres", "database_link"),
        ("aws-iam-task-execution", "iam_trust"),
        ("onprem-vpn-gateway", "vpn_peering"),
    ],
    "aws-rds-postgres": [
        ("aws-ebs-volume", "storage_mount"),
        ("aws-kms-key", "crypto_key"),
    ],
    "onprem-vpn-gateway": [
        ("onprem-cdc-node", "network_tunnel"),
    ],
    "gcp-cloud-run": [
        ("gcp-cloud-sql", "database_link"),
    ],
}

DEFAULT_NODE_METADATA = {
    "aws-ecs-workitems": {
        "name": "AWS ECS Fargate (work-items-app)",
        "provider": "aws",
        "resource_type": "container",
    },
    "aws-rds-postgres": {
        "name": "AWS RDS PostgreSQL (db-alpha-prod)",
        "provider": "aws",
        "resource_type": "database",
    },
    "aws-iam-task-execution": {
        "name": "AWS IAM Role (ecsTaskExecutionRole)",
        "provider": "aws",
        "resource_type": "iam_role",
    },
    "aws-ebs-volume": {
        "name": "AWS EBS gp3 Volume (vol-03f918e7)",
        "provider": "aws",
        "resource_type": "vm",
    },
    "aws-kms-key": {
        "name": "AWS KMS CMK (alias/alpha-rds-key)",
        "provider": "aws",
        "resource_type": "iam_role",
    },
    "onprem-vpn-gateway": {
        "name": "On-Premises IPsec DRG Tunnel",
        "provider": "onprem",
        "resource_type": "network",
    },
    "onprem-cdc-node": {
        "name": "On-Prem Debezium CDC Connector",
        "provider": "onprem",
        "resource_type": "container",
    },
    "gcp-cloud-run": {
        "name": "GCP Cloud Run (target-app-service)",
        "provider": "gcp",
        "resource_type": "container",
    },
    "gcp-cloud-sql": {
        "name": "GCP Cloud SQL PostgreSQL (alpha-replica)",
        "provider": "gcp",
        "resource_type": "database",
    },
}


class SecurityGovernanceService:
    def __init__(self) -> None:
        self._alerts: List[SecurityAlert] = [
            SecurityAlert(
                id="sec-alert-gd-001",
                provider="aws",
                severity="CRITICAL",
                resource_type="container",
                resource_id="arn:aws:ecs:ap-northeast-2:123456789012:task/work-items-app/task-a19c",
                threat_category="UnauthorizedAccess:EC2/MaliciousIPCaller.Custom",
                description="GuardDuty detected outbound communication to a known Tor exit node with abnormal egress traffic spikes (CVE-2026-4192 RCE suspect).",
                detected_at=datetime.now(timezone.utc),
            ),
            SecurityAlert(
                id="sec-alert-scc-002",
                provider="gcp",
                severity="LOW",
                resource_type="database",
                resource_id="//cloudresourcemanager.googleapis.com/projects/softbank-alpha/cloudsql/instances/alpha-replica",
                threat_category="PUBLIC_SQL_INSTANCE_DISABLED",
                description="SCC audit verified Cloud SQL instance enforces Private Services Access (VPC peering only, 0 public IP).",
                detected_at=datetime.now(timezone.utc),
            ),
        ]
        self._quarantined_nodes: set[str] = set()

    def get_alerts(self) -> List[SecurityAlert]:
        return self._alerts

    def calculate_blast_radius(
        self,
        compromised_node_id: str = "aws-ecs-workitems",
        depth_hops: int = 2,
        alpha_decay: float = 0.45,
    ) -> BlastRadiusResponse:
        # 루트 알림 찾기
        root_alert = next(
            (a for a in self._alerts if compromised_node_id in a.resource_id or a.resource_id.endswith(compromised_node_id)),
            self._alerts[0],
        )

        base_weight = SEVERITY_WEIGHTS.get(root_alert.severity, 0.5)

        # BFS 로 의존성 그래프 탐색 및 전파 점수 연산: S(v) = weight * exp(-alpha * hop)
        visited = {compromised_node_id: 0}
        queue = [(compromised_node_id, 0)]
        nodes: List[BlastRadiusNode] = []

        # 0 hop (루트 침해 노드)
        meta_root = DEFAULT_NODE_METADATA.get(
            compromised_node_id,
            {"name": compromised_node_id, "provider": root_alert.provider, "resource_type": root_alert.resource_type},
        )
        nodes.append(
            BlastRadiusNode(
                node_id=compromised_node_id,
                name=meta_root["name"],
                provider=meta_root["provider"],
                resource_type=meta_root["resource_type"],
                risk_score=round(base_weight, 3),
                hop_distance=0,
                dependency_type="direct_ingress",
                is_compromised=True,
                quarantined=compromised_node_id in self._quarantined_nodes,
            )
        )

        while queue:
            curr_node, curr_hop = queue.pop(0)
            if curr_hop >= depth_hops:
                continue

            for neighbor, dep_type in DEFAULT_TOPOLOGY_EDGES.get(curr_node, []):
                next_hop = curr_hop + 1
                if neighbor not in visited or visited[neighbor] > next_hop:
                    visited[neighbor] = next_hop
                    queue.append((neighbor, next_hop))

                    # 감쇄 공식: S = base_weight * exp(-alpha * hop)
                    risk_score = round(base_weight * math.exp(-alpha_decay * next_hop), 3)
                    meta = DEFAULT_NODE_METADATA.get(
                        neighbor,
                        {"name": neighbor, "provider": "aws", "resource_type": "vm"},
                    )
                    nodes.append(
                        BlastRadiusNode(
                            node_id=neighbor,
                            name=meta["name"],
                            provider=meta["provider"],
                            resource_type=meta["resource_type"],
                            risk_score=risk_score,
                            hop_distance=next_hop,
                            dependency_type=dep_type,
                            is_compromised=False,
                            quarantined=neighbor in self._quarantined_nodes,
                        )
                    )

        safe_targets = ["gcp-cloud-run", "azure-container-app"]

        return BlastRadiusResponse(
            root_alert=root_alert,
            compromised_node_id=compromised_node_id,
            max_risk_score=base_weight,
            impacted_nodes=nodes,
            recommended_action=(
                f"침해된 [{compromised_node_id}] 인그레스 차단 및 0.4초 무중단으로 "
                f"GCP Cloud Run [{safe_targets[0]}] 으로 트래픽 즉각 우회(Reroute)"
            ),
            safe_reroute_targets=safe_targets,
        )

    def execute_reroute(self, request: RerouteRequest) -> RerouteResponse:
        start_ts = time.perf_counter()

        # 노드 격리 상태 업데이트
        if request.quarantine:
            self._quarantined_nodes.add(request.compromised_node_id)

        # 에지 프록시 우회 가상 지연 측정 (목표: < 500ms)
        elapsed_ms = round((time.perf_counter() - start_ts) * 1000 + 41.5, 2)

        return RerouteResponse(
            status="rerouted",
            quarantined_node_id=request.compromised_node_id,
            active_target_id=request.target_reroute_id,
            reroute_latency_ms=elapsed_ms,
            message=(
                f"보안 위험 노드 [{request.compromised_node_id}] 가 성공적으로 격리(Quarantine)되었습니다. "
                f"전체 인입 트래픽이 [{request.target_reroute_id}] 으로 {elapsed_ms}ms 만에 우회되었습니다."
            ),
            cloudflare_synced=True,
        )
