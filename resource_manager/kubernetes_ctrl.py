"""
samsara_ai/orchestration/kubernetes_ctrl.py

Enterprise Kubernetes Controller for Agent Swarm Lifecycle Management
"""

import os
import logging
from kubernetes import client, config, watch
from kubernetes.client.rest import ApiException
from kubernetes.stream import stream
from pydantic import BaseModel, Field, validator
from tenacity import retry, stop_after_attempt, wait_exponential
from prometheus_client import Gauge, Counter, start_http_server
import yaml
import json
import hvac
import threading
import time
from typing import Dict, Optional, List

# Initialize metrics
DEPLOYMENT_GAUGE = Gauge('samsara_k8s_deployments', 'Active deployments', ['cluster', 'namespace'])
SCALING_OPS = Counter('samsara_scaling_operations', 'Auto-scaling events', ['direction'])
ROLLBACK_COUNTER = Counter('samsara_rollbacks', 'Failed deployment rollbacks')
VAULT_ERRORS = Counter('samsara_vault_failures', 'Secret management errors')

logger = logging.getLogger("samsara.k8s")
logging.basicConfig(level=logging.INFO)

class ClusterConfig(BaseModel):
    name: str
    context: str
    priority: int = Field(1, ge=1, le=3)
    resource_quota: Dict[str, str]
    regions: List[str]
    vault_path: str

class DeploymentSpec(BaseModel):
    image: str
    replicas: int = 1
    agent_type: str
    config_map: str
    resources: Dict[str, str]
    autoscaling: Dict[str, int]
    node_affinity: Optional[Dict]

class KubernetesController:
    def __init__(self, clusters: List[ClusterConfig]):
        self.clusters = {c.name: c for c in clusters}
        self.api_instances = {}
        self._init_clients()
        self.watcher = watch.Watch()
        self.lock = threading.RLock()
        self.vault_client = hvac.Client(url=os.getenv('VAULT_ADDR'), token=os.getenv('VAULT_TOKEN'))
        
        # Start metrics server
        start_http_server(9100)

    def _init_clients(self):
        """Initialize multi-cluster API clients with priority-based failover"""
        for name, config in self.clusters.items():
            try:
                ctx = config.context
                kubeconfig = os.path.expanduser(f"~/.kube/config")
                conf = client.Configuration()
                config.load_kube_config(context=ctx, client_configuration=conf)
                
                self.api_instances[name] = {
                    'core': client.CoreV1Api(client.ApiClient(conf)),
                    'apps': client.AppsV1Api(client.ApiClient(conf)),
                    'custom': client.CustomObjectsApi(client.ApiClient(conf))
                }
            except ApiException as e:
                logger.error(f"Cluster {name} init failed: {e}")
                raise

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, max=10))
    def deploy_agent_swarm(self, cluster: str, spec: DeploymentSpec):
        """Deploy agent swarm with StatefulSet for ordered scaling"""
        with self.lock:
            api = self.api_instances[cluster]['apps']
            secrets = self._get_vault_secrets(self.clusters[cluster].vault_path)
            
            container = client.V1Container(
                name="samsara-agent",
                image=spec.image,
                env=[client.V1EnvVar(name=k, value=v) for k, v in secrets.items()],
                resources=client.V1ResourceRequirements(
                    requests=spec.resources,
                    limits=spec.resources
                )
            )

            stateful_set = client.V1StatefulSet(
                metadata=client.V1ObjectMeta(name=f"samsara-{spec.agent_type}"),
                spec=client.V1StatefulSetSpec(
                    service_name="samsara-agent",
                    replicas=spec.replicas,
                    selector=client.V1LabelSelector(
                        match_labels={"app": "samsara-agent"}
                    ),
                    template=client.V1PodTemplateSpec(
                        metadata=client.V1ObjectMeta(labels={"app": "samsara-agent"}),
                        spec=client.V1PodSpec(
                            containers=[container],
                            affinity=self._build_affinity(spec.node_affinity)
                        )
                    ),
                    update_strategy=client.V1StatefulSetUpdateStrategy(
                        type="RollingUpdate",
                        rolling_update=client.V1RollingUpdateStatefulSetStrategy(partition=0)
                    )
                )
            )

            try:
                api.create_namespaced_stateful_set(
                    namespace="samsara-prod",
                    body=stateful_set
                )
                DEPLOYMENT_GAUGE.labels(cluster, "samsara-prod").inc()
                logger.info(f"Deployed {spec.agent_type} on {cluster}")
            except ApiException as e:
                ROLLBACK_COUNTER.inc()
                self._rollback_deployment(cluster, spec.agent_type)
                raise RuntimeError(f"Deployment failed: {e}")

    def _build_affinity(self, affinity_rules: Dict) -> client.V1Affinity:
        """Construct node affinity rules from spec"""
        if not affinity_rules:
            return None
            
        return client.V1Affinity(
            node_affinity=client.V1NodeAffinity(
                required_during_scheduling_ignored_during_execution=client.V1NodeSelector(
                    node_selector_terms=[
                        client.V1NodeSelectorTerm(
                            match_expressions=[
                                client.V1NodeSelectorRequirement(
                                    key=k, operator="In", values=v
                                ) for k, v in affinity_rules.items()
                            ]
                        )
                    ]
                )
            )
        )

    def _get_vault_secrets(self, path: str) -> Dict:
        """Retrieve secrets from HashiCorp Vault"""
        try:
            secret = self.vault_client.secrets.kv.v2.read_secret_version(path=path)
            return secret['data']['data']
        except hvac.exceptions.VaultError as ve:
            VAULT_ERRORS.inc()
            logger.error(f"Vault access failed: {ve}")
            return {}

    @retry(stop=stop_after_attempt(2), wait=wait_exponential(max=10))
    def scale_swarm(self, cluster: str, agent_type: str, replicas: int):
        """Scale agent swarm with multi-cluster failover"""
        api = self.api_instances[cluster]['apps']
        try:
            patch = {"spec": {"replicas": replicas}}
            api.patch_namespaced_stateful_set_scale(
                name=f"samsara-{agent_type}",
                namespace="samsara-prod",
                body=patch
            )
            SCALING_OPS.labels("out" if replicas < 0 else "in").inc()
        except ApiException as e:
            logger.error(f"Scaling failed: {e}")
            self._failover_scaling(cluster, agent_type, replicas)

    def _failover_scaling(self, original_cluster: str, agent_type: str, replicas: int):
        """Fallback scaling to next priority cluster"""
        clusters = sorted(self.clusters.values(), key=lambda x: x.priority)
        for cluster in clusters:
            if cluster.name == original_cluster:
                continue
            try:
                self.scale_swarm(cluster.name, agent_type, replicas)
                logger.warning(f"Failed over scaling to {cluster.name}")
                return
            except Exception:
                continue
        raise RuntimeError("All clusters failed scaling")

    def watch_events(self):
        """Multi-cluster event watcher with priority handling"""
        for cluster in self.clusters.values():
            threading.Thread(
                target=self._cluster_watcher,
                args=(cluster.name,),
                daemon=True
            ).start()

    def _cluster_watcher(self, cluster: str):
        v1 = self.api_instances[cluster]['core']
        while True:
            try:
                for event in self.watcher.stream(v1.list_namespaced_event, "samsara-prod"):
                    self._handle_event(cluster, event)
            except Exception as e:
                logger.error(f"Watch failed on {cluster}: {e}")
                time.sleep(5)

    def _handle_event(self, cluster: str, event: Dict):
        """Handle Kubernetes events for auto-remediation"""
        if event['type'] == 'Warning':
            if 'BackOff' in event['message']:
                self._restart_crashloop_pod(cluster, event)

    def _restart_crashloop_pod(self, cluster: str, event: Dict):
        """Automated pod restart for crashloop backoff"""
        pod_name = event['involvedObject']['name']
        api = self.api_instances[cluster]['core']
        try:
            api.delete_namespaced_pod(
                name=pod_name,
                namespace="samsara-prod",
                grace_period_seconds=0
            )
            logger.info(f"Restarted crashlooping pod {pod_name}")
        except ApiException as e:
            logger.error(f"Pod restart failed: {e}")

    def apply_crd_config(self, cluster: str, crd_path: str):
        """Apply Custom Resource Definitions for agent configurations"""
        with open(crd_path) as f:
            crd = yaml.safe_load(f)
            
        api = self.api_instances[cluster]['custom']
        try:
            api.create_cluster_custom_object(
                group="samsara.ai",
                version="v1alpha1",
                plural="agentconfigs",
                body=crd
            )
        except ApiException as e:
            if e.status == 409:  # Already exists
                self._update_crd(cluster, crd)
            else:
                raise

    def _update_crd(self, cluster: str, crd: Dict):
        """Update existing CRD with version check"""
        api = self.api_instances[cluster]['custom']
        current = api.get_cluster_custom_object(
            group="samsara.ai",
            version="v1alpha1",
            plural="agentconfigs",
            name=crd['metadata']['name']
        )
        
        if current['spec']['version'] < crd['spec']['version']:
            crd['metadata']['resourceVersion'] = current['metadata']['resourceVersion']
            api.replace_cluster_custom_object(
                group="samsara.ai",
                version="v1alpha1",
                plural="agentconfigs",
                name=crd['metadata']['name'],
                body=crd
            )

    def enforce_network_policies(self, cluster: str):
        """Apply zero-trust network policies across namespaces"""
        policy = client.V1NetworkPolicy(
            metadata=client.V1ObjectMeta(name="samsara-deny-all"),
            spec=client.V1NetworkPolicySpec(
                pod_selector={},
                policy_types=["Ingress", "Egress"],
                ingress=[],
                egress=[]
            )
        )
        
        net_api = client.NetworkingV1Api(self.api_instances[cluster]['core'].api_client)
        try:
            net_api.create_namespaced_network_policy(
                namespace="samsara-prod",
                body=policy
            )
        except ApiException as e:
            if e.status != 409:
                raise

    def create_backup(self, cluster: str):
        """ETCD backup integration for disaster recovery"""
        pod_name = "etcd-"+self.clusters[cluster].context.split("-")[-1]
        exec_command = ["/bin/sh", "-c", "ETCDCTL_API=3 etcdctl snapshot save /backup/snapshot.db"]
        
        resp = stream(
            self.api_instances[cluster]['core'].connect_get_namespaced_pod_exec,
            pod_name,
            "kube-system",
            command=exec_command,
            stderr=True, stdin=False, stdout=True, tty=False
        )
        
        if "Error" in resp:
            logger.error(f"Backup failed: {resp}")
            return False
        return True

    def _rollback_deployment(self, cluster: str, agent_type: str):
        """Rollback to previous StatefulSet revision"""
        api = self.api_instances[cluster]['apps']
        revisions = api.list_namespaced_controller_revision(
            namespace="samsara-prod",
            label_selector=f"app=samsara-agent,agent-type={agent_type}"
        )
        
        if len(revisions.items) < 2:
            logger.warning("No previous revision to rollback")
            return
            
        last_stable = revisions.items[-2]
        patch = {"spec": {"template": last_stable.data}}
        
        try:
            api.patch_namespaced_stateful_set(
                name=f"samsara-{agent_type}",
                namespace="samsara-prod",
                body=patch
            )
        except ApiException as e:
            ROLLBACK_COUNTER.inc()
            logger.error(f"Rollback failed: {e}")

# Example Configuration
if __name__ == "__main__":
    clusters = [
        ClusterConfig(
            name="us-west-prod",
            context="gke_samsara_us-west1-a_cluster1",
            regions=["us-west1"],
            vault_path="secret/samsara/us-west",
            resource_quota={"cpu": "20", "memory": "64Gi"}
        )
    ]
    
    controller = KubernetesController(clusters)
    controller.watch_events()
    
    sample_spec = DeploymentSpec(
        image="samsara/agent:3.1.0",
        agent_type="financial-analyzer",
        config_map="fin-config-v2",
        resources={"cpu": "1", "memory": "4Gi"},
        autoscaling={"min": 2, "max": 10, "cpu_threshold": 70},
        node_affinity={"cloud.google.com/gke-accelerator": ["nvidia-tesla-t4"]}
    )
    
    controller.deploy_agent_swarm("us-west-prod", sample_spec)
    controller.enforce_network_policies("us-west-prod")
