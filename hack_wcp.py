#!/usr/bin/env python3
"""
NSX NCP Deployment Manager

This module manages NSX NCP (Network Control Plane) deployments in Kubernetes,
providing functionality to update deployments, manage volumes, and monitor pod status.

Author: Expert Python Implementation
Version: 2.0
"""

import os
import sys
import time
import logging
from abc import ABC, abstractmethod
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

# Add the parent directory to the path to find util module
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from util import util
from timeout_decorator import timeout_decorator
from kubernetes import client, config
from kubernetes.client.models.v1_container_image import V1ContainerImage


class ComponentType(Enum):
    """Enumeration of supported NSX components."""
    NSX_OPERATOR = "nsx-operator"
    NSX_NCP = "nsx-ncp"


class OperationMode(Enum):
    """Enumeration of operation modes."""
    SLEEP = 0
    NORMAL = 1


@dataclass(frozen=True)
class NSXConfig:
    """Configuration constants for NSX deployment management."""
    
    # Paths and directories
    NCP_INI_DIR: str = "/etc/nsx-ujo/vc"
    NCP_INI_FILE: str = "/etc/nsx-ujo/ncp.ini"
    KUBE_CONFIG: str = "/root/.kube/config"
    
    # Kubernetes deployment configuration
    DEPLOYMENT_NAMESPACE: str = "vmware-system-nsx"
    DEPLOYMENT_NAME: str = "nsx-ncp"
    
    # Timeout and retry constants
    POD_STATUS_TIMEOUT: int = 180
    POD_CHECK_TIMEOUT: int = 50
    SLEEP_INTERVAL: int = 10
    LIVENESS_PROBE_FAILURE_THRESHOLD: int = 5000
    
    # Volume configuration
    NSX_OPERATOR_VOLUME_NAME: str = 'nsx-operator-volume'
    NSX_OPERATOR_HOST_PATH: str = '/root/nsx-operator'
    
    # Command configuration
    SLEEP_COMMAND: List[str] = None
    SLEEP_ARGS: List[str] = None
    
    def __post_init__(self):
        # Use object.__setattr__ to modify frozen dataclass
        object.__setattr__(self, 'SLEEP_COMMAND', ["/bin/bash"])
        object.__setattr__(self, 'SLEEP_ARGS', ["-c", "while true; do echo hello, world!; sleep 1; done"])


@dataclass(frozen=True)
class CredentialFile:
    """Represents a credential file to be extracted from pod."""
    source_path: str
    dest_path: str


class NSXDeploymentError(Exception):
    """Custom exception for NSX deployment operations."""
    pass


class ContainerNotFoundError(NSXDeploymentError):
    """Exception raised when a container is not found in deployment."""
    pass


class KubernetesClientManager:
    """Context manager for Kubernetes API clients."""
    
    def __init__(self, config_path: str):
        self.config_path = config_path
        self.api_client: Optional[client.ApiClient] = None
        self.apps_v1_api: Optional[client.AppsV1Api] = None
        self.core_v1_api: Optional[client.CoreV1Api] = None
    
    def __enter__(self) -> 'KubernetesClientManager':
        """Initialize Kubernetes clients."""
        config.load_kube_config(self.config_path)
        configuration = client.Configuration()
        self.api_client = client.ApiClient(configuration=configuration)
        self.apps_v1_api = client.AppsV1Api(api_client=self.api_client)
        self.core_v1_api = client.CoreV1Api(api_client=self.api_client)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Clean up resources."""
        if self.api_client:
            self.api_client.close()


class ContainerConfigurationStrategy(ABC):
    """Abstract base class for container configuration strategies."""
    
    def __init__(self, config: NSXConfig):
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
    
    @abstractmethod
    def configure_sleep_mode(self, deployment: client.V1Deployment, container: client.V1Container) -> None:
        """Configure container for sleep/debug mode."""
        pass
    
    @abstractmethod
    def configure_normal_mode(self, deployment: client.V1Deployment, container: client.V1Container) -> None:
        """Configure container for normal operation mode."""
        pass
    
    @abstractmethod
    def update_container_command(self, container: client.V1Container, sleep_mode: bool) -> None:
        """Update container command and arguments."""
        pass


class NSXOperatorStrategy(ContainerConfigurationStrategy):
    """Configuration strategy for NSX Operator containers."""
    
    def configure_sleep_mode(self, deployment: client.V1Deployment, container: client.V1Container) -> None:
        """Configure deployment for NSX Operator sleep/debug mode."""
        self._add_operator_volume(deployment, container)
        self._configure_deployment_settings(deployment)
    
    def configure_normal_mode(self, deployment: client.V1Deployment, container: client.V1Container) -> None:
        """Configure deployment for NSX Operator normal operation mode."""
        self._remove_operator_volume(deployment, container)
        
        # Check if command contains sleep and remove it
        if container.command and any("sleep" in str(cmd) for cmd in container.command):
            self.logger.info(f"Removing sleep command from container '{container.name}'")
            container.command = None
            container.args = None
        
        # Set normal operation command if not already set
        if not container.command:
            container.command = [
                "/usr/local/bin/manager", 
                "-nsxconfig", self.config.NCP_INI_FILE, 
                "-health-probe-bind-address", ":8383", 
                "-log-level", "2"
            ]
            container.args = None
        
        # Restore normal liveness probe
        if container.liveness_probe:
            container.liveness_probe.failure_threshold = 5
        
        self.logger.info(f"Configured NSX Operator container '{container.name}' for normal mode")
    
    def update_container_command(self, container: client.V1Container, sleep_mode: bool) -> None:
        """Update NSX Operator container command and liveness probe."""
        if sleep_mode:
            container.command = self.config.SLEEP_COMMAND.copy()
            container.args = self.config.SLEEP_ARGS.copy()
        else:
            container.command = [
                "/usr/local/bin/manager", 
                "-nsxconfig", self.config.NCP_INI_FILE, 
                "-health-probe-bind-address", ":8383", 
                "-log-level", "2"
            ]
            container.args = None
        
        # Update liveness probe
        if container.liveness_probe:
            container.liveness_probe.failure_threshold = self.config.LIVENESS_PROBE_FAILURE_THRESHOLD
    
    def _add_operator_volume(self, deployment: client.V1Deployment, container: client.V1Container) -> None:
        """Add NSX operator volume and volume mount."""
        # Create volume
        volume = client.V1Volume(
            name=self.config.NSX_OPERATOR_VOLUME_NAME,
            host_path=client.V1HostPathVolumeSource(
                path=self.config.NSX_OPERATOR_HOST_PATH,
                type='Directory'
            )
        )
        
        # Add volume if not present
        if not any(vol.name == self.config.NSX_OPERATOR_VOLUME_NAME for vol in deployment.spec.template.spec.volumes):
            deployment.spec.template.spec.volumes.append(volume)
        
        # Create and add volume mount
        volume_mount = client.V1VolumeMount(
            name=self.config.NSX_OPERATOR_VOLUME_NAME,
            mount_path=self.config.NSX_OPERATOR_HOST_PATH
        )
        
        if not any(mount.name == self.config.NSX_OPERATOR_VOLUME_NAME for mount in container.volume_mounts):
            container.volume_mounts.append(volume_mount)
    
    def _remove_operator_volume(self, deployment: client.V1Deployment, container: client.V1Container) -> None:
        """Remove NSX operator volume and volume mount."""
        # Remove volume
        deployment.spec.template.spec.volumes = [
            vol for vol in deployment.spec.template.spec.volumes 
            if vol.name != self.config.NSX_OPERATOR_VOLUME_NAME
        ]
        
        # Remove volume mount
        container.volume_mounts = [
            mount for mount in container.volume_mounts 
            if mount.name != self.config.NSX_OPERATOR_VOLUME_NAME
        ]
    
    def _configure_deployment_settings(self, deployment: client.V1Deployment) -> None:
        """Configure deployment-level settings for operator."""
        deployment.spec.replicas = 1
        deployment.spec.template.spec.node_selector = {
            "node-role.kubernetes.io/control-plane": "",
            "current": "current",
        }


class NSXNCPStrategy(ContainerConfigurationStrategy):
    """Configuration strategy for NSX NCP containers."""
    
    def configure_sleep_mode(self, deployment: client.V1Deployment, container: client.V1Container) -> None:
        """Configure deployment for NSX NCP sleep/debug mode."""
        self._configure_deployment_settings(deployment)
        self.logger.info(f"Configuring NCP container '{container.name}' for sleep mode")
    
    def configure_normal_mode(self, deployment: client.V1Deployment, container: client.V1Container) -> None:
        """Configure deployment for NSX NCP normal operation mode."""
        # Check if command contains sleep and remove it
        if container.command and any("sleep" in str(cmd) for cmd in container.command):
            self.logger.info(f"Removing sleep command from container '{container.name}'")
            container.command = None
            container.args = None
        
        # Use default from image if no specific command needed
        if not container.command:
            container.command = None  # Use default from image
            container.args = None
        
        # Restore normal liveness probe
        if container.liveness_probe and container.liveness_probe._exec:
            container.liveness_probe._exec.command = [
                "/bin/sh", "-c", "check_pod_liveness nsx-ncp 30"
            ]
            container.liveness_probe.failure_threshold = 5
        
        self.logger.info(f"Configured NCP container '{container.name}' for normal mode")
    
    def update_container_command(self, container: client.V1Container, sleep_mode: bool) -> None:
        """Update NSX NCP container command and liveness probe."""
        if sleep_mode:
            container.command = self.config.SLEEP_COMMAND.copy()
            container.args = self.config.SLEEP_ARGS.copy()
            
            # Update liveness probe for sleep mode
            if container.liveness_probe and container.liveness_probe._exec:
                container.liveness_probe._exec.command = [
                    "/bin/sh", "-c", "check_pod_liveness nsx-ncp 3000000"
                ]
                container.liveness_probe.failure_threshold = self.config.LIVENESS_PROBE_FAILURE_THRESHOLD
        else:
            # Restore normal mode settings
            container.command = None  # Use default from image
            container.args = None
            
            # Restore normal liveness probe
            if container.liveness_probe and container.liveness_probe._exec:
                container.liveness_probe._exec.command = [
                    "/bin/sh", "-c", "check_pod_liveness nsx-ncp 30"
                ]
                container.liveness_probe.failure_threshold = 5
    
    def _configure_deployment_settings(self, deployment: client.V1Deployment) -> None:
        """Configure deployment-level settings for NCP."""
        deployment.spec.replicas = 1
        deployment.spec.template.spec.node_selector = {
            "node-role.kubernetes.io/control-plane": "",
            "current": "current",
        }


class NSXDeploymentManager:
    """Main class for managing NSX deployments."""
    
    def __init__(self, config: NSXConfig):
        self.config = config
        self.logger = util.logger.get_logger(__name__)
        self._strategies: Dict[ComponentType, ContainerConfigurationStrategy] = {
            ComponentType.NSX_OPERATOR: NSXOperatorStrategy(config),
            ComponentType.NSX_NCP: NSXNCPStrategy(config),
        }
        
        # Apply Kubernetes client workaround
        self._apply_k8s_client_workaround()
    
    def _apply_k8s_client_workaround(self) -> None:
        """Apply workaround for Kubernetes client bug."""
        def _names_setter(self, vs):
            """Setter function for V1ContainerImage names property."""
            self._names = vs
        
        # See: https://github.com/kubernetes-client/python/issues/895
        V1ContainerImage.names = V1ContainerImage.names.setter(_names_setter)
    
    def get_deployment(self, api: client.AppsV1Api) -> client.V1Deployment:
        """
        Retrieve the NSX NCP deployment from Kubernetes.
        
        Args:
            api: Kubernetes Apps V1 API client
            
        Returns:
            V1Deployment: The NSX NCP deployment object
            
        Raises:
            NSXDeploymentError: If deployment cannot be found
        """
        try:
            return api.read_namespaced_deployment(
                name=self.config.DEPLOYMENT_NAME,
                namespace=self.config.DEPLOYMENT_NAMESPACE,
            )
        except client.exceptions.ApiException as e:
            raise NSXDeploymentError(f"Failed to get deployment: {e}") from e
    
    def get_running_pod_name(self) -> str:
        """
        Get the name of the running NSX NCP pod.
        
        Returns:
            str: Name of the running NSX NCP pod
            
        Raises:
            NSXDeploymentError: If no running pod is found or command fails
        """
        cmd = (
            f'kubectl get pods -l component=nsx-ncp -n {self.config.DEPLOYMENT_NAMESPACE} '
            '-o=jsonpath="{.items[?(@.status.phase==\'Running\')].metadata.name}"'
        )
        
        try:
            _, pod_name = util.runcmd(cmd)
            self.logger.info(f"Found running pod: {pod_name}")
            return pod_name.strip()
        except Exception as e:
            raise NSXDeploymentError(f"Failed to get running pod name: {e}") from e
    
    @util.wait_and_retry()
    def dump_ncp_configuration(self) -> None:
        """
        Dump NCP configuration files from the running pod to the local filesystem.
        
        This function extracts the NCP configuration file, username, password, and
        NSX manager certificate from the running NSX NCP pod.
        
        Raises:
            NSXDeploymentError: If any of the file extraction operations fail
        """
        # Ensure configuration directory exists
        config_dir = Path(self.config.NCP_INI_DIR)
        config_dir.mkdir(parents=True, exist_ok=True)
        
        pod_name = self.get_running_pod_name()
        
        # Extract main configuration file
        self._extract_file_from_pod(
            pod_name, 
            self.config.NCP_INI_FILE, 
            self.config.NCP_INI_FILE,
            required=True
        )
        
        # Extract credential files
        credential_files = [
            CredentialFile("/etc/nsx-ujo/vc/username", "/etc/nsx-ujo/vc/username"),
            CredentialFile("/etc/nsx-ujo/vc/password", "/etc/nsx-ujo/vc/password"),
            CredentialFile("/etc/nsx-ujo/nsx_manager_certificate_0", "/etc/nsx-ujo/nsx_manager_certificate_0")
        ]
        
        for cred_file in credential_files:
            self._extract_file_from_pod(
                pod_name,
                cred_file.source_path,
                cred_file.dest_path,
                required=False
            )
    
    def _extract_file_from_pod(self, pod_name: str, source_path: str, dest_path: str, required: bool = True) -> None:
        """Extract a file from a pod to the local filesystem."""
        cmd = (
            f"kubectl exec {pod_name} -c nsx-ncp -n {self.config.DEPLOYMENT_NAMESPACE} -- "
            f"cat {source_path} > {dest_path}"
        )
        
        res, _ = util.runcmd(cmd)
        if res != 0:
            if required:
                raise NSXDeploymentError(f"Failed to extract required file {source_path} from pod")
            else:
                self.logger.warning(f"Failed to extract optional file {source_path} from pod")
    
    @timeout_decorator.timeout(NSXConfig().POD_STATUS_TIMEOUT, timeout_exception=StopIteration)
    def monitor_pod_status(self, api: client.CoreV1Api) -> bool:
        """
        Monitor NSX NCP pod status until all pods and containers are ready.
        
        This function continuously checks the status of NSX NCP pods and their containers
        until they are all running and ready, or until the timeout is reached.
        
        Args:
            api: Kubernetes Core V1 API client
            
        Returns:
            bool: True when all pods and containers are ready
            
        Raises:
            StopIteration: If timeout is reached before pods are ready
        """
        while True:
            try:
                resp = api.list_namespaced_pod(
                    namespace=self.config.DEPLOYMENT_NAMESPACE,
                    label_selector="component=nsx-ncp",
                    timeout_seconds=self.config.POD_CHECK_TIMEOUT
                )
            except client.exceptions.ApiException as e:
                self.logger.error(f"Failed to list pods: {e}")
                time.sleep(self.config.SLEEP_INTERVAL)
                continue
            
            if self._check_all_pods_ready(resp.items):
                return True
                
            time.sleep(self.config.SLEEP_INTERVAL)
    
    def _check_all_pods_ready(self, pods: List[client.V1Pod]) -> bool:
        """Check if all pods and their containers are ready."""
        for pod in pods:
            self.logger.info(f"Pod {pod.metadata.name} status: {pod.status.phase}")
            
            if pod.status.phase != "Running":
                self.logger.info(f"Pod {pod.metadata.name} is not running, waiting {self.config.SLEEP_INTERVAL}s")
                return False
                
            # Check container readiness
            if pod.status.container_statuses:
                for container in pod.status.container_statuses:
                    self.logger.info(
                        f"Pod {pod.metadata.name} container {container.name} ready: {container.ready}"
                    )
                    if not container.ready:
                        self.logger.info(
                            f"Pod {pod.metadata.name} container {container.name} "
                            f"is not ready, waiting {self.config.SLEEP_INTERVAL}s"
                        )
                        return False
        
        return True
    
    def update_deployment(
        self, 
        api: client.AppsV1Api, 
        deployment: client.V1Deployment, 
        component: ComponentType,
        operation_mode: OperationMode
    ) -> None:
        """
        Update the NSX deployment configuration based on the component and operation mode.
        
        Args:
            api: Kubernetes Apps V1 API client
            deployment: The deployment object to update
            component: The component type to update
            operation_mode: The operation mode to apply
            
        Raises:
            ContainerNotFoundError: If container name is not found in deployment
            NSXDeploymentError: If deployment update fails
        """
        container = self._find_container_by_name(deployment, component.value)
        strategy = self._strategies[component]
        sleep_mode = operation_mode == OperationMode.SLEEP
        
        # Update container configuration
        strategy.update_container_command(container, sleep_mode)
        
        # Apply deployment-level configuration
        if sleep_mode:
            strategy.configure_sleep_mode(deployment, container)
        else:
            strategy.configure_normal_mode(deployment, container)
        
        # Apply the deployment update
        try:
            api.patch_namespaced_deployment(
                name=self.config.DEPLOYMENT_NAME, 
                namespace=self.config.DEPLOYMENT_NAMESPACE, 
                body=deployment
            )
        except client.exceptions.ApiException as e:
            raise NSXDeploymentError(f"Failed to update deployment: {e}") from e
    
    def _find_container_by_name(self, deployment: client.V1Deployment, container_name: str) -> client.V1Container:
        """Find and return a container by name in the deployment."""
        for container in deployment.spec.template.spec.containers:
            if container.name == container_name:
                return container
        
        raise ContainerNotFoundError(f"Container '{container_name}' not found in deployment")
    
    def restart_deployment(self) -> str:
        """
        Restart the NSX deployment.
        
        Returns:
            str: Command output from the restart operation
            
        Raises:
            NSXDeploymentError: If restart command fails
        """
        cmd = f"kubectl rollout restart deployment {self.config.DEPLOYMENT_NAME} -n {self.config.DEPLOYMENT_NAMESPACE}"
        
        try:
            _, stdout = util.runcmd(cmd)
            return stdout
        except Exception as e:
            raise NSXDeploymentError(f"Failed to restart deployment: {e}") from e
    
    def label_current_node(self, hostname: str) -> str:
        """
        Label the current node with 'current=current'.
        
        Args:
            hostname: The hostname of the node to label
            
        Returns:
            str: Command output from the labeling operation
            
        Raises:
            NSXDeploymentError: If labeling command fails
        """
        cmd = f"kubectl label node {hostname} current=current --overwrite"
        
        try:
            _, stdout = util.runcmd(cmd)
            return stdout
        except Exception as e:
            raise NSXDeploymentError(f"Failed to label node: {e}") from e


class CLIArgumentParser:
    """Parser for command line arguments."""
    
    @staticmethod
    def parse_arguments() -> Tuple[ComponentType, OperationMode]:
        """
        Parse and validate command line arguments.
        
        Returns:
            Tuple of ComponentType and OperationMode
            
        Raises:
            SystemExit: If invalid arguments are provided
        """
        logger = util.logger.get_logger(__name__)
        
        if len(sys.argv) != 3:
            logger.error("Usage: python hack_wcp.py <component> <mode>")
            logger.error("  component: nsx-operator or nsx-ncp")
            logger.error("  mode: 0 for sleep mode, 1 for normal mode")
            sys.exit(1)
        
        try:
            # Parse component
            component_str = sys.argv[1]
            try:
                component = ComponentType(component_str)
            except ValueError:
                raise ValueError(f"Component must be one of: {[c.value for c in ComponentType]}")
            
            # Parse mode
            mode_arg = int(sys.argv[2])
            try:
                operation_mode = OperationMode(mode_arg)
            except ValueError:
                raise ValueError(f"Mode must be one of: {[m.value for m in OperationMode]}")
            
            return component, operation_mode
            
        except ValueError as e:
            logger.error(f"Invalid argument: {e}")
            sys.exit(1)


def get_current_hostname() -> str:
    """
    Get the current hostname.
    
    Returns:
        str: The current hostname
        
    Raises:
        NSXDeploymentError: If hostname command fails
    """
    try:
        _, hostname = util.runcmd("hostname")
        return hostname.strip()
    except Exception as e:
        raise NSXDeploymentError(f"Failed to get hostname: {e}") from e


def main() -> None:
    """
    Main function to manage NSX NCP deployment configuration.
    
    This function orchestrates the entire process of:
    1. Parsing command line arguments
    2. Loading Kubernetes configuration
    3. Dumping NCP configuration files
    4. Labeling the current node
    5. Updating the deployment based on arguments
    6. Restarting deployment
    7. Monitoring pod status
    
    Raises:
        SystemExit: If invalid command line arguments are provided or operations fail
    """
    logger = util.logger.get_logger(__name__)
    
    try:
        # Parse command line arguments
        component, operation_mode = CLIArgumentParser.parse_arguments()
        
        # Initialize configuration and manager
        config = NSXConfig()
        manager = NSXDeploymentManager(config)
        
        # Get current hostname
        hostname = get_current_hostname()
        logger.info(f"Current hostname: {hostname}")
        
        # Initialize Kubernetes clients
        with KubernetesClientManager(config.KUBE_CONFIG) as k8s_client:
            # Dump NCP configuration files
            logger.info("Dumping NCP configuration and credentials")
            manager.dump_ncp_configuration()
            
            # Label the current node
            logger.info(f"Labeling node {hostname} with current=current")
            label_result = manager.label_current_node(hostname)
            logger.info(f"Node labeling result: {label_result}")
            
            # Get deployment and update the specified container
            logger.info(f"Updating {component.value} container in deployment")
            deployment = manager.get_deployment(k8s_client.apps_v1_api)
            
            # Log operation details
            mode_desc = "sleep" if operation_mode == OperationMode.SLEEP else "normal"
            logger.info(f"{component.value.upper()} mode - configuring {mode_desc} mode")
            
            # Update deployment
            manager.update_deployment(k8s_client.apps_v1_api, deployment, component, operation_mode)
            
            # Restart the deployment
            logger.info("Restarting NSX deployment")
            restart_result = manager.restart_deployment()
            logger.info(f"Deployment restart result: {restart_result}")
            
            # Monitor pod status
            logger.info("Monitoring NSX pod status")
            manager.monitor_pod_status(k8s_client.core_v1_api)
            
            logger.info(f"NSX {component.value} deployment update completed successfully")
    
    except (NSXDeploymentError, ContainerNotFoundError) as e:
        logger.error(f"NSX deployment operation failed: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()