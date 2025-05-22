import copy
import tempfile
import requests
import mongoengine as me
from requests.exceptions import ConnectionError
from requests.exceptions import ConnectTimeout

from libcloud.compute.providers import get_driver
from mist.api.clouds.controllers.compute.base import BaseComputeController
from mist.api.clouds.controllers.compute.base import (
    log, copy, config, BadRequestError, NotFoundError, InternalServerError,
    node_to_dict, NodeState, BaseHTTPError
)
from libcloud.container.drivers.kubernetes import Node as KubernetesNode
from libcloud.container.drivers.kubernetes import KubernetesPod
from libcloud.container.providers import get_driver as get_container_driver
from libcloud.container.types import Provider as Container_Provider
from libcloud.container.base import Container

from libcloud.container.drivers.kubernetes import to_n_bytes
from libcloud.container.drivers.kubernetes import to_memory_str
from libcloud.container.drivers.kubernetes import to_cpu_str
from libcloud.container.drivers.kubernetes import to_n_cpus

class _KubernetesBaseComputeController(BaseComputeController):
    def _connect(self, provider, use_container_driver=True, **kwargs):
        host, port = dnat(self.cloud.owner,
                          self.cloud.host, self.cloud.port)
        url = f'https://{sanitize_host(host)}:{port}'

        try:
            requests.get(url, verify=False, timeout=15)
        except (ConnectionError, ConnectTimeout):
            raise Exception("Make sure host is accessible. ")
        if use_container_driver:
            get_driver_method = get_container_driver
        else:
            get_driver_method = get_driver

        ca_cert = None
        if self.cloud.ca_cert_file:
            ca_cert_temp_file = tempfile.NamedTemporaryFile(delete=False)
            ca_cert_temp_file.write(self.cloud.ca_cert_file.value.encode())
            ca_cert_temp_file.close()
            ca_cert = ca_cert_temp_file.name

        # tls authentication
        if self.cloud.key_file and self.cloud.cert_file:
            key_temp_file = tempfile.NamedTemporaryFile(delete=False)
            key_temp_file.write(self.cloud.key_file.value.encode())
            key_temp_file.close()
            key_file = key_temp_file.name
            cert_temp_file = tempfile.NamedTemporaryFile(delete=False)
            cert_temp_file.write(self.cloud.cert_file.value.encode())
            cert_temp_file.close()
            cert_file = cert_temp_file.name

            return get_driver_method(provider)(secure=True,
                                               host=host,
                                               port=port,
                                               key_file=key_file,
                                               cert_file=cert_file,
                                               ca_cert=ca_cert)

        elif self.cloud.token:
            token = self.cloud.token.value

            return get_driver_method(provider)(key=token,
                                               secure=True,
                                               host=host,
                                               port=port,
                                               ca_cert=ca_cert,
                                               ex_token_bearer_auth=True)
        # username/password auth
        elif self.cloud.username and self.cloud.password:
            key = self.cloud.username.value
            secret = self.cloud.password.value

            return get_driver_method(provider)(key=key,
                                               secret=secret,
                                               secure=True,
                                               host=host,
                                               port=port)
        else:
            msg = '''Necessary parameters for authentication are missing.
            Either a key_file/cert_file pair or a username/pass pair
            or a bearer token.'''
            raise ValueError(msg)

    def _list_machines__machine_actions(self, machine, node_dict):
        super()._list_machines__machine_actions(machine, node_dict)
        machine.actions.start = True
        machine.actions.stop = True
        machine.actions.reboot = True
        machine.actions.destroy = True

    def _reboot_machine(self, machine, node):
        return self.connection.reboot_node(node)

    def _start_machine(self, machine, node):
        return self.connection.start_node(node)

    def _stop_machine(self, machine, node):
        return self.connection.stop_node(node)

    def _destroy_machine(self, machine, node):
        res = self.connection.destroy_node(node)
        if res:
            if machine.extra.get('pvcs'):
                # FIXME: resolve circular import issues
                from mist.api.models import Volume
                volumes = Volume.objects.filter(cloud=self.cloud)
                for volume in volumes:
                    if machine.id in volume.attached_to:
                        volume.attached_to.remove(machine.id)

    def _list_machines__get_location(self, node):
        return node.get('extra', {}).get('namespace', "")

    def _list_machines__get_image(self, node):
        return node.get('image', {}).get('id')

    def _list_machines__get_size(self, node):
        return node.get('size', {}).get('id')

    def _list_sizes__get_cpu(self, size):
        cpu = int(size.extra.get('cpus') or 1)
        if cpu > 1000:
            cpu = cpu / 1000
        elif cpu > 99:
            cpu = 1
        return cpu

    def _list_sizes__fetch_sizes(self):
        return []


class KubernetesComputeController(_KubernetesBaseComputeController):
    def _connect(self, **kwargs):
        return super()._connect(Container_Provider.KUBERNETES, **kwargs)

    def check_connection(self):
        try:
            self._connect().list_namespaces()
        except InvalidCredsError as e:
            raise CloudUnauthorizedError(str(e))

    def list_namespaces(self):
        return [node_to_dict(ns) for ns in self.connection.list_namespaces()]

    def list_services(self):
        return self.connection.ex_list_services()

    def get_version(self):
        return self.connection.ex_get_version()

    def get_node_resources(self):
        nodes = self._list_nodes()
        available_cpu = 0
        available_memory = 0
        used_cpu = 0
        used_memory = 0
        for node in nodes:
            available_cpu += to_n_cpus(
                node['extra']['cpu'])
            available_memory += to_n_bytes(
                node['extra']['memory'])
            used_cpu += to_n_cpus(
                node['extra']['usage']['cpu'])
            used_memory += to_n_bytes(
                node['extra']['usage']['memory'])
        return dict(cpu=to_cpu_str(available_cpu),
                    memory=to_memory_str(
                        available_memory),
                    usage=dict(cpu=to_cpu_str(used_cpu),
                               memory=to_memory_str(
                                   used_memory)))

    def _list_nodes(self, return_node_map=False):
        node_map = {}
        nodes = []
        try:
            nodes_metrics = self.connection.ex_list_nodes_metrics()
        except BaseHTTPError:
            nodes_metrics = []
        nodes_metrics_dict = {node_metrics['metadata']['name']: node_metrics
                              for node_metrics in nodes_metrics}
        for node in self.connection.ex_list_nodes():
            node_map[node.name] = node.id
            node.type = 'node'
            node.os = node.extra.get('os')
            node_metrics = nodes_metrics_dict.get(node.name)
            if node_metrics:
                node.extra['usage'] = node_metrics['usage']
            nodes.append(node_to_dict(node))
        if return_node_map:
            return nodes, node_map
        return nodes

    def _list_machines__fetch_machines(self):
        """List all kubernetes machines: nodes, pods and containers"""
        nodes, node_map = self._list_nodes(return_node_map=True)
        pod_map = {}
        pods = []
        pod_containers = []
        try:
            pods_metrics = self.connection.ex_list_pods_metrics()
        except BaseHTTPError:
            pods_metrics = []
        pods_metrics_dict = {pods_metrics['metadata']['name']: pods_metrics
                             for pods_metrics in pods_metrics}
        containers_metrics_dict = {}
        for pod in self.connection.ex_list_pods():
            pod.type = 'pod'
            pod_map[pod.name] = pod.id
            pod_containers += pod.containers
            pod.parent_id = node_map.get(pod.node_name)
            pod.public_ips, pod.private_ips = [], []
            for ip in pod.ip_addresses:
                if is_private_subnet(ip):
                    pod.private_ips.append(ip)
                else:
                    pod.public_ips.append(ip)
            containers_metrics = pods_metrics_dict.get(
                pod.name, {}).get('containers')
            if containers_metrics:
                total_usage = {'cpu': 0, 'memory': 0}
                for container_metrics in containers_metrics:
                    containers_metrics_dict.setdefault(pod.id, {})[
                        container_metrics['name']] = container_metrics
                    ctr_cpu_usage = container_metrics['usage']['cpu']
                    ctr_memory_usage = container_metrics['usage']['memory']
                    total_usage['cpu'] += to_n_cpus(
                        ctr_cpu_usage)
                    total_usage['memory'] += \
                        to_n_bytes(
                            ctr_memory_usage)
                total_usage['cpu'] = to_cpu_str(total_usage['cpu'])
                total_usage['memory'] = to_memory_str(
                    total_usage['memory']
                )
                pod.extra['usage'] = {
                    'containers': containers_metrics,
                    'total': total_usage
                }
            pod.extra['namespace'] = pod.namespace
            pods.append(node_to_dict(pod))
        containers = []
        for container in pod_containers:
            container.type = 'container'
            container.public_ips, container.private_ips = [], []
            container.parent_id = pod_map.get(container.extra['pod'])
            metrics = containers_metrics_dict.get(
                container.parent_id, {}).get(container.name)
            if metrics:
                container.extra['usage'] = metrics['usage']
            containers.append(node_to_dict(container))
        machines = nodes + pods + containers
        return machines

    def _list_machines__postparse_machine(self, machine, node_dict):
        updated = False
        node_type = node_dict['type']
        if machine.machine_type != node_type:
            machine.machine_type = node_type
            updated = True
        node_parent_id = node_dict.get('parent_id')
        if node_parent_id:
            from mist.api.machines.models import Machine
            try:
                machine_parent = Machine.objects.get(
                    cloud=machine.cloud, external_id=node_parent_id)
            except Machine.DoesNotExist:
                pass
            else:
                if machine.parent != machine_parent:
                    machine.parent = machine_parent
                    updated = True
        node_cpu = node_dict.get('extra', {}).get('cpu')
        if node_cpu and (isinstance(node_cpu, int) or node_cpu.isdigit()):
            machine.cores = float(node_cpu)
            updated = True
        os_type = node_dict.get('extra', {}).get('os')
        if machine.os_type != os_type:
            machine.os_type = os_type
            updated = True
        return updated

    def _list_machines__get_custom_image(self, node_dict):
        updated = False
        from mist.api.images.models import CloudImage
        node_image = node_dict.get('image')
        if node_image is None:
            return None
        image_id = node_image.get('id')
        if image_id is None or image_id == 'undefined':
            return None
        try:
            image = CloudImage.objects.get(cloud=self.cloud,
                                           external_id=image_id)
        except CloudImage.DoesNotExist:
            image = CloudImage(cloud=self.cloud,
                               external_id=str(image_id),
                               name=node_image.get('name'),
                               extra=node_image.get('extra'))
            updated = True
        if updated:
            image.save()
        return image

    def _list_machines__get_custom_size(self, node_dict):
        node_size = node_dict.get('size')
        if node_size is None:
            return None
        from mist.api.clouds.models import CloudSize
        updated = False
        size_id = node_size.get('id')
        try:
            size = CloudSize.objects.get(
                cloud=self.cloud, external_id=str(size_id))
        except me.DoesNotExist:
            size = CloudSize(cloud=self.cloud,
                             external_id=str(size_id))
            updated = True
        ram = node_size.get('ram')
        if size.ram != ram:
            if isinstance(ram, str) and ram.isalnum():
                ram = to_n_bytes(ram)
            size.ram = ram
            updated = True
        cpu = node_size.get('cpu')
        if size.cpus != cpu:
            size.cpus = cpu
            updated = True
        disk = node_size.get('disk')
        if size.disk != disk:
            size.disk = disk
            updated = True
        name = node_size.get('name')
        if size.name != name:
            size.name = name
            updated = True
        if updated:
            size.save()
        return size

    def _list_machines__get_machine_extra(self, machine, node_dict):
        node_extra = node_dict.get('extra')
        return copy.copy(node_extra) if node_extra else {}

    def _list_machines__machine_actions(self, machine, node_dict):
        machine.actions.start = False
        machine.actions.stop = False
        machine.actions.reboot = False
        machine.actions.rename = False
        machine.actions.expose = False
        machine.actions.resume = False
        machine.actions.suspend = False
        machine.actions.undefine = False
        machine.actions.tag = True
        machine.actions.destroy = True

    def _get_libcloud_node(self, machine):
        """Return an instance of a libcloud node"""
        assert self.cloud == machine.cloud
        nodes = self.connection.ex_list_nodes() + \
            self.connection.ex_list_pods() + \
            self.connection.list_containers()
        for node in nodes:
            if node.id == machine.external_id:
                return node
        raise MachineNotFoundError(
            "Machine with external_id '%s'." % machine.external_id
        )

    def _destroy_machine(self, machine, node):
        if isinstance(node, KubernetesNode):
            self.connection.ex_destroy_node(node.name)
        elif isinstance(node, KubernetesPod):
            self.connection.ex_destroy_pod(node.namespace, node.name)
        elif isinstance(node, Container):
            self.connection.destroy_container(node)

