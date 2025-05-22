import socket
import tempfile
import json

from libcloud.compute.providers import get_driver
from libcloud.compute.types import Provider
from mist.api.clouds.controllers.compute.base import BaseComputeController
from mist.api.clouds.controllers.compute.base import (
    log, copy, config, BadRequestError, NotFoundError, InternalServerError,
    node_to_dict, NodeState, BaseHTTPError
)

from libcloud.container.providers import get_driver as get_container_driver
from libcloud.container.types import Provider as Container_Provider

from mist.api.exceptions import MistError
from mist.api.exceptions import MachineNotFoundError
from mist.api.exceptions import BadRequestError
from mist.api.exceptions import NotFoundError


class LXDComputeController(BaseComputeController):
    """
    Compute controller for LXC containers
    """

    def __init__(self, *args, **kwargs):
        super(LXDComputeController, self).__init__(*args, **kwargs)
        self._lxchost = None
        self.is_lxc = True

    def _stop_machine(self, machine, node):
        """Stop the given machine"""
        return self.connection.stop_container(container=machine)

    def _start_machine(self, machine, node):
        """Start the given container"""
        return self.connection.start_container(container=machine)

    def _destroy_machine(self, machine, node):
        """Delete the given container"""

        from libcloud.container.drivers.lxd import LXDAPIException
        from libcloud.container.types import ContainerState
        try:

            if node.state == ContainerState.RUNNING:
                self.connection.stop_container(container=machine)

            container = self.connection.destroy_container(container=machine)
            return container
        except LXDAPIException as e:
            raise MistError(msg=e.message, exc=e)
        except Exception as e:
            raise MistError(exc=e)

    def _reboot_machine(self, machine, node):
        """Restart the given container"""
        return self.connection.restart_container(container=machine)

    def _list_sizes__fetch_sizes(self):
        return []

    def _list_machines__fetch_machines(self):
        """Perform the actual libcloud call to get list of containers"""

        containers = self.connection.list_containers()

        # add public/private ips for mist
        for container in containers:
            public_ips, private_ips = [], []
            for ip in container.extra.get('ips'):
                if is_private_subnet(ip):
                    private_ips.append(ip)
                else:
                    public_ips.append(ip)

            container.public_ips = public_ips
            container.private_ips = private_ips
            container.size = None
            container.image = container.image.name

        return [node_to_dict(node) for node in containers]

    def _list_machines__machine_creation_date(self, machine, node_dict):
        """Unix timestap of when the machine was created"""
        return node_dict['extra'].get('created')  # unix timestamp

    def _list_machines__postparse_machine(self, machine, node_dict):
        updated = False
        if machine.machine_type != 'container':
            machine.machine_type = 'container'
            updated = True
        return updated

    def _get_libcloud_node(self, machine, no_fail=False):
        """Return an instance of a libcloud node

        This is a private method, used mainly by machine action methods.
        """
        # assert isinstance(machine.cloud, Machine)
        assert self.cloud == machine.cloud
        for node in self.connection.list_containers():
            if node.id == machine.external_id:
                return node
        if no_fail:
            return Node(machine.external_id, name=machine.external_id,
                        state=0, public_ips=[], private_ips=[],
                        driver=self.connection)
        raise MachineNotFoundError(
            "Machine with external_id '%s'." % machine.external_id
        )

    def _connect(self, **kwargs):
        host, port = dnat(self.cloud.owner, self.cloud.host,
                          self.cloud.port)

        try:
            socket.setdefaulttimeout(15)
            so = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            so.connect((sanitize_host(host), int(port)))
            so.close()
        except:
            raise Exception("Make sure host is accessible "
                            "and LXD port is specified")

        if self.cloud.key_file and self.cloud.cert_file:
            tls_auth = self._tls_authenticate(host=host, port=port)

            if tls_auth is None:
                raise Exception("key_file and cert_file exist "
                                "but TLS certification was not possible ")
            return tls_auth

        # Username/Password authentication.
        if self.cloud.username and self.cloud.password:

            return get_container_driver(Container_Provider.LXD)(
                key=self.cloud.username.value,
                secret=self.cloud.password.value,
                host=host, port=port)
        # open authentication.
        else:
            return get_container_driver(Container_Provider.LXD)(
                host=host, port=port)

    def _tls_authenticate(self, host, port):
        """Perform TLS authentication given the host and port"""

        # TLS authentication.

        key_temp_file = tempfile.NamedTemporaryFile(delete=False)
        key_temp_file.write(self.cloud.key_file.value.encode())
        key_temp_file.close()
        cert_temp_file = tempfile.NamedTemporaryFile(delete=False)
        cert_temp_file.write(self.cloud.cert_file.value.encode())
        cert_temp_file.close()
        ca_cert = None

        if self.cloud.ca_cert_file:
            ca_cert_temp_file = tempfile.NamedTemporaryFile(delete=False)
            ca_cert_temp_file.write(self.cloud.ca_cert_file.value.encode())
            ca_cert_temp_file.close()
            ca_cert = ca_cert_temp_file.name

        # tls auth
        cert_file = cert_temp_file.name
        key_file = key_temp_file.name
        return \
            get_container_driver(Container_Provider.LXD)(host=host,
                                                         port=port,
                                                         key_file=key_file,
                                                         cert_file=cert_file,
                                                         ca_cert=ca_cert)

    def _generate_plan__parse_size(self, auth_context, size_obj):
        size_obj = size_obj or {}

        if not isinstance(size_obj, dict):
            raise BadRequestError('Invalid size type')

        cpu_limit = size_obj.get('cpu')
        if cpu_limit and cpu_limit <= 0:
            raise BadRequestError('Cpu limit value should be bigger than 0')

        memory_limit = size_obj.get('memory')
        if memory_limit and memory_limit < 6:
            raise BadRequestError('Memory limit value should be at least 6 MB')

        ret_size = {}
        limits = {}

        if cpu_limit:
            limits['cpu'] = str(cpu_limit)
        if memory_limit:
            limits['memory'] = f'{memory_limit}MB'

        if limits:
            ret_size['limits'] = limits

        return [ret_size], None

    def _generate_plan__parse_networks(self,
                                       auth_context,
                                       networks_dict,
                                       location):
        from mist.api.methods import list_resources
        networks = networks_dict.get('networks') or []
        ret_networks = []
        for net in networks:
            try:
                [network], _ = list_resources(auth_context,
                                              'network',
                                              search=net,
                                              cloud=self.cloud.id,
                                              limit=1)
            except ValueError:
                raise NotFoundError(f'Network: {net} not found')

            ret_networks.append({
                'id': network.id,
                'name': network.name,
            })

        return ret_networks

    def _generate_plan__parse_volume_attrs(self, volume_dict, vol_obj):
        try:
            path = volume_dict['path']
        except KeyError:
            raise BadRequestError('Volume path parameter is required')

        return {
            'id': vol_obj.id,
            'name': vol_obj.name,
            'path': path,
        }

    def _generate_plan__parse_custom_volume(self, volume_dict):
        ret_volume = {}
        try:
            ret_volume['name'] = volume_dict['name']
        except KeyError:
            raise BadRequestError('Volume name parameter is required')

        try:
            ret_volume['size'] = int(volume_dict['size'])
        except KeyError:
            raise BadRequestError('Volume size parameter is required')
        except (TypeError, ValueError):
            raise BadRequestError('Invalid volume size type')

        try:
            ret_volume['path'] = volume_dict['path']
        except KeyError:
            raise BadRequestError('Volume path parameter is required')

        ret_volume['filesystem'] = volume_dict.get('filesystem') or 'ext4'
        ret_volume['mount_options'] = (volume_dict.get('mount_options') or
                                       'discard')
        ret_volume['pool'] = volume_dict.get('pool') or 'default'

        security_shifted = volume_dict.get('security_shifted') is True
        if security_shifted:
            ret_volume['security_shifted'] = security_shifted

        return ret_volume

    def _generate_plan__parse_extra(self, extra, plan):
        plan['ephemeral'] = extra.get('ephemeral') is True

    def _create_machine__compute_kwargs(self, plan):
        from mist.api.volumes.models import Volume
        kwargs = super()._create_machine__compute_kwargs(plan)
        image = kwargs.pop('image')
        kwargs['image'] = None
        parameters = {
            'source': {
                'type': 'image',
                'fingerprint': image.id
            }
        }
        kwargs['parameters'] = json.dumps(parameters)
        devices = {}
        volumes = plan.get('volumes', [])
        for volume in volumes:
            if volume.get('id'):
                mist_volume = Volume.objects.get(id=volume['id'])
                devices[mist_volume.name] = {
                    'type': 'disk',
                    'path': volume['path'],
                    'source': mist_volume.name,
                    'pool': mist_volume.extra['pool_id']
                }
            else:
                definition = {
                    'name': volume['name'],
                    'type': 'custom',
                    'size_type': 'GB',
                    'config': {
                        'size': volume['size'],
                        'block.filesystem': volume['filesystem'],
                        'block.mount_options': volume['mount_options'],
                    }
                }
                try:
                    libcloud_volume = self.connection.create_volume(
                        pool_id=volume['pool'],
                        definition=definition)
                except Exception:
                    log.error('Failed to create volume for LXD cloud: %s',
                              self.cloud.id)
                else:
                    devices[libcloud_volume.name] = {
                        'type': 'disk',
                        'path': volume['path'],
                        'source': libcloud_volume.name,
                        'pool': libcloud_volume.extra['pool_id']
                    }

        networks = plan.get('networks', [])
        for network in networks:
            devices[network['name']] = {
                'name': network['name'],
                'type': 'nic',
                'nictype': 'bridged',
                'parent': 'lxdbr0',
            }
        if devices:
            kwargs['ex_devices'] = devices

        kwargs['ex_ephemeral'] = plan['ephemeral']
        if plan.get('size'):
            kwargs['ex_config'] = {}
            try:
                kwargs['ex_config']['limits.cpu'] = plan['size']['limits']['cpu']  # noqa
            except KeyError:
                pass
            try:
                kwargs['ex_config']['limits.memory'] = plan['size']['limits']['memory']  # noqa
            except KeyError:
                pass

        return kwargs
