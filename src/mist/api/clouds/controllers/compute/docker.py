import re
import socket
import datetime
import netaddr
import tempfile

from libcloud.compute.providers import get_driver
from libcloud.compute.types import Provider
from mist.api.clouds.controllers.compute.base import BaseComputeController
from mist.api.clouds.controllers.compute.base import (
    log, copy, config, BadRequestError, NotFoundError, InternalServerError,
    node_to_dict, NodeState, BaseHTTPError
)

from mist.api.exceptions import MachineNotFoundError
from mist.api.exceptions import BadRequestError
from mist.api.exceptions import NotFoundError
from mist.api.exceptions import CloudUnavailableError
from mist.api.exceptions import MachineCreationError


class DockerComputeController(BaseComputeController):

    def __init__(self, *args, **kwargs):
        super(DockerComputeController, self).__init__(*args, **kwargs)
        self._dockerhost = None

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
                            "and docker port is specified")

        # TLS authentication.
        if self.cloud.key_file and self.cloud.cert_file:
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
            return get_container_driver(Container_Provider.DOCKER)(
                host=host, port=port,
                key_file=key_temp_file.name,
                cert_file=cert_temp_file.name,
                ca_cert=ca_cert)

        # Username/Password authentication.
        if self.cloud.username and self.cloud.password:

            return get_container_driver(Container_Provider.DOCKER)(
                key=self.cloud.username.value,
                secret=self.cloud.password.value,
                host=host, port=port)
        # open authentication.
        else:
            return get_container_driver(Container_Provider.DOCKER)(
                host=host, port=port)

    def _list_machines__fetch_machines(self):
        """Perform the actual libcloud call to get list of containers"""
        containers = self.connection.list_containers(all=self.cloud.show_all)
        # add public/private ips for mist
        for container in containers:
            public_ips, private_ips = [], []
            host = sanitize_host(self.cloud.host)
            if is_private_subnet(host):
                private_ips.append(host)
            else:
                public_ips.append(host)
            container.public_ips = public_ips
            container.private_ips = private_ips
            container.size = None
            container.image = container.image.name
        return [node_to_dict(node) for node in containers]

    def _list_machines__machine_creation_date(self, machine, node_dict):
        return node_dict['extra'].get('created')  # unix timestamp

    def _list_machines__machine_actions(self, machine, node_dict):
        # todo this is not necessary
        super(DockerComputeController, self)._list_machines__machine_actions(
            machine, node_dict)
        if node_dict['state'] in (ContainerState.RUNNING,):
            machine.actions.rename = True
        elif node_dict['state'] in (ContainerState.REBOOTING,
                                    ContainerState.PENDING):
            machine.actions.start = False
            machine.actions.stop = False
            machine.actions.reboot = False
        elif node_dict['state'] in (ContainerState.STOPPED,
                                    ContainerState.UNKNOWN):
            # We assume unknown state means stopped.
            machine.actions.start = True
            machine.actions.stop = False
            machine.actions.reboot = False
            machine.actions.rename = True
        elif node_dict['state'] in (ContainerState.TERMINATED, ):
            machine.actions.start = False
            machine.actions.stop = False
            machine.actions.reboot = False
            machine.actions.destroy = False
            machine.actions.rename = False

    def _list_machines__postparse_machine(self, machine, node_dict):
        updated = False
        if machine.machine_type != 'container':
            machine.machine_type = 'container'
            updated = True
        if machine.parent != self.dockerhost:
            machine.parent = self.dockerhost
            updated = True
        return updated

    @property
    def dockerhost(self):
        """This is a helper method to get the machine representing the host"""
        if self._dockerhost is not None:
            return self._dockerhost

        from mist.api.machines.models import Machine
        try:
            # Find dockerhost from database.
            machine = Machine.objects.get(cloud=self.cloud,
                                          machine_type='container-host')
        except Machine.DoesNotExist:
            try:
                # Find dockerhost with previous format from database.
                machine = Machine.objects.get(
                    cloud=self.cloud,
                    # Nested query. Trailing underscores to avoid conflict
                    # with mongo's $type operator. See:
                    # https://github.com/MongoEngine/mongoengine/issues/1410
                    **{'extra__tags__type__': 'docker_host'}
                )
            except Machine.DoesNotExist:
                # Create dockerrhost machine.
                machine = Machine(cloud=self.cloud,
                                  machine_type='container-host')

        # Update dockerhost machine model fields.
        changed = False
        for attr, val in {'name': self.cloud.name,
                          'hostname': self.cloud.host,
                          'machine_type': 'container-host'}.items():
            if getattr(machine, attr) != val:
                setattr(machine, attr, val)
                changed = True
        if not machine.external_id:
            machine.external_id = machine.id
            changed = True
        try:
            ip_addr = socket.gethostbyname(machine.hostname)
        except socket.gaierror:
            pass
        else:
            is_private = netaddr.IPAddress(ip_addr).is_private()
            ips = machine.private_ips if is_private else machine.public_ips
            if ip_addr not in ips:
                ips.insert(0, ip_addr)
                changed = True
        if changed:
            machine.save()

        self._dockerhost = machine
        return machine

    def inspect_node(self, node):
        """
        Inspect a container
        """
        result = self.connection.connection.request(
            "/v%s/containers/%s/json" % (self.connection.version,
                                         node.id)).object

        name = result.get('Name').strip('/')
        if result['State']['Running']:
            state = ContainerState.RUNNING
        else:
            state = ContainerState.STOPPED

        extra = {
            'image': result.get('Image'),
            'volumes': result.get('Volumes'),
            'env': result.get('Config', {}).get('Env'),
            'ports': result.get('ExposedPorts'),
            'network_settings': result.get('NetworkSettings', {}),
            'exit_code': result['State'].get("ExitCode")
        }

        node_id = result.get('Id')
        if not node_id:
            node_id = result.get('ID', '')

        host = sanitize_host(self.cloud.host)
        public_ips, private_ips = [], []
        if is_private_subnet(host):
            private_ips.append(host)
        else:
            public_ips.append(host)

        networks = result['NetworkSettings'].get('Networks', {})
        for network in networks:
            network_ip = networks[network].get('IPAddress')
            if is_private_subnet(network_ip):
                private_ips.append(network_ip)
            else:
                public_ips.append(network_ip)

        ips = []  # TODO maybe the api changed
        ports = result.get('Ports', [])
        for port in ports:
            if port.get('IP') is not None:
                ips.append(port.get('IP'))

        contnr = (Container(id=node_id,
                            name=name,
                            image=result.get('Image'),
                            state=state,
                            ip_addresses=ips,
                            driver=self.connection,
                            extra=extra))
        contnr.public_ips = public_ips
        contnr.private_ips = private_ips
        contnr.size = None
        return contnr

    def _list_machines__fetch_generic_machines(self):
        return [self.dockerhost]

    def _list_images__fetch_images(self, search=None):
        if not search:
            # Fetch mist's recommended images
            images = [ContainerImage(id=image, name=name, path=None,
                                     version=None, driver=self.connection,
                                     extra={})
                      for image, name in list(config.DOCKER_IMAGES.items())]
            images += self.connection.list_images()

        else:
            # search on dockerhub
            images = self.connection.ex_search_images(term=search)[:100]

        return images

    def image_is_default(self, image_id):
        return image_id in config.DOCKER_IMAGES

    def _action_change_port(self, machine, node):
        """This part exists here for docker specific reasons. After start,
        reboot and destroy actions, docker machine instance need to rearrange
        its port. Finally save the machine in db.
        """
        # this exist here cause of docker host implementation
        if machine.machine_type == 'container-host':
            return
        container_info = self.inspect_node(node)

        try:
            port = container_info.extra[
                'network_settings']['Ports']['22/tcp'][0]['HostPort']
        except (KeyError, TypeError):
            # add TypeError in case of 'Ports': {u'22/tcp': None}
            port = 22

        from mist.api.machines.models import KeyMachineAssociation
        key_associations = KeyMachineAssociation.objects(machine=machine)
        for key_assoc in key_associations:
            key_assoc.port = port
            key_assoc.save()
        return True

    def _get_libcloud_node(self, machine, no_fail=False):
        """Return an instance of a libcloud node

        This is a private method, used mainly by machine action methods.
        """
        assert self.cloud == machine.cloud
        for node in self.connection.list_containers():
            if node.id == machine.external_id:
                return node
        if no_fail:
            container = Container(id=machine.external_id,
                                  name=machine.external_id,
                                  image=machine.image.id,
                                  state=0,
                                  ip_addresses=[],
                                  driver=self.connection,
                                  extra={})
            container.public_ips = []
            container.private_ips = []
            container.size = None
            return container
        raise MachineNotFoundError(
            "Machine with external_id '%s'." % machine.external_id
        )

    def _start_machine(self, machine, node):
        ret = self.connection.start_container(node)
        self._action_change_port(machine, node)
        return ret

    def reboot_machine(self, machine):
        if machine.machine_type == 'container-host':
            return self.reboot_machine_ssh(machine)
        return super(DockerComputeController, self).reboot_machine(machine)

    def _reboot_machine(self, machine, node):
        self.connection.restart_container(node)
        self._action_change_port(machine, node)

    def _stop_machine(self, machine, node):
        return self.connection.stop_container(node)

    def _destroy_machine(self, machine, node):
        try:
            if node.state == ContainerState.RUNNING:
                self.connection.stop_container(node)
            return self.connection.destroy_container(node)
        except Exception as e:
            log.error('Destroy failed: %r' % e)
            return False

    def _list_sizes__fetch_sizes(self):
        return []

    def _rename_machine(self, machine, node, name):
        """Private method to rename a given machine"""
        self.connection.ex_rename_container(node, name)

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

        cpu_shares = size_obj.get('prefer', {}).get('cpu_shares')
        if cpu_shares and cpu_shares < 2:
            raise BadRequestError('Cpu shares value should be at least 2')

        ret_size = {}
        if cpu_shares:
            ret_size['cpu_shares'] = cpu_shares

        limits = {}
        if cpu_limit:
            limits['cpu'] = cpu_limit
        if memory_limit:
            limits['memory'] = memory_limit

        if limits:
            ret_size['limits'] = limits

        return [ret_size], None

    def _generate_plan__parse_custom_image(self, image_obj):
        # Image does not exist, so it needs to be pulled.
        # Instead of pulling it here synchronously, we create a dummy
        # CloudImage object that will be pulled later on asynchronous context
        from mist.api.images.models import CloudImage
        from mist.api.helpers import get_docker_image_sha
        if isinstance(image_obj, str):
            name = image_obj
        else:
            name = image_obj.get('image')

        # Use the default "latest" tag if image path given is not tagged
        if ':' not in name:
            name = f'{name}:latest'

        try:
            image_sha = get_docker_image_sha(name)
        except Exception:
            log.exception('Failed to fetch image sha256 hash')
            raise CloudUnavailableError(
                'Failed to fetch image sha256 hash') from None

        if image_sha is None:
            raise BadRequestError('Image does not exist on docker registry')

        try:
            image = CloudImage.objects.get(cloud=self.cloud,
                                           external_id=image_sha)
        except CloudImage.DoesNotExist:
            image = CloudImage(external_id=image_sha,
                               name=name,
                               cloud=self.cloud,
                               missing_since=datetime.datetime.now()
                               ).save()

        return image, {'pull': True}

    def _generate_plan__parse_networks(self, auth_context, networks_dict,
                                       location):
        port_bindings = networks_dict.get('port_bindings', {})

        if not isinstance(port_bindings, dict):
            raise BadRequestError('Invalid port_bindings parameter')

        host_port_regex = r'^\d{1,5}$'
        container_port_regex = r'^\d{1,5}(\/\w+)?$'

        for container_port, host_port in port_bindings.items():
            if (not re.match(host_port_regex, host_port) or
                    not re.match(container_port_regex, container_port)):
                raise BadRequestError('Invalid port bindings')

        return {
            'port_bindings': port_bindings
        }

    def _generate_plan__parse_extra(self, extra, plan) -> None:
        if extra.get('command'):
            plan['command'] = extra['command']

        if extra.get('environment'):
            if not isinstance(extra['environment'], dict):
                raise BadRequestError('Invalid port_bindings parameter')

            plan['environment'] = extra['environment']

    def _compute_best_combination(self, combination_list):
        if not combination_list:
            raise NotFoundError('No available plan exists for given '
                                'images, sizes, locations')

        # prioritize images tagged latest
        def sort_by_tag(value):
            image, size, location = value
            tagged_latest = ':latest' in image.name
            return -tagged_latest, -image.starred

        return sorted(combination_list, key=sort_by_tag)[0]

    def _create_machine__get_image_object(self, image):
        if image.get('pull') is True:
            from mist.api.helpers import pull_docker_image
            try:
                image_obj = pull_docker_image(self.cloud.id, image['name'])
            except Exception as exc:
                raise MachineCreationError(
                    f'Failed to pull image with exception: {exc!r}')
        else:
            image_obj = super()._create_machine__get_image_object(image['id'])
            # Docker deploy_container method uses the image name to deploy from
            image_obj.name = image_obj.id

        return image_obj

    def _create_machine__compute_kwargs(self, plan):
        kwargs = {
            'name': plan['machine_name'],
            'image': self._create_machine__get_image_object(plan['image'])
        }

        environment = [f'{key}={value}' for key, value in
                       plan.get('environment', {}).items()]

        key = self._create_machine__get_key_object(
            plan.get('key', {}).get('id'))
        if key:
            environment.append(f'PUBLIC_KEY={key.public}')
        kwargs['environment'] = environment
        kwargs['command'] = plan.get('command', '')

        if plan.get('size'):
            # The Docker API expects cpu quota in units of 10^9 CPUs.
            try:
                kwargs['nano_cpus'] = int(
                    plan['size']['limits']['cpu'] * (10**9))
            except KeyError:
                pass
            # The Docker API expects memory quota in bytes
            try:
                kwargs['mem_limit'] = int(
                    plan['size']['limits']['memory'] * 1024 * 1024)
            except KeyError:
                pass

            try:
                kwargs['cpu_shares'] = plan['size']['cpu_shares']
            except KeyError:
                pass

        if plan.get('networks'):
            port_bindings = plan['networks']['port_bindings']
            exposed_ports = {}
            bindings = {}
            # Docker API expects an object with the exposed container ports
            # in the form: {"<port>/<tcp|udp|sctp>": {}}
            for container_port, host_port in port_bindings.items():
                port = (container_port if '/' in container_port
                        else f'{container_port}/tcp')
                exposed_ports[port] = {}
                bindings[port] = [{
                    'HostPort': host_port
                }]

            kwargs['ports'] = exposed_ports
            kwargs['port_bindings'] = bindings

        return kwargs

    def _create_machine__post_machine_creation_steps(self, node, kwargs, plan):
        if plan.get('key'):
            node_info = self.inspect_node(node)
            try:
                ssh_port = int(
                    node_info.extra[
                        'network_settings']['Ports']['22/tcp'][0]['HostPort'])
            except KeyError:
                pass
            else:
                node.extra['ssh_port'] = ssh_port

