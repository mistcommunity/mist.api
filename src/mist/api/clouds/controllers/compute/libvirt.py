import copy
import datetime
import asyncio
import mongoengine as me

from libcloud.compute.base import Node, NodeLocation
from libcloud.compute.providers import get_driver
from libcloud.compute.types import Provider, NodeState
from libcloud.compute.types import Provider
from mist.api.clouds.controllers.compute.base import BaseComputeController
from mist.api.clouds.controllers.compute.base import (
    log, copy, config, BadRequestError, NotFoundError, InternalServerError,
    node_to_dict, NodeState, BaseHTTPError
)

from mist.api.exceptions import MistError
from mist.api.exceptions import InternalServerError
from mist.api.exceptions import MachineNotFoundError
from mist.api.exceptions import BadRequestError
from mist.api.exceptions import NotFoundError
from mist.api.exceptions import ForbiddenError
from mist.api.exceptions import MachineCreationError


class LibvirtComputeController(BaseComputeController):

    def _connect(self, **kwargs):
        """
        Look for the host that corresponds to the provided location
        """
        from mist.api.clouds.models import CloudLocation
        from mist.api.machines.models import Machine
        location = CloudLocation.objects.get(
            id=kwargs.get('location_id'), cloud=self.cloud)
        host = Machine.objects.get(
            cloud=self.cloud, parent=None, external_id=location.external_id)

        return self._get_host_driver(host)

    def _get_host_driver(self, machine):
        import libcloud.compute.drivers.libvirt_driver
        libvirt_driver = libcloud.compute.drivers.libvirt_driver
        libvirt_driver.ALLOW_LIBVIRT_LOCALHOST = config.ALLOW_LIBVIRT_LOCALHOST

        if not machine.extra.get('tags', {}).get('type') == 'hypervisor':
            machine = machine.parent

        from mist.api.machines.models import KeyMachineAssociation
        from mongoengine import Q
        # Get key associations, prefer root or sudoer ones
        # TODO: put this in a helper function
        key_associations = KeyMachineAssociation.objects(
            Q(machine=machine) & (Q(ssh_user='root') | Q(sudo=True))) \
            or KeyMachineAssociation.objects(machine=machine)
        if not key_associations:
            raise ForbiddenError()

        host, port = dnat(machine.cloud.owner,
                          machine.hostname, machine.ssh_port)
        driver = get_driver(Provider.LIBVIRT)(
            host, hypervisor=machine.hostname, ssh_port=int(port),
            user=key_associations[0].ssh_user,
            ssh_key=key_associations[0].key.private.value)

        return driver

    def list_machines_single_host(self, host):
        try:
            driver = self._get_host_driver(host)
            return driver.list_nodes(
                parse_arp_table=config.LIBVIRT_PARSE_ARP_TABLES)
        except Exception as e:
            log.error('Failed to get machines from host: %s', host)
            return []

    async def list_machines_all_hosts(self, hosts, loop):
        vms = [
            loop.run_in_executor(None, self.list_machines_single_host, host)
            for host in hosts
        ]
        return await asyncio.gather(*vms)

    def _list_machines__fetch_machines(self):
        from mist.api.machines.models import Machine
        hosts = Machine.objects(cloud=self.cloud,
                                parent=None,
                                missing_since=None)
        try:
            loop = asyncio.get_event_loop()
            if loop.is_closed():
                raise RuntimeError('loop is closed')
        except RuntimeError:
            asyncio.set_event_loop(asyncio.new_event_loop())
            loop = asyncio.get_event_loop()

        node_lists = loop.run_until_complete(
            self.list_machines_all_hosts(hosts, loop))
        return [node_to_dict(node)
                for node_list in node_lists
                for node in node_list]

    def _list_machines__fetch_generic_machines(self):
        machines = []
        from mist.api.machines.models import Machine
        all_machines = Machine.objects(cloud=self.cloud, missing_since=None)
        for machine in all_machines:
            if machine.extra.get('tags', {}).get('type') == 'hypervisor':
                machines.append(machine)

        return machines

    def _list_machines__update_generic_machine_state(self, machine):
        # Defaults
        machine.unreachable_since = None
        machine.state = config.STATES[NodeState.RUNNING.value]

        # If any of the probes has succeeded, then state is running
        if (
            machine.ssh_probe and not machine.ssh_probe.unreachable_since or
            machine.ping_probe and not machine.ping_probe.unreachable_since
        ):
            machine.state = config.STATES[NodeState.RUNNING.value]

        # If ssh probe failed, then unreachable since then
        if machine.ssh_probe and machine.ssh_probe.unreachable_since:
            machine.unreachable_since = machine.ssh_probe.unreachable_since
            machine.state = config.STATES[NodeState.UNKNOWN.value]
        # Else if ssh probe has never succeeded and ping probe failed,
        # then unreachable since then
        elif (not machine.ssh_probe and
              machine.ping_probe and machine.ping_probe.unreachable_since):
            machine.unreachable_since = machine.ping_probe.unreachable_since
            machine.state = config.STATES[NodeState.UNKNOWN.value]

    def _list_machines__machine_actions(self, machine, node_dict):
        super(LibvirtComputeController, self)._list_machines__machine_actions(
            machine, node_dict)
        machine.actions.clone = True
        machine.actions.undefine = False
        if node_dict['state'] is NodeState.TERMINATED.value:
            # In libvirt a terminated machine can be started.
            machine.actions.start = True
            machine.actions.undefine = True
            machine.actions.rename = True
        if node_dict['state'] is NodeState.RUNNING.value:
            machine.actions.suspend = True
        if node_dict['state'] is NodeState.SUSPENDED.value:
            machine.actions.resume = True

    def _list_machines__generic_machine_actions(self, machine):
        super(LibvirtComputeController,
              self)._list_machines__generic_machine_actions(machine)
        machine.actions.rename = True
        machine.actions.start = False
        machine.actions.stop = False
        machine.actions.destroy = False
        machine.actions.reboot = False

    def _list_machines__postparse_machine(self, machine, node_dict):
        updated = False
        xml_desc = node_dict['extra'].get('xml_description')
        if xml_desc:
            escaped_xml_desc = escape(xml_desc)
            if machine.extra.get('xml_description') != escaped_xml_desc:
                machine.extra['xml_description'] = escaped_xml_desc
                updated = True
            import xml.etree.ElementTree as ET
            root = ET.fromstring(unescape(xml_desc))
            devices = root.find('devices')
            # TODO: rethink image association

            vnfs = []
            hostdevs = devices.findall('hostdev') + \
                devices.findall('interface[@type="hostdev"]')
            for hostdev in hostdevs:
                address = hostdev.find('source').find('address')
                vnf_addr = '%s:%s:%s.%s' % (
                    address.attrib.get('domain').replace('0x', ''),
                    address.attrib.get('bus').replace('0x', ''),
                    address.attrib.get('slot').replace('0x', ''),
                    address.attrib.get('function').replace('0x', ''),
                )
                vnfs.append(vnf_addr)
            if machine.extra.get('vnfs', []) != vnfs:
                machine.extra['vnfs'] = vnfs
                updated = True

        # Number of CPUs allocated to guest.
        if 'processors' in machine.extra and \
                machine.extra.get('cpus', []) != machine.extra['processors']:
            machine.extra['cpus'] = machine.extra['processors']
            updated = True

        # set machine's parent
        hypervisor = machine.extra.get('hypervisor', '')
        if hypervisor:
            try:
                from mist.api.machines.models import Machine
                parent = Machine.objects.get(cloud=machine.cloud,
                                             name=hypervisor)
            except Machine.DoesNotExist:
                # backwards compatibility
                hypervisor = hypervisor.replace('.', '-')
                try:
                    parent = Machine.objects.get(cloud=machine.cloud,
                                                 external_id=hypervisor)
                except me.DoesNotExist:
                    parent = None
            if machine.parent != parent:
                machine.parent = parent
                updated = True
        return updated

    def _list_machines__get_machine_extra(self, machine, node_dict):
        extra = copy.copy(node_dict['extra'])
        # make sure images_location is not overridden
        extra.update({'images_location': machine.extra.get('images_location')})
        return extra

    def _list_machines__get_size(self, node):
        return None

    def _list_machines__get_custom_size(self, node):
        if not node.get('size'):
            return
        from mist.api.clouds.models import CloudSize
        updated = False
        try:
            _size = CloudSize.objects.get(
                cloud=self.cloud, external_id=node['size'].get('name'))
        except me.DoesNotExist:
            _size = CloudSize(cloud=self.cloud,
                              external_id=node['size'].get('name'))
            updated = True
        if int(_size.ram or 0) != int(node['size'].get('ram', 0)):
            _size.ram = int(node['size'].get('ram'))
            updated = True
        if _size.cpus != node['size'].get('extra', {}).get('cpus'):
            _size.cpus = node['size'].get('extra', {}).get('cpus')
            updated = True
        if _size.disk != int(node['size'].get('disk')):
            _size.disk = int(node['size'].get('disk'))
        name = ""
        if _size.cpus:
            name += '%s CPUs, ' % _size.cpus
        if _size.ram:
            name += '%dMB RAM' % _size.ram
        if _size.disk:
            name += f', {_size.disk}GB disk.'
        if _size.name != name:
            _size.name = name
            updated = True
        if updated:
            _size.save()

        return _size

    def _list_machines__get_location(self, node):
        return node['extra'].get('hypervisor').replace('.', '-')

    def list_sizes(self, persist=True):
        return []

    def _list_locations__fetch_locations(self, persist=True):
        """
        We refer to hosts (KVM hypervisors) as 'location' for
        consistency purpose.
        """
        from mist.api.machines.models import Machine
        # FIXME: query parent for better performance
        hosts = Machine.objects(cloud=self.cloud,
                                missing_since=None,
                                parent=None)
        locations = [NodeLocation(id=host.external_id,
                                  name=host.name,
                                  country='', driver=None,
                                  extra=copy.deepcopy(host.extra))
                     for host in hosts]

        return locations

    def _list_locations__get_images_location(self, libcloud_location):
        return libcloud_location.extra.get('images_location')

    def list_images_single_host(self, host):
        driver = self._get_host_driver(host)
        return driver.list_images(location=host.extra.get(
            'images_location', {}))

    async def list_images_all_hosts(self, hosts, loop):
        images = [
            loop.run_in_executor(None, self.list_images_single_host, host)
            for host in hosts
        ]
        return await asyncio.gather(*images)

    def _list_images__fetch_images(self, search=None):
        from mist.api.machines.models import Machine
        hosts = Machine.objects(cloud=self.cloud, parent=None,
                                missing_since=None)
        try:
            loop = asyncio.get_event_loop()
            if loop.is_closed():
                raise RuntimeError('loop is closed')
        except RuntimeError:
            asyncio.set_event_loop(asyncio.new_event_loop())
            loop = asyncio.get_event_loop()
        all_images = loop.run_until_complete(self.list_images_all_hosts(hosts,
                                                                        loop))
        return [image for host_images in all_images for image in host_images]

    def _list_images__postparse_image(self, image, image_libcloud):
        locations = []
        if image_libcloud.extra.get('host', ''):
            host_name = image_libcloud.extra.get('host')
            from mist.api.clouds.models import CloudLocation
            try:
                host = CloudLocation.objects.get(cloud=self.cloud,
                                                 name=host_name)
                locations.append(host.id)
            except me.DoesNotExist:
                host_name = host_name.replace('.', '-')
                try:
                    host = CloudLocation.objects.get(cloud=self.cloud,
                                                     external_id=host_name)
                    locations.append(host.id)
                except me.DoesNotExist:
                    pass
        image.locations = locations

    def _get_libcloud_node(self, machine, no_fail=False):
        assert self.cloud == machine.cloud
        machine_type = machine.extra.get('tags', {}).get('type')
        host = machine if machine_type == 'hypervisor' else machine.parent

        driver = self._get_host_driver(host)

        for node in driver.list_nodes():
            if node.id == machine.external_id:
                return node

        if no_fail:
            return Node(machine.external_id, name=machine.external_id,
                        state=0, public_ips=[], private_ips=[],
                        driver=self.connection)
        raise MachineNotFoundError(
            "Machine with external_id '%s'." % machine.external_id
        )

    def _reboot_machine(self, machine, node):
        hypervisor = node.extra.get('tags', {}).get('type', None)
        if hypervisor == 'hypervisor':
            # issue an ssh command for the libvirt hypervisor
            try:
                hostname = node.public_ips[0] if \
                    node.public_ips else \
                    node.private_ips[0]
                command = '$(command -v sudo) shutdown -r now'
                # todo move it up
                from mist.api.methods import ssh_command
                ssh_command(self.cloud.owner, self.cloud.id,
                            node.id, hostname, command)
                return True
            except MistError as exc:
                log.error("Could not ssh machine %s", machine.name)
                raise
            except Exception as exc:
                log.exception(exc)
                # FIXME: Do not raise InternalServerError!
                raise InternalServerError(exc=exc)
        else:
            node.reboot()

    def _rename_machine(self, machine, node, name):
        if machine.extra.get('tags', {}).get('type') == 'hypervisor':
            machine.name = name
            machine.save()
            from mist.api.helpers import trigger_session_update
            trigger_session_update(machine.owner.id, ['clouds'])
        else:
            self._get_host_driver(machine).ex_rename_node(node, name)

    def remove_machine(self, machine):
        from mist.api.machines.models import KeyMachineAssociation
        from mist.api.clouds.models import CloudLocation
        KeyMachineAssociation.objects(machine=machine).delete()
        machine.missing_since = datetime.datetime.now()
        machine.save()
        if machine.machine_type == 'hypervisor':
            self.cloud.hosts.remove(machine.id)
            self.cloud.save()
            try:
                location = CloudLocation.objects.get(
                    external_id=machine.machine_id,
                    cloud=self.cloud)
                location.missing_since = datetime.datetime.now()
                location.save()
            except Exception as exc:
                log.error(
                    "Failed to set missing_since on LibVirt Location %s, %s",
                    machine.machine_id,
                    repr(exc))

        if amqp_owner_listening(self.cloud.owner.id):
            old_machines = [m.as_dict() for m in
                            self.cloud.ctl.compute.list_cached_machines()]
            new_machines = self.cloud.ctl.compute.list_machines()
            self.cloud.ctl.compute.produce_and_publish_patch(
                old_machines, new_machines)

    def _start_machine(self, machine, node):
        driver = self._get_host_driver(machine)
        return driver.ex_start_node(node)

    def _stop_machine(self, machine, node):
        driver = self._get_host_driver(machine)
        return driver.ex_stop_node(node)

    def _resume_machine(self, machine, node):
        driver = self._get_host_driver(machine)
        return driver.ex_resume_node(node)

    def _destroy_machine(self, machine, node):
        driver = self._get_host_driver(machine)
        return driver.destroy_node(node)

    def _suspend_machine(self, machine, node):
        driver = self._get_host_driver(machine)
        return driver.ex_suspend_node(node)

    def _undefine_machine(self, machine, node, delete_domain_image=False):
        if machine.extra.get('active'):
            raise BadRequestError('Cannot undefine an active domain')
        driver = self._get_host_driver(machine)
        result = driver.ex_undefine_node(node)
        if delete_domain_image and result:
            xml_description = node.extra.get('xml_description', '')
            if xml_description:
                index1 = xml_description.index("source file") + 13
                index2 = index1 + xml_description[index1:].index('\'')
                image_path = xml_description[index1:index2]
                driver._run_command("rm {}".format(image_path))
        return result

    def _clone_machine(self, machine, node, name, resume):
        driver = self._get_host_driver(machine)
        return driver.ex_clone_node(node, new_name=name)

    def _list_sizes__get_cpu(self, size):
        return size.extra.get('cpu')

    def _generate_plan__parse_networks(self, auth_context, networks_dict,
                                       location):
        """
        Parse network interfaces.
        - If networks_dict is empty, no network interface will be configured.
        - If only `id` or `name` is given, the interface will be
        configured by DHCP.
        - If `ip` is given, it will be statically assigned to the interface and
          optionally `gateway` and `primary` attributes will be used.
        """
        from mist.api.methods import list_resources
        from libcloud.utils.networking import is_valid_ip_address

        if not networks_dict:
            return None

        ret_dict = {
            'networks': [],
        }
        networks = networks_dict.get('networks', [])
        for net in networks:
            network_id = net.get('id') or net.get('name')
            if not network_id:
                raise BadRequestError('network id or name is required')
            try:
                [network], _ = list_resources(auth_context, 'network',
                                              search=network_id,
                                              cloud=self.cloud.id,
                                              limit=1)
            except ValueError:
                raise NotFoundError('Network does not exist')

            nid = {
                'network_name': network.name
            }
            if net.get('ip'):
                if is_valid_ip_address(net['ip']):
                    nid['ip'] = net['ip']
                else:
                    raise BadRequestError('IP given is invalid')
                if net.get('gateway'):
                    if is_valid_ip_address(net['gateway']):
                        nid['gateway'] = net['gateway']
                    else:
                        raise BadRequestError('Gateway IP given is invalid')
                if net.get('primary'):
                    nid['primary'] = net['primary']
            ret_dict['networks'].append(nid)

        if networks_dict.get('vnfs'):
            ret_dict['vnfs'] = networks_dict['vnfs']

        return ret_dict

    def _generate_plan__parse_disks(self, auth_context, disks_dict):
        ret_dict = {
            'disk_size': disks_dict.get('disk_size', 4),
        }
        if disks_dict.get('disk_path'):
            ret_dict['disk_path'] = disks_dict.get('disk_path')

        return ret_dict

    def _create_machine__get_image_object(self, image):
        from mist.api.images.models import CloudImage
        try:
            cloud_image = CloudImage.objects.get(id=image)
        except me.DoesNotExist:
            raise NotFoundError('Image does not exist')
        return cloud_image.external_id

    def _create_machine__get_size_object(self, size):
        if isinstance(size, dict):
            return size
        from mist.api.clouds.models import CloudSize
        try:
            cloud_size = CloudSize.objects.get(id=size)
        except me.DoesNotExist:
            raise NotFoundError('Size does not exist')
        return {'cpus': cloud_size.cpus, 'ram': cloud_size.ram}

    def _create_machine__get_location_object(self, location):
        from mist.api.clouds.models import CloudLocation
        try:
            cloud_location = CloudLocation.objects.get(id=location)
        except me.DoesNotExist:
            raise NotFoundError('Location does not exist')
        return cloud_location.external_id

    def _create_machine__compute_kwargs(self, plan):
        from mist.api.machines.models import Machine
        kwargs = super()._create_machine__compute_kwargs(plan)
        location_id = kwargs.pop('location')
        try:
            host = Machine.objects.get(
                cloud=self.cloud, external_id=location_id)
        except me.DoesNotExist:
            raise MachineCreationError("The host specified does not exist")
        driver = self._get_host_driver(host)
        kwargs['driver'] = driver
        size = kwargs.pop('size')
        kwargs['cpu'] = size['cpus']
        kwargs['ram'] = size['ram']
        if kwargs.get('auth'):
            kwargs['public_key'] = kwargs.pop('auth').public
        kwargs['disk_size'] = plan['disks'].get('disk_size')
        kwargs['disk_path'] = plan['disks'].get('disk_path')
        kwargs['networks'] = plan.get('networks', {}).get('networks', [])
        kwargs['vnfs'] = plan.get('networks', {}).get('vnfs', [])
        kwargs['cloud_init'] = plan.get('cloudinit')

        return kwargs

    def _create_machine__create_node(self, kwargs):
        driver = kwargs.pop('driver')
        node = driver.create_node(**kwargs)
        return node
