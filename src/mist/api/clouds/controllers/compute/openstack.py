import time
import secrets
import mongoengine as me
from time import sleep

from libcloud.compute.providers import get_driver
from libcloud.compute.types import Provider
from mist.api.clouds.controllers.compute.base import BaseComputeController
from mist.api.clouds.controllers.compute.base import (
    log, copy, config, BadRequestError, NotFoundError, InternalServerError,
    node_to_dict, NodeState, BaseHTTPError
)

from mist.api.exceptions import BadRequestError
from mist.api.exceptions import NotFoundError
from mist.api.exceptions import CloudUnavailableError

if config.HAS_VPN:
    from mist.vpn.methods import destination_nat as dnat
else:
    from mist.api.dummy.methods import dnat


class OpenStackComputeController(BaseComputeController):

    def _connect(self, **kwargs):
        url = dnat(self.cloud.owner, self.cloud.url)
        return get_driver(Provider.OPENSTACK)(
            self.cloud.username,
            self.cloud.password.value,
            api_version='2.2',
            ex_force_auth_version='3.x_password',
            ex_tenant_name=self.cloud.tenant,
            ex_force_service_region=self.cloud.region,
            ex_force_base_url=self.cloud.compute_endpoint,
            ex_auth_url=url,
            ex_domain_name=self.cloud.domain or 'Default'
        )

    def _list_machines__machine_creation_date(self, machine, node_dict):
        return node_dict['extra'].get('created')  # iso8601 string

    def _list_machines__machine_actions(self, machine, node_dict):
        super(OpenStackComputeController,
              self)._list_machines__machine_actions(machine, node_dict)
        machine.actions.rename = True
        machine.actions.resize = True

    def _resize_machine(self, machine, node, node_size, kwargs):
        try:
            self.connection.ex_resize(node, node_size)
        except Exception as exc:
            raise BadRequestError('Failed to resize node: %s' % exc)

        try:
            sleep(50)
            node = self._get_libcloud_node(machine)
            return self.connection.ex_confirm_resize(node)
        except Exception as exc:
            sleep(50)
            node = self._get_libcloud_node(machine)
            try:
                return self.connection.ex_confirm_resize(node)
            except Exception as exc:
                raise BadRequestError('Failed to resize node: %s' % exc)

    def _list_machines__postparse_machine(self, machine, node_dict):
        updated = False
        # do not include ipv6 on public ips
        public_ips = []
        for ip in machine.public_ips:
            if ip and ':' not in ip:
                public_ips.append(ip)
        if machine.public_ips != public_ips:
            machine.public_ips = public_ips
            updated = True
        return updated

    def _list_machines__get_location(self, node):
        return node['extra'].get('availability_zone', '')

    def _list_sizes__get_cpu(self, size):
        return size.vcpus

    def _list_machines__get_size(self, node):
        return node['extra'].get('flavorId')

    def _list_security_groups(self):
        if self.cloud.tenant_id is None:
            # try to populate tenant_id field
            try:
                tenant_id = \
                    self.cloud.ctl.compute.connection.ex_get_tenant_id()
            except Exception as exc:
                log.error(
                    'Failed to retrieve project id for Openstack cloud %s: %r',
                    self.cloud.id, exc)
            else:
                self.cloud.tenant_id = tenant_id
                try:
                    self.cloud.save()
                except me.ValidationError as exc:
                    log.error(
                        'Error adding tenant_id to %s: %r',
                        self.cloud.name, exc)
        try:
            sec_groups = \
                self.cloud.ctl.compute.connection.ex_list_security_groups(
                    tenant_id=self.cloud.tenant_id
                )
        except Exception as exc:
            log.error('Could not list security groups for cloud %s: %r',
                      self.cloud, exc)
            raise CloudUnavailableError(exc=exc)

        sec_groups = [{'id': sec_group.id,
                       'name': sec_group.name,
                       'tenant_id': sec_group.tenant_id,
                       'description': sec_group.description,
                       }
                      for sec_group in sec_groups]

        return sec_groups

    def _list_locations__fetch_locations(self):
        return self.connection.ex_list_availability_zones()

    def _list_locations__get_capabilities(self, libcloud_location):
        capabilities = [key for key, value in libcloud_location.extra.items()
                        if key in config.LOCATION_CAPABILITIES and
                        value is True]
        return capabilities

    def _generate_plan__parse_location(self, auth_context, location_search):
        # If a location string is not given, let openstack set
        # the default location
        if not location_search:
            from mist.api.clouds.models import CloudLocation
            return [CloudLocation()]

        locations = super()._generate_plan__parse_location(
            auth_context, location_search)
        # filter out locations that do not supoort compute resources
        return [location for location in locations
                if location.extra.get('compute', False) is True]

    def _generate_plan__parse_networks(self, auth_context, networks_dict,
                                       location):
        from mist.api.methods import list_resources
        from mist.api.networks.models import Network

        ret_dict = {}

        ret_dict['associate_floating_ip'] = True if networks_dict.get(
            'associate_floating_ip', True) is True else False

        networks = networks_dict.get('networks', [])
        ret_dict['networks'] = []

        # if multiple networks exist, network parameter must be defined
        if (len(networks) == 0 and Network.objects(cloud=self.cloud, missing_since=None).count() > 1):  # noqa
            raise BadRequestError('Multiple networks found, define a network to be more specific.')  # noqa

        for net in networks:
            try:
                [network], _ = list_resources(auth_context, 'network',
                                              search=net,
                                              cloud=self.cloud.id,
                                              limit=1)
            except ValueError:
                raise NotFoundError(f'Network {net} does not exist')

            ret_dict['networks'].append({'id': network.network_id,
                                         'name': network.name})

        try:
            security_groups = set(networks_dict.get('security_groups', []))
        except TypeError:
            raise BadRequestError('Invalid type for security groups')

        ret_dict['security_groups'] = []
        if security_groups:
            try:
                sec_groups = \
                    self.cloud.ctl.compute.connection.ex_list_security_groups(
                        tenant_id=self.cloud.tenant_id
                    )
            except Exception as exc:
                log.exception('Could not list security groups for cloud %s',
                              self.cloud)
                raise CloudUnavailableError(exc=exc) from None

            ret_dict['security_groups'] = list({
                sec_group.name for sec_group in sec_groups
                if sec_group.name in security_groups or
                sec_group.id in security_groups})

        return ret_dict

    def _generate_plan__parse_volume_attrs(self, volume_dict, vol_obj):
        delete_on_termination = True if volume_dict.get(
            'delete_on_termination', False) is True else False

        boot = True if volume_dict.get(
            'boot', False) is True else False

        return {
            'id': vol_obj.id,
            'name': vol_obj.name,
            'delete_on_termination': delete_on_termination,
            'boot': boot,
        }

    def _generate_plan__parse_custom_volume(self, volume_dict):
        try:
            size = int(volume_dict['size'])
        except KeyError:
            raise BadRequestError('Volume size is required')
        except (TypeError, ValueError):
            raise BadRequestError('Invalid volume size type')

        delete_on_termination = True if volume_dict.get(
            'delete_on_termination', False) is True else False

        boot = True if volume_dict.get(
            'boot', False) is True else False

        return {
            'size': size,
            'delete_on_termination': delete_on_termination,
            'boot': boot,
        }

    def _generate_plan__post_parse_plan(self, plan):
        volumes = plan.get('volumes', [])

        # make sure boot drive is first if it exists
        volumes.sort(key=lambda k: k['boot'],
                     reverse=True)

        if len(volumes) > 1:
            # make sure only one boot volume is set
            if volumes[1].get('boot') is True:
                raise BadRequestError('Up to 1 volume must be set as boot')

        plan['volumes'] = volumes

    def _create_machine__compute_kwargs(self, plan):
        from libcloud.compute.drivers.openstack import OpenStackSecurityGroup
        from libcloud.compute.drivers.openstack import OpenStackNetwork
        kwargs = super()._create_machine__compute_kwargs(plan)

        if kwargs.get('location'):
            kwargs['ex_availability_zone'] = kwargs.pop('location').name

        if plan.get('cloudinit'):
            kwargs['ex_userdata'] = plan['cloudinit']

        key = kwargs.pop('auth')
        try:
            openstack_keys = self.connection.list_key_pairs()
        except Exception as exc:
            log.exception('Failed to fetch keypairs')
            raise

        for openstack_key in openstack_keys:
            if key.public == openstack_key.public_key:
                server_key = openstack_key
                break
        else:
            try:
                server_key = self.connection.import_key_pair_from_string(
                    name=f'mistio-{secrets.token_hex(3)}',
                    key_material=key.public,
                )
            except Exception:
                log.exception('Failed to create keypair')
                raise
        kwargs['ex_keyname'] = server_key.name

        # use dummy objects with only the attributes needed
        kwargs['networks'] = [OpenStackNetwork(network['id'],
                                               None,
                                               None,
                                               self.connection)
                              for network in plan['networks']['networks']]

        kwargs['ex_security_groups'] = [
            OpenStackSecurityGroup(id=None,
                                   name=sec_group,
                                   tenant_id=None,
                                   description=None,
                                   driver=self.connection)
            for sec_group in plan['networks']['security_groups']
        ]

        blockdevicemappings = []
        for volume in plan['volumes']:
            mapping = {
                'delete_on_termination': volume['delete_on_termination'],
                'destination_type': 'volume',
            }
            if volume.get('id'):
                from mist.api.volumes.models import Volume
                vol = Volume.objects.get(id=volume['id'])
                if volume['boot'] is True:
                    mapping['boot_index'] = 0
                else:
                    mapping['boot_index'] = None
                mapping['uuid'] = vol.external_id
                mapping['source_type'] = 'volume'
            else:
                mapping['volume_size'] = volume['size']
                if volume['boot'] is True:
                    mapping['boot_index'] = 0
                    mapping['source_type'] = 'image'
                    mapping['uuid'] = kwargs.pop('image').id
                else:
                    mapping['boot_index'] = None
                    mapping['source_type'] = 'blank'
            blockdevicemappings.append(mapping)

        # This is a workaround for an issue which occurs only
        # when non-boot volumes are passed. Openstack expects a
        # block device mapping with boot_index 0.
        # http://lists.openstack.org/pipermail/openstack-dev/2015-March/059332.html  # noqa
        if (blockdevicemappings and
                blockdevicemappings[0]['boot_index'] is None):
            blockdevicemappings.insert(0, {'uuid': kwargs.pop('image').id,
                                           'source_type': 'image',
                                           'destination_type': 'local',
                                           'boot_index': 0,
                                           'delete_on_termination': True})

        kwargs['ex_blockdevicemappings'] = blockdevicemappings
        return kwargs

    def _create_machine__post_machine_creation_steps(self, node, kwargs, plan):
        if plan['networks']['associate_floating_ip'] is False:
            return

        # From the already created floating ips try to find one
        # that is not associated to a node
        floating_ips = self.connection.ex_list_floating_ips()
        unassociated_floating_ip = next((ip for ip in floating_ips
                                         if ip.status == 'DOWN'), None)

        # Find the ports which are associated to the machine
        # (e.g. the ports of the private ips)
        # and use one to associate a floating ip
        for _ in range(5):
            ports = self.connection.ex_list_ports()
            machine_port_id = next((port.id for port in ports
                                    if port.extra.get('device_id') == node.id),  # noqa
                                   None)
            if machine_port_id is None:
                # sleep in case a port has not been yet associated
                # with the machine
                time.sleep(5)
            else:
                break
        else:
            log.error('Unable to find machine port.'
                      'OpenstackCloud: %s, Machine external_id: %s',
                      self.cloud.id, node.id)
            return

        if unassociated_floating_ip:
            log.info('Associating floating ip with machine: %s', node.id)
            try:
                self.connection.ex_associate_floating_ip_to_node(
                    unassociated_floating_ip.id, machine_port_id)
            except BaseHTTPError:
                log.exception('Failed to associate ip address to node')
        else:
            # Find the external network
            networks = self.connection.ex_list_networks()
            ext_net_id = next((network.id for network in networks
                               if network.router_external is True),
                              None)
            if ext_net_id is None:
                log.error('Failed to find external network')
                return
            log.info('Create and associating floating ip with machine: %s',
                     node.id)
            try:
                self.connection.ex_create_floating_ip(ext_net_id,
                                                      machine_port_id)
            except BaseHTTPError:
                log.exception('Failed to create floating ip address')
