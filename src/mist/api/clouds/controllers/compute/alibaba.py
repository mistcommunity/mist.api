from libcloud.compute.providers import get_driver
from libcloud.compute.types import Provider
from mist.api.clouds.controllers.compute.base import BaseComputeController
from mist.api.clouds.controllers.compute.base import (
    log, copy, config, BadRequestError, NotFoundError, InternalServerError,
    node_to_dict, NodeState, BaseHTTPError
)
from mist.api.clouds.controllers.compute.amazon import AmazonComputeController

from mist.api.exceptions import BadRequestError
from mist.api.exceptions import NotFoundError
from mist.api.exceptions import MachineCreationError


class AlibabaComputeController(AmazonComputeController):

    def _connect(self, **kwargs):
        return get_driver(Provider.ALIYUN_ECS)(self.cloud.apikey,
                                               self.cloud.apisecret.value,
                                               region=self.cloud.region)

    def _resize_machine(self, machine, node, node_size, kwargs):
        # instance must be in stopped mode
        if node.state != NodeState.STOPPED:
            raise BadRequestError('The instance has to be stopped '
                                  'in order to be resized')
        try:
            self.connection.ex_resize_node(node, node_size.id)
            self.connection.ex_start_node(node)
        except Exception as exc:
            raise BadRequestError('Failed to resize node: %s' % exc)

    def _list_machines__get_location(self, node):
        return node['extra'].get('zone_id')

    def _list_machines__cost_machine(self, machine, node_dict):
        size = node_dict['extra'].get('instance_type', {})
        driver_name = 'ecs-' + node_dict['extra'].get('zone_id')
        price = get_pricing(
            driver_type='compute', driver_name=driver_name).get(size, {})
        image = node_dict['extra'].get('image_id', '')
        if 'win' in image:
            price = price.get('windows', '')
        else:
            price = price.get('linux', '')
        if node_dict['extra'].get('instance_charge_type') == 'PostPaid':
            return (price.get('pay_as_you_go', 0), 0)
        else:
            return (0, price.get('prepaid', 0))

    def _list_machines__machine_creation_date(self, machine, node_dict):
        return node_dict['extra'].get('creation_time')

    def _list_images__fetch_images(self, search=None):
        return self.connection.list_images()

    def image_is_default(self, image_id):
        return True

    def _list_images__get_os_type(self, image):
        if image.extra.get('os_type', ''):
            return image.extra.get('os_type').lower()
        if 'windows' in image.name.lower():
            return 'windows'
        else:
            return 'linux'

    def _list_locations__fetch_locations(self):
        """List ECS regions as locations, embed info about zones

        In EC2 all locations of a region have the same name, so the
        availability zones are listed instead.

        """
        zones = self.connection.ex_list_zones()
        locations = []
        for zone in zones:
            extra = {
                'name': zone.name,
                'available_disk_categories': zone.available_disk_categories,
                'available_instance_types': zone.available_instance_types,
                'available_resource_types': zone.available_resource_types
            }
            location = NodeLocation(
                id=zone.id, name=zone.id, country=zone.id, driver=zone.driver,
                extra=extra
            )
            locations.append(location)
        return locations

    def _list_locations__get_available_sizes(self, location):
        from mist.api.clouds.models import CloudSize
        return CloudSize.objects(cloud=self.cloud,
                                 external_id__in=location.extra['available_instance_types'])  # noqa

    def _list_sizes__get_cpu(self, size):
        return size.extra['cpu_core_count']

    def _list_sizes__get_name(self, size):
        specs = str(size.extra['cpu_core_count']) + ' cpus/ ' \
            + str(size.ram / 1024) + 'Gb RAM '
        return "%s (%s)" % (size.name, specs)

    def _list_images__get_os_distro(self, image):
        try:
            os_distro = image.extra.get('platform').lower()
        except AttributeError:
            return super()._list_images__get_os_distro(image)

        if 'windows' in os_distro:
            os_distro = 'windows'
        return os_distro

    def _list_images__get_min_disk_size(self, image):
        try:
            min_disk_size = int(image.extra.get('size'))
        except (TypeError, ValueError):
            return None
        return min_disk_size

    def _list_images__get_origin(self, image):
        """ `image_owner_alias` valid values are:

            system: public images provided by alibaba
            self: account's custom images
            others: shared images from other accounts
            marketplace: alibaba marketplace images
        """
        owner = image.extra.get('image_owner_alias', 'system')
        if owner == 'system':
            return 'system'
        elif owner == 'marketplace':
            return 'marketplace'
        else:
            return 'custom'

    def _generate_plan__parse_networks(self, auth_context, networks_dict,
                                       location):
        from mist.api.methods import list_resources
        ret_dict = {}

        network_search = networks_dict.get('network', '')
        networks, count = list_resources(auth_context,
                                         'network',
                                         search=network_search,
                                         cloud=self.cloud.id,
                                         )
        if count == 0:
            raise NotFoundError(f'Network "{network_search}" not found')

        subnet_search = networks_dict.get('subnet',
                                          config.ECS_SWITCH.get('name'))
        subnets, _ = list_resources(auth_context,
                                    'subnet',
                                    search=subnet_search,
                                    )
        subnets = subnets.filter(network__in=networks)
        subnets = [subnet for subnet in subnets
                   if subnet.extra['zone_id'] == location.external_id]
        if len(subnets) == 0:
            # Subnet will be created later on the first network found
            ret_dict['network'] = {
                'id': networks[0].id,
                'name': networks[0].name,
                'external_id': networks[0].network_id,
            }
            ret_dict['subnet'] = {
                'name': subnet_search,
            }
        else:
            subnet = subnets[0]
            ret_dict['network'] = {
                'id': subnet.network.id,
                'name': subnet.network.name,
                'external_id': subnet.network.network_id,
            }
            ret_dict['subnet'] = {
                'id': subnet.id,
                'name': subnet.name,
                'external_id': subnet.subnet_id,
            }

        try:
            ret_dict['security_group'] = networks_dict['security_group']
        except KeyError:
            ret_dict['security_group'] = config.EC2_SECURITYGROUP.get('name')

        return ret_dict

    def _generate_plan__parse_volume_attrs(self, volume_dict, vol_obj):
        delete_on_termination = True if volume_dict.get(
            'delete_on_termination', False) is True else False

        return {
            'id': vol_obj.id,
            'name': vol_obj.name,
            'delete_on_termination': delete_on_termination,
        }

    def _generate_plan__parse_custom_volume(self, volume_dict):
        try:
            name = volume_dict['name']
            size = int(volume_dict['size'])
        except KeyError:
            raise BadRequestError('Volume name & size are required parameters')
        except (TypeError, ValueError):
            raise BadRequestError('Invalid size type')

        type_ = volume_dict.get('type', config.ALIBABA_DEFAULT_VOLUME_TYPE)
        try:
            min_valid, max_valid = config.ALIBABA_VOLUME_TYPES[type_]
        except KeyError:
            raise BadRequestError(
                f'Permitted volume types are: '
                f'{*config.ALIBABA_VOLUME_TYPES.keys(),}')

        if size not in range(min_valid, max_valid + 1):
            raise BadRequestError(
                f"Valid size values for '{type_}' type are "
                f"{min_valid} to {max_valid}"
            )

        delete_on_termination = True if volume_dict.get(
            'delete_on_termination', False) is True else False

        return {
            'name': name,
            'size': size,
            'type': type_,
            'delete_on_termination': delete_on_termination,
        }

    def _create_machine__get_location_object(self, location):
        # Redefine method to avoid calling Amazon's
        # corresponding method
        return BaseComputeController._create_machine__get_location_object(
            self, location)

    def _create_machine__compute_kwargs(self, plan):
        kwargs = BaseComputeController._create_machine__compute_kwargs(
            self, plan)
        kwargs['ex_zone_id'] = kwargs.pop('location').id
        kwargs['ex_keyname'] = kwargs['auth'].name
        kwargs['auth'] = NodeAuthSSHKey(pubkey=kwargs['auth'].public)
        if plan.get('cloudinit'):
            kwargs['ex_userdata'] = plan['cloudinit']

        vpc_id = plan['networks']['network']['external_id']
        sec_group_name = plan['networks']['security_group']
        security_groups = self.connection.ex_list_security_groups(
            ex_filters={
                'VpcId': vpc_id,
                'SecurityGroupName': sec_group_name
            }
        )
        if security_groups:
            sec_group_id = security_groups[0].id
        else:
            description = config.EC2_SECURITYGROUP['description'].format(
                portal_name=config.PORTAL_NAME
            )
            sec_group_id = self.connection.ex_create_security_group(
                name=sec_group_name,
                description=description,
                vpc_id=vpc_id)
            self.connection.ex_authorize_security_group(
                group_id=sec_group_id,
                description='Allow SSH',
                ip_protocol='tcp',
                port_range='22/22')
        kwargs['ex_security_group_id'] = sec_group_id

        subnet_id = plan['networks']['subnet'].get('external_id')
        if subnet_id:
            kwargs['ex_vswitch_id'] = subnet_id
        else:
            from mist.api.networks.models import AlibabaNetwork, AlibabaSubnet
            network = AlibabaNetwork.objects.get(
                id=plan['networks']['network']['id'],
                cloud=self.cloud)
            cidr_network = ipaddress.IPv4Network(network.cidr)
            # decide the subnet mask length
            mask_length = config.ECS_SWITCH_CIDR_BLOCK_LENGTH
            prefix = (mask_length
                      if cidr_network.prefixlen < mask_length
                      else cidr_network.prefixlen + 2)
            if prefix > 32:
                prefix = 32
            subnets = AlibabaSubnet.objects(network=network,
                                            missing_since=None)
            subnet_cidrs = [ipaddress.IPv4Network(subnet.cidr)
                            for subnet in subnets]
            # Find an available CIDR block for the new subnet
            for subnet in cidr_network.subnets(new_prefix=prefix):
                overlaps = any((
                    subnet.supernet_of(
                        subnet_cidr) or subnet.subnet_of(subnet_cidr)
                    for subnet_cidr in subnet_cidrs))
                if not overlaps:
                    subnet_cidr_block = subnet.exploded
                    break
            else:
                raise MachineCreationError(
                    'Could not find available switch(subnet)')

            subnet_name = plan['networks']['subnet']['name']
            description = config.ECS_SWITCH['description'].format(
                portal_name=config.PORTAL_NAME
            )
            kwargs['ex_vswitch_id'] = self.connection.ex_create_switch(
                subnet_cidr_block,
                kwargs['ex_zone_id'],
                vpc_id,
                name=subnet_name,
                description=description)
            # make sure switch is available to use
            for _ in range(10):
                switches = self.cloud.ctl.compute.connection.ex_list_switches(
                    ex_filters={'VSwitchId': kwargs['ex_vswitch_id']})
                if switches and switches[0].extra['status'] == 'Available':
                    break
                time.sleep(5)
        # already existing volumes cannot be passed as parameters
        # to the createInstance API  endpoint,
        # so they will be attached after machine creation
        new_volumes = []
        for volume in plan.get('volumes', []):
            if volume.get('id') is None:
                # create_node expect category instead of type
                volume['category'] = volume['type']
                new_volumes.append(volume)
        if new_volumes:
            kwargs['ex_data_disks'] = new_volumes

        kwargs['max_tries'] = 1
        kwargs['ex_io_optimized'] = True
        kwargs['ex_allocate_public_ip_address'] = True
        kwargs['ex_internet_charge_type'] = 'PayByTraffic'
        kwargs['ex_internet_max_bandwidth_out'] = 100

        return kwargs

    def _create_machine__post_machine_creation_steps(self, node, kwargs, plan):
        from mist.api.volumes.models import Volume
        from libcloud.compute.base import StorageVolume
        existing_volumes = [
            volume for volume in plan.get('volumes', [])
            if volume.get('id')
        ]
        if len(existing_volumes) == 0:
            return
        # wait for node to be running
        for _ in range(10):
            nodes = self.connection.list_nodes(ex_node_ids=[node.id])
            if nodes and nodes[0].state == 'running':
                break
            time.sleep(5)
        for volume in existing_volumes:
            vol = Volume.objects.get(id=volume['id'])
            libcloud_vol = StorageVolume(id=vol.external_id,
                                         name=vol.name,
                                         size=vol.size,
                                         driver=self.connection)
            try:
                self.connection.attach_volume(
                    node,
                    libcloud_vol,
                    ex_delete_with_instance=volume['delete_on_termination'])
            except Exception as exc:
                log.exception('Failed to attach volume')
