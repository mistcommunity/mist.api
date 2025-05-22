from libcloud.compute.providers import get_driver
from libcloud.compute.types import Provider
from mist.api.clouds.controllers.compute.base import BaseComputeController
from mist.api.clouds.controllers.compute.base import (
    log, copy, config, BadRequestError, NotFoundError, InternalServerError,
    node_to_dict, NodeState, BaseHTTPError
)

from mist.api.exceptions import InternalServerError
from mist.api.exceptions import BadRequestError
from mist.api.exceptions import NotFoundError
from mist.api.exceptions import CloudUnavailableError


class AmazonComputeController(BaseComputeController):

    def _connect(self, **kwargs):
        return get_driver(Provider.EC2)(self.cloud.apikey,
                                        self.cloud.apisecret.value,
                                        region=self.cloud.region)

    def _list_machines__machine_actions(self, machine, node_dict):
        super(AmazonComputeController, self)._list_machines__machine_actions(
            machine, node_dict)
        machine.actions.rename = True
        if node_dict['state'] != NodeState.TERMINATED.value:
            machine.actions.resize = True

    def _resize_machine(self, machine, node, node_size, kwargs):
        attributes = {'InstanceType.Value': node_size.id}
        # instance must be in stopped mode
        if node.state != NodeState.STOPPED:
            raise BadRequestError('The instance has to be stopped '
                                  'in order to be resized')
        try:
            self.connection.ex_modify_instance_attribute(node,
                                                         attributes)
            self.connection.ex_start_node(node)
        except Exception as exc:
            raise BadRequestError('Failed to resize node: %s' % exc)

    def _list_machines__postparse_machine(self, machine, node_dict):
        updated = False
        # This is windows for windows servers and None for Linux.
        os_type = node_dict['extra'].get('platform', 'linux')

        if machine.os_type != os_type:
            machine.os_type = os_type
            updated = True

        try:
            # return list of ids for network interfaces as str
            network_interfaces = node_dict['extra'].get(
                'network_interfaces', [])
            network_interfaces = [{
                'id': network_interface['id'],
                'state': network_interface['state'],
                'extra': network_interface['extra']
            } for network_interface in network_interfaces]
        except Exception as exc:
            log.warning("Cannot parse net ifaces for machine %s/%s/%s: %r" % (
                machine.name, machine.id, machine.owner.name, exc
            ))
            network_interfaces = []

        if network_interfaces != machine.extra.get('network_interfaces'):
            machine.extra['network_interfaces'] = network_interfaces
            updated = True

        network_id = node_dict['extra'].get('vpc_id')

        if machine.extra.get('network') != network_id:
            machine.extra['network'] = network_id
            updated = True

        # Discover network of machine.
        from mist.api.networks.models import Network
        try:
            network = Network.objects.get(cloud=self.cloud,
                                          external_id=network_id,
                                          missing_since=None)
        except Network.DoesNotExist:
            network = None

        if network != machine.network:
            machine.network = network
            updated = True

        subnet_id = machine.extra.get('subnet_id')
        if machine.extra.get('subnet') != subnet_id:
            machine.extra['subnet'] = subnet_id
            updated = True

        # Discover subnet of machine.
        from mist.api.networks.models import Subnet
        try:
            subnet = Subnet.objects.get(external_id=subnet_id,
                                        network=machine.network,
                                        missing_since=None)
        except Subnet.DoesNotExist:
            subnet = None
        if subnet != machine.subnet:
            machine.subnet = subnet
            updated = True

        return updated

    def _list_machines__cost_machine(self, machine, node_dict):
        # TODO: stopped instances still charge for the EBS device
        # https://aws.amazon.com/ebs/pricing/
        # Need to add this cost for all instances
        if node_dict['state'] != NodeState.RUNNING.value:
            return 0, 0

        # getting the pricing data each time is inefficient
        # for now it will be saved in the controller
        # in the future it should be cached
        if not hasattr(self, 'pricing_data'):
            self.pricing_data = {}

        if not machine.image or not machine.image.name:
            pricing_driver_name = 'ec2_linux'
        elif 'high availability' in machine.image.name.lower():
            pricing_driver_name = 'ec2_rhel_ha'
        elif 'rhel' in machine.image.name.lower():
            pricing_driver_name = 'ec2_rhel'
        elif 'suse' in machine.image.name.lower():
            pricing_driver_name = 'ec2_suse'
        else:
            pricing_driver_name = f'ec2_{machine.image.os_type}'

        if not self.pricing_data.get(pricing_driver_name):
            try:
                self.pricing_data[pricing_driver_name] = get_pricing(
                    'compute', pricing_driver_name)
            except KeyError:
                log.error(f"Error while trying to get pricing data for "
                          f"machine f{machine.name} with id f{machine.id} "
                          f"Could not find prices for {pricing_driver_name}."
                          f"Will return 0 for this machine's cost")
                return 0, 0

        size = self._list_machines__get_size(node_dict)

        try:
            location = machine.location.name
        except AttributeError:
            return 0, 0

        # Remove last letter if it is there.
        # eg. remove last 'a' from 'ap-northeast-1a'
        if location[-1].isalpha():
            location = location[:-1]

        # This is an exception which might change in the future.
        # For now prices for mac1.metal or mac2.metal
        # are under ec2_linux -> mac1 (or mac2).
        # mac1.metal and mac2.metal have price 0 for all regions.
        if size == 'mac1.metal':
            size = 'mac1'
        if size == 'mac2.metal':
            size = 'mac2'
        cost = self.pricing_data[pricing_driver_name].get(
            size, {}).get(location, 0)
        return cost, 0

    def _list_machines__get_location(self, node):
        return node['extra'].get('availability')

    def _list_machines__get_size(self, node):
        return node['extra'].get('instance_type')

    def _list_images__fetch_images(self, search=None):
        if not search:
            from mist.api.images.models import CloudImage
            images_file = os.path.join(config.MIST_API_DIR,
                                       config.EC2_IMAGES_FILE)
            with open(images_file, 'r') as f:
                default_images = json.load(f)[self.cloud.region]

            image_ids = list(default_images.keys())
            try:
                # this might break if image_ids contains starred images
                # that are not valid anymore for AWS
                images = self.connection.list_images(None, image_ids)
            except Exception as e:
                bad_ids = re.findall(r'ami-\w*', str(e), re.DOTALL)
                for bad_id in bad_ids:
                    try:
                        _image = CloudImage.objects.get(cloud=self.cloud,
                                                        external_id=bad_id)
                        _image.delete()
                    except CloudImage.DoesNotExist:
                        log.error('Image %s not found in cloud %r' % (
                            bad_id, self.cloud
                        ))
                keys = list(default_images.keys())
                try:
                    images = self.connection.list_images(None, keys)
                except BaseHTTPError as e:
                    if 'UnauthorizedOperation' in str(e.message):
                        images = []
                    else:
                        raise
            for image in images:
                if image.id in default_images:
                    image.name = default_images[image.id]
            try:
                images += self.connection.list_images(ex_owner='self')
            except BaseHTTPError as e:
                if 'UnauthorizedOperation' in str(e.message):
                    pass
                else:
                    raise
        else:
            # search on EC2.
            search = search.lstrip()
            filters = [
                {
                    'image-id': search,
                    'image-type': 'machine',
                },
                {
                    'name': '%s*' % search,
                    'image-type': 'machine',
                },
                {
                    'description': '*%s*' % search,
                    'image-type': 'machine',
                },
            ]
            images = []
            for filter_ in filters:
                try:
                    images = self.connection.list_images(
                        ex_filters=filter_)
                except BaseHTTPError as e:
                    if 'UnauthorizedOperation' in str(e.message):
                        break
                    else:
                        raise
                else:
                    if images:
                        break

            def sort_by_owner(libcloud_image):
                """Sort images fetched based on the owner alias.

                Give priority first to Amazon's own images,
                then self and `None` and finally marketplace.
                """
                owner_alias = libcloud_image.extra.get('owner_alias')
                if owner_alias == 'amazon':
                    return 0
                if owner_alias == 'self':
                    return 1
                if owner_alias is None:
                    return 2
                if owner_alias == 'aws-marketplace':
                    return 3
                return 4

            images = sorted(images, key=sort_by_owner)[:50]

        return images

    def _list_machines__get_machine_cluster(self,
                                            machine,
                                            node):
        # Nodes belonging to an EKS Cluster automatically get assigned
        # the 'eks:cluster-name' tag.
        try:
            cluster_name = node['extra']['tags']['eks:cluster-name']
        except KeyError:
            return None

        from mist.api.containers.models import Cluster
        cluster = None
        try:
            cluster = Cluster.objects.get(name=cluster_name,
                                          cloud=self.cloud,
                                          missing_since=None)
        except Cluster.DoesNotExist as exc:
            log.warn('Error getting cluster of %s: %r', machine, exc)

        return cluster

    def image_is_default(self, image_id):
        return image_id in config.EC2_IMAGES[self.cloud.region]

    def _list_locations__fetch_locations(self):
        """List availability zones for EC2 region
        """
        from libcloud.compute.base import NodeLocation
        locations = self.connection.list_locations()
        region = NodeLocation(id=self.cloud.region,
                              name=self.cloud.region,
                              country=self.connection.country,
                              driver=self.connection,
                              extra={})
        locations.insert(0, region)
        return locations

    def _list_locations__get_parent(self, location, libcloud_location):
        from mist.api.clouds.models import CloudLocation
        if libcloud_location.id == self.cloud.region:
            return None

        try:
            parent = CloudLocation.objects.get(
                external_id=self.cloud.region,
                cloud=self.cloud,
                missing_since=None)
            return parent
        except me.DoesNotExist:
            log.error('Parent does not exist for Location: %s',
                      location.id)

    def _list_locations__get_type(self, location, libcloud_location):
        if libcloud_location.id == self.cloud.region:
            return 'region'
        return 'zone'

    def _list_sizes__get_cpu(self, size):
        return int(size.extra.get('vcpu', 1))

    def _list_sizes__get_name(self, size):
        return '%s - %s' % (size.id, size.name)

    def _list_sizes__get_architecture(self, size):
        """Arm-based sizes use Amazon's Graviton processor
        """
        if 'graviton' in size.extra.get('physicalProcessor', '').lower():
            return 'arm'
        return 'x86'

    def _list_images__get_os_type(self, image):
        # os_type is needed for the pricing per VM
        if image.name:
            if any(x in image.name.lower() for x in ['sles',
                                                     'suse linux enterprise']):
                return 'sles'
            if any(x in image.name.lower() for x in ['rhel', 'red hat']):
                return 'rhel'
            if 'windows' in image.name.lower():
                if 'sql' in image.name.lower():
                    if 'web' in image.name.lower():
                        return 'mswinSQLWeb'
                    return 'mswinSQL'
                return 'mswin'
            if 'vyatta' in image.name.lower():
                return 'vyatta'
            return 'linux'

    def _list_images__get_architecture(self, image):
        architecture = image.extra.get('architecture')
        if architecture == 'arm64':
            return ['arm']
        return ['x86']

    def _list_images__get_origin(self, image):
        if image.extra.get('is_public', 'true').lower() == 'true':
            return 'system'
        return 'custom'

    def _list_security_groups(self):
        try:
            sec_groups = \
                self.cloud.ctl.compute.connection.ex_list_security_groups()
        except Exception as exc:
            log.error('Could not list security groups for cloud %s: %r',
                      self.cloud, exc)
            raise CloudUnavailableError(exc=exc)

        return sec_groups

    def _generate_plan__parse_networks(self, auth_context, network_dict,
                                       location):
        security_group = network_dict.get('security_group')
        subnet = network_dict.get('subnet')

        networks = {}
        sec_groups = self.connection.ex_list_security_groups()
        if security_group:
            for sec_group in sec_groups:
                if (security_group == sec_group['id'] or
                        security_group == sec_group['name']):
                    networks['security_group'] = {
                        'name': sec_group['name'],
                        'id': sec_group['id']
                    }
                    break
            else:
                raise NotFoundError('Security group not found: %s'
                                    % security_group)
        else:
            # check if default security_group already exists
            for sec_group in sec_groups:
                if sec_group['name'] == config.EC2_SECURITYGROUP.get('name',
                                                                     ''):
                    networks['security_group'] = {
                        'name': sec_group['name'],
                        'id': sec_group['id']
                    }
                    break
            else:
                networks['security_group'] = {
                    'name': config.EC2_SECURITYGROUP.get('name', ''),
                    'description':
                        config.EC2_SECURITYGROUP.get('description', '').format(
                            portal_name=config.PORTAL_NAME)
                }

        if subnet:
            # APIv1 also searches for amazon's id
            from mist.api.methods import list_resources
            subnets, _ = list_resources(auth_context, 'subnet',
                                        search=subnet,
                                        )
            subnets = [subnet for subnet in subnets
                       if subnet.network.cloud == self.cloud]
            if len(subnets) == 0:
                raise NotFoundError('Subnet not found %s' % subnet)

            networks['subnet'] = subnets[0].id

        return networks

    def _generate_plan__parse_volume_attrs(self, volume_dict, vol_obj):
        if not volume_dict.get('device'):
            raise BadRequestError('Device is mandatory'
                                  ' when attaching a volume')
        ret_dict = {
            'id': vol_obj.id,
            'device': volume_dict['device']
        }
        return ret_dict

    def _generate_plan__parse_custom_volume(self, volume_dict):
        size = volume_dict.get('size')
        name = volume_dict.get('name')
        volume_type = volume_dict.get('volume_type')
        iops = volume_dict.get('iops')
        delete_on_termination = volume_dict.get('delete_on_termination')

        if size is None or name is None:
            raise BadRequestError('Volume required parameter missing')

        ret_dict = {
            'size': size,
            'name': name,
            'volume_type': volume_type,
            'iops': iops,
            'delete_on_termination': delete_on_termination
        }

        return ret_dict

    def _create_machine__get_location_object(self, location):
        from libcloud.compute.drivers.ec2 import ExEC2AvailabilityZone
        location_obj = super()._create_machine__get_location_object(location)
        location_obj.availability_zone = ExEC2AvailabilityZone(
            name=location_obj.name,
            zone_state=None,
            region_name=self.connection.region_name
        )
        return location_obj

    def _create_machine__compute_kwargs(self, plan):
        kwargs = super()._create_machine__compute_kwargs(plan)
        kwargs['ex_keyname'] = kwargs['auth'].name
        kwargs['auth'] = NodeAuthSSHKey(pubkey=kwargs['auth'].public)

        kwargs['ex_userdata'] = plan.get('cloudinit', '')
        security_group = plan['networks']['security_group']
        # if id is not given, then default security group does not exist
        if not security_group.get('id'):
            try:
                log.info('Attempting to create security group')
                ret_dict = self.connection.ex_create_security_group(
                    name=plan['networks']['security_group']['name'],
                    description=plan['networks']['security_group']['description']  # noqa
                )
                self.connection.ex_authorize_security_group_permissive(
                    name=plan['networks']['security_group']['name'])
            except Exception as exc:
                raise InternalServerError(
                    "Couldn't create security group", exc)
            else:
                security_group['id'] = ret_dict['group_id']

        subnet_id = plan['networks'].get('subnet')
        if subnet_id:
            from mist.api.networks.models import Subnet
            subnet = Subnet.objects.get(id=subnet_id)
            subnet_external_id = subnet.subnet_id

            # TODO check if the following API call is not needed
            # and instead instantiate an EC2NetworkSubnet object
            # libcloud.compute.drivers.ec2.EC2NetworkSubnet
            libcloud_subnets = self.connection.ex_list_subnets()
            for libcloud_subnet in libcloud_subnets:
                if libcloud_subnet.id == subnet_external_id:
                    subnet = libcloud_subnet
                    break
            else:
                raise NotFoundError('Subnet specified does not exist')
            # if subnet is specified, then security group id
            # instead of security group name is needed
            kwargs.update({
                'ex_subnet': subnet,
                'ex_security_group_ids': security_group['id']
            })
        else:
            kwargs.update({
                'ex_securitygroup': plan['networks']['security_group']['name']
            })
        mappings = []
        for volume in plan.get('volumes', []):
            # here only the mappings are handled
            # volumes will be created and attached after machine creation
            if not volume.get('id'):
                mapping = {}
                mapping.update({'Ebs':
                                {'VolumeSize': int(volume.get('size'))}})
                if volume.get('name'):
                    mapping.update({'DeviceName': volume.get('name')})
                if volume.get('volume_type'):
                    volume_type = {'VolumeType': volume.get('volume_type')}
                    mapping['Ebs'].update(volume_type)
                if volume.get('iops'):
                    mapping['Ebs'].update({'Iops': volume.get('iops')})
                if volume.get('delete_on_termination'):
                    delete_on_term = volume.get('delete_on_termination')
                    mapping['Ebs'].update({
                        'DeleteOnTermination': delete_on_term})
                mappings.append(mapping)
        kwargs.update({'ex_blockdevicemappings': mappings})
        return kwargs

    def _create_machine__post_machine_creation_steps(self, node, kwargs, plan):
        volumes = []
        for volume in plan.get('volumes', []):
            if volume.get('id'):
                from mist.api.volumes.models import Volume
                from libcloud.compute.base import StorageVolume
                vol = Volume.objects.get(id=volume['id'])
                libcloud_vol = StorageVolume(id=vol.external_id,
                                             name=vol.name,
                                             size=vol.size,
                                             driver=self.connection,
                                             extra=vol.extra)
                ex_vol = {
                    'volume': libcloud_vol,
                    'device': volume.get('device')
                }
                volumes.append(ex_vol)
        if volumes:
            ready = False
            while not ready:
                lib_nodes = self.connection.list_nodes()
                for lib_node in lib_nodes:
                    if lib_node.id == node.id and lib_node.state == 'running':
                        ready = True
            for volume in volumes:
                self.connection.attach_volume(node, volume.get('volume'),
                                              volume.get('device'))

    def _list_machines__get_machine_extra(self, machine, node_dict):
        extra = copy.copy(node_dict['extra'])
        nodepool_name = extra.get(
            'tags', {}).get('eks:nodegroup-name', '')
        if nodepool_name:
            extra['nodepool'] = nodepool_name
        return extra
