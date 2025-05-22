import re
import iso8601
import pytz
import mongoengine as me

from libcloud.compute.base import NodeAuthSSHKey, NodeAuthPassword
from libcloud.compute.providers import get_driver
from libcloud.compute.types import Provider

from libcloud.pricing import get_size_price, get_pricing
from libcloud.pricing import _get_gce_image_price

from mist.api.clouds.controllers.compute.base import BaseComputeController
from mist.api.clouds.controllers.compute.base import (
    log, copy, config, BadRequestError, NotFoundError, InternalServerError,
    node_to_dict, NodeState, BaseHTTPError
)

from mist.api.exceptions import BadRequestError
from mist.api.exceptions import NotFoundError


class GoogleComputeController(BaseComputeController):

    def _connect(self, **kwargs):
        return get_driver(Provider.GCE)(self.cloud.email,
                                        self.cloud.private_key.value,
                                        project=self.cloud.project_id)

    def _list_machines__get_machine_extra(self, machine, node_dict):
        # FIXME: we delete the extra.metadata for now because it can be
        # > 40kb per machine on GCE clouds with enabled GKE, causing the
        # websocket to overload and hang and is also a security concern.
        # We should revisit this and see if there is some use for this
        # metadata and if there are other fields that should be filtered
        # as well

        extra = copy.copy(node_dict['extra'])

        for key in list(extra.keys()):
            if key in ['metadata']:
                # check for nodepool
                try:
                    kube_labels = extra[key]['items'][3]
                except (IndexError, KeyError):
                    kube_labels = {}
                if kube_labels.get('key', '') == 'kube-labels':
                    # value is a super long string that contains
                    # `,gke-nodepool=xxxx,` among others
                    value = kube_labels.get('value', '')
                    result = re.search('gke-nodepool=', value)
                    if result:
                        index = result.span()[1]
                        nodepool_name = value[index:]
                        # remove anything after first ,
                        nodepool_name = nodepool_name[:nodepool_name.find(',')]
                        extra['nodepool'] = nodepool_name
                del extra[key]
        for disk in extra.get('disks', []):
            disk.pop('shieldedInstanceInitialState', None)
            disk.pop('source', None)
            disk.pop('licenses', None)
        return extra

    def _list_machines__machine_creation_date(self, machine, node_dict):
        try:
            created_at = node_dict['extra']['creationTimestamp']
        except KeyError:
            return None

        try:
            created_at = iso8601.parse_date(created_at)
        except iso8601.ParseError as exc:
            log.error(str(exc))
            return created_at

        created_at = pytz.UTC.normalize(created_at)
        return created_at

    def _list_machines__get_custom_size(self, node):
        machine_type = node['extra'].get('machineType', "").split("/")[-1]
        size = self.connection.ex_get_size(machine_type,
                                           node['extra']['zone'].get('name'))
        # create object only if the size of the node is custom
        if 'custom' in size.name:
            # FIXME: resolve circular import issues
            from mist.api.clouds.models import CloudSize
            _size = CloudSize(cloud=self.cloud, external_id=size.id)
            _size.ram = size.ram
            _size.cpus = size.extra.get('guestCpus')
            _size.name = size.name
            _size.save()
            return _size

    def _list_machines__postparse_machine(self, machine, node_dict):
        updated = False
        extra = node_dict['extra']

        # Wrap in try/except to prevent from future GCE API changes.
        # Identify server OS.
        os_type = 'linux'
        extra_os_type = None

        try:
            license = extra.get('license')
            if license:
                if 'sles' in license:
                    extra_os_type = 'sles'
                if 'rhel' in license:
                    extra_os_type = 'rhel'
                if 'win' in license:
                    extra_os_type = 'win'
                    os_type = 'windows'
            if extra.get('disks') and extra['disks'][0].get('licenses') and \
                    'windows-cloud' in extra['disks'][0]['licenses'][0]:
                os_type = 'windows'
                extra_os_type = 'win'
            if extra_os_type and machine.extra.get('os_type') != extra_os_type:
                machine.extra['os_type'] = extra_os_type
                updated = True
            if machine.os_type != os_type:
                machine.os_type = os_type
                updated = True
        except:
            log.exception("Couldn't parse os_type for machine %s:%s for %s",
                          machine.id, machine.name, self.cloud)

        # Get disk metadata.
        try:
            if extra.get('boot_disk'):
                if machine.extra.get('boot_disk_size') != extra[
                        'boot_disk'].get('size'):
                    machine.extra['boot_disk_size'] = extra['boot_disk'].get(
                        'size')
                    updated = True
                if machine.extra.get('boot_disk_type') != extra[
                        'boot_disk'].get('extra', {}).get('type'):
                    machine.extra['boot_disk_type'] = extra[
                        'boot_disk'].get('extra', {}).get('type')
                    updated = True
                if machine.extra.get('boot_disk'):
                    machine.extra.pop('boot_disk')
                    updated = True
        except:
            log.exception("Couldn't parse disk for machine %s:%s for %s",
                          machine.id, machine.name, self.cloud)

        # Get zone name.
        try:
            if extra.get('zone'):
                if machine.extra.get('zone') != extra.get('zone',
                                                          {}).get('name'):
                    machine.extra['zone'] = extra.get('zone', {}).get('name')
                    updated = True
        except:
            log.exception("Couldn't parse zone for machine %s:%s for %s",
                          machine.id, machine.name, self.cloud)

        # Get machine type.
        try:
            if extra.get('machineType'):
                machine_type = extra['machineType'].split('/')[-1]
                if machine.extra.get('machine_type') != machine_type:
                    machine.extra['machine_type'] = machine_type
                    updated = True
        except:
            log.exception("Couldn't parse machine type "
                          "for machine %s:%s for %s",
                          machine.id, machine.name, self.cloud)

        network_interface = node_dict['extra'].get(
            'networkInterfaces')[0]
        network = network_interface.get('network')
        network_name = network.split('/')[-1]
        if machine.extra.get('network') != network_name:
            machine.extra['network'] = network_name
            updated = True

        # Discover network of machine.
        from mist.api.networks.models import Network
        try:
            network = Network.objects.get(cloud=self.cloud,
                                          name=network_name,
                                          missing_since=None)
        except Network.DoesNotExist:
            network = None

        if machine.network != network:
            machine.network = network
            updated = True

        subnet = network_interface.get('subnetwork')
        if subnet:
            subnet_name = subnet.split('/')[-1]
            subnet_region = subnet.split('/')[-3]
            if machine.extra.get('subnet') != (subnet_name, subnet_region):
                machine.extra['subnet'] = (subnet_name, subnet_region)
                updated = True
            # Discover subnet of machine.
            from mist.api.networks.models import Subnet
            try:
                subnet = Subnet.objects.get(name=subnet_name,
                                            network=machine.network,
                                            region=subnet_region,
                                            missing_since=None)
            except Subnet.DoesNotExist:
                subnet = None
            if subnet != machine.subnet:
                machine.subnet = subnet
                updated = True

            return updated

    def _list_machines__machine_actions(self, machine, node_dict):
        super(GoogleComputeController,
              self)._list_machines__machine_actions(machine, node_dict)
        machine.actions.resize = True

    def _list_images__fetch_images(self, search=None):
        images = self.connection.list_images()
        # GCE has some objects in extra so we make sure they are not passed.
        for image in images:
            image.extra.pop('licenses', None)
        return images

    def _list_machines__cost_machine(self, machine, node_dict):
        if node_dict['state'] == NodeState.STOPPED.value or not machine.size:
            return 0, 0
        # eg n1-standard-1 (1 vCPU, 3.75 GB RAM)
        machine_cpu = float(machine.size.cpus)
        machine_ram = float(machine.size.ram) / 1024
        # example is `t2d-standard-1 (1 vCPUs, 4 GB RAM)`` we want just `t2d`
        # get size without the `x vCPUs y GB RAM` part
        size_type = machine.size.name.split(" ")[0]
        # make sure the format is as expected
        index = size_type.find('-')
        # remove the `-standard-1` like part
        if index != -1:
            size_type = size_type[0:index]
        else:
            size_type = size_type[0:2]
            log.warn(
                f'Machine {machine.name} with id {machine.id} has unexpected '
                f'size name: {machine.size.name}, will use size type '
                f'{size_type} to determine machine cost.'
            )
        if "custom" in machine.size.name:
            size_type += "_custom"
            if machine.size.name.startswith('custom'):
                size_type = 'n1_custom'
        usage_type = "on_demand"
        if "preemptible" in machine.size.name.lower():
            usage_type = "preemptible"
        if "1yr" in machine.size.name.lower():
            usage_type = '1yr_commitment'
        if "3yr" in machine.size.name.lower():
            usage_type = '3yr_commitment'
        default_location = "us-central1"
        location = node_dict['extra'].get('zone', {}).get('name')
        # could be europe-west1-d, we want europe-west1
        location = '-'.join(location.split('-')[:2])
        disk_type = machine.extra.get('boot_disk_type') or \
            node_dict['extra'].get('boot_disk',
                                   {}).get('extra',
                                           {}).get('type')
        disk_usage_type = "on_demand"
        disk_size = 0
        for disk in machine.extra['disks']:
            disk_size += float(disk['diskSizeGb'])
        if 'regional' in disk_type:
            if 'standard' in disk_type:
                disk_type = 'Regional Standard'
            elif 'ssd' in disk_type:
                disk_type = 'Regional SSD'
        elif 'local' in disk_type:
            if 'preemptible' in disk_type:
                disk_usage_type = 'preemptible'
            elif '1yr' in disk_type:
                disk_usage_type = '1yr_commitment'
            elif '3yr' in disk_type:
                disk_usage_type = '3yr_commitment'
            disk_type = 'Local SSD'
        elif 'standard' in disk_type:
            disk_type = 'Standard'
        elif 'ssd' in disk_type:
            disk_type = 'SSD'

        disk_prices = get_pricing(driver_type='compute',
                                  driver_name='gce_disks').get(disk_type, {})
        gce_instance = get_pricing(driver_type='compute',
                                   driver_name='gce_instances').get(
                                       size_type, {})
        cpu_price = 0
        ram_price = 0
        os_price = 0
        disk_price = 0
        if disk_prices:
            try:
                disk_price = disk_prices[disk_usage_type][
                    location].get('price', 0)
            except KeyError:
                disk_price = disk_prices[disk_usage_type][
                    default_location].get('price', 0)
        if gce_instance:
            try:
                cpu_price = gce_instance['cpu'][usage_type][
                    location].get('price', 0)
            except KeyError:
                cpu_price = gce_instance['cpu'][usage_type][
                    default_location].get('price', 0)
            if size_type not in {'f1', 'g1'}:
                try:
                    ram_price = gce_instance['ram'][usage_type][
                        location].get('price', 0)
                except KeyError:
                    ram_price = gce_instance['ram'][usage_type][
                        default_location].get('price', 0)
            ram_instance = None
            if (size_type == "n1" and machine_cpu > 0 and
               machine_ram / machine_cpu > 6.5):
                size_type += "_extended"
                ram_instance = get_size_price(driver_type='compute',
                                              driver_name='gce_instances',
                                              size_id=size_type)
            if (size_type == "n2" and machine_cpu > 0 and
               machine_ram / machine_cpu > 8):
                size_type += "_extended"
                ram_instance = get_size_price(driver_type='compute',
                                              driver_name='gce_instances',
                                              size_id=size_type)
            if (size_type == "n2d" and machine_cpu > 0 and
               machine_ram / machine_cpu > 8):
                size_type += "_extended"
                ram_instance = get_size_price(driver_type='compute',
                                              driver_name='gce_instances',
                                              size_id=size_type)
            if ram_instance:
                try:
                    ram_price = ram_instance['ram'][
                        usage_type][location].get('price', 0)
                except KeyError:
                    ram_price = ram_instance['ram'][
                        usage_type][default_location].get('price', 0)
        image_name = machine.image.name if machine.image \
            else machine.extra.get('image', '')

        os_price = _get_gce_image_price(image_name=image_name,
                                       size_name=machine.size.name,
                                       cores=machine_cpu)

        total_price = (machine_cpu * cpu_price + machine_ram *
                       ram_price + os_price + disk_price * disk_size)
        return total_price, 0

    def _list_machines__get_location(self, node_dict):
        return node_dict['extra'].get('zone', {}).get('id')

    def _list_machines__get_machine_cluster(self, machine, node):
        try:
            metadata = node['extra']['metadata']['items']
        except KeyError:
            return None

        for item in metadata:
            if item.get('key') == 'cluster-uid':
                cluster_id = item.get('value')
                break
        else:
            return None

        from mist.api.containers.models import Cluster
        cluster = None
        try:
            cluster = Cluster.objects.get(external_id=cluster_id,
                                          cloud=self.cloud,
                                          missing_since=None)
        except Cluster.DoesNotExist as exc:
            log.warn('Error getting cluster of %s: %r', machine, exc)

        return cluster

    def _list_sizes__get_name(self, size):
        return "%s (%s)" % (size.name, size.extra.get('description'))

    def _list_sizes__get_cpu(self, size):
        return size.extra.get('guestCpus')

    def _list_sizes__get_extra(self, size):
        extra = {}
        description = size.extra.get('description', '')
        if description:
            extra.update({'description': description})
        if size.price:
            extra.update({'price': size.price})
        extra['accelerators'] = size.extra.get('accelerators', [])
        extra['isSharedCpu'] = size.extra.get('isSharedCpu')
        return extra

    def _list_locations__fetch_locations(self):
        regions = self.connection.region_list
        zones = self.connection.zone_list
        # use only the region's slug instead of a GCE url
        for zone in zones:
            try:
                zone.extra['region'] = zone.extra['region'].split('/')[-1]
            except (KeyError, AttributeError):
                zone.extra['region'] = None
            zone.extra['acceleratorTypes'] = (
                self.connection.ex_list_accelerator_types_for_location(zone))

        return regions + zones

    def _list_locations__get_parent(self, location, libcloud_location):
        from libcloud.compute.drivers.gce import GCERegion
        from mist.api.clouds.models import CloudLocation

        if isinstance(libcloud_location, GCERegion):
            return None

        region_name = libcloud_location.extra['region']
        try:
            parent = CloudLocation.objects.get(name=region_name,
                                               missing_since=None,
                                               cloud=self.cloud)
            return parent
        except me.DoesNotExist:
            log.error('Parent does not exist for Location: %s',
                      location.id)
        except me.MultipleObjectsReturned:
            log.error('Multiple parents found for Location: %s',
                      location.id)

    def _list_locations__get_available_sizes(self, location):
        from libcloud.compute.drivers.gce import GCERegion
        if isinstance(location, GCERegion):
            return None
        libcloud_size_ids = [size.id for size
                             in self.connection.list_sizes(location=location)]

        from mist.api.clouds.models import CloudSize

        return CloudSize.objects(cloud=self.cloud,
                                 external_id__in=libcloud_size_ids)

    def _list_locations__get_type(self, location, libcloud_location):
        from libcloud.compute.drivers.gce import GCERegion
        if isinstance(libcloud_location, GCERegion):
            return 'region'
        return 'zone'

    def _list_images__get_min_disk_size(self, image):
        try:
            min_disk_size = int(image.extra.get('diskSizeGb'))
        except (TypeError, ValueError):
            return None
        return min_disk_size

    def _resize_machine(self, machine, node, node_size, kwargs):
        # instance must be in stopped mode
        if node.state != NodeState.STOPPED:
            raise BadRequestError('The instance has to be stopped '
                                  'in order to be resized')
        # get size name as returned by libcloud
        machine_type = node_size.name.split(' ')[0]
        try:
            self.connection.ex_set_machine_type(node,
                                                machine_type)
            self.connection.ex_start_node(node)
        except Exception as exc:
            raise BadRequestError('Failed to resize node: %s' % exc)

    def _generate_plan__parse_networks(self, auth_context, network_dict,
                                       location):

        subnet_search = network_dict.get('subnetwork')
        network_search = network_dict.get('network')
        networks_dict = {}

        from mist.api.methods import list_resources
        network = None
        if network_search:
            try:
                [network], _ = list_resources(auth_context, 'network',
                                              search=network_search,
                                              cloud=self.cloud.id,
                                              limit=1)
            except ValueError:
                raise NotFoundError('Network does not exist')

            networks_dict['network'] = network.name
        else:
            networks_dict['network'] = 'default'

        if subnet_search:
            subnets, _ = list_resources(auth_context, 'subnet',
                                        search=subnet_search,
                                        limit=1)
            if network:
                subnets.filter(network=network)
            else:
                subnets = [subnet for subnet in subnets
                           if subnet.network.cloud == self.cloud]
            if len(subnets) == 0:
                raise NotFoundError('Subnet not found %s' % subnet_search)

            networks_dict['subnet'] = subnets[0].name

        return networks_dict

    def _generate_plan__parse_key(self, auth_context, key_obj):
        key, _ = super()._generate_plan__parse_key(auth_context, key_obj)

        # extract ssh user from key param
        try:
            ssh_user = key_obj.get('user') or 'user'
        except AttributeError:
            # key_obj is a string
            ssh_user = 'user'

        if not isinstance(ssh_user, str):
            raise BadRequestError('Invalid type for user')

        extra_attrs = {
            'user': ssh_user,
        }
        return key, extra_attrs

    def _generate_plan__parse_size(self, auth_context, size_obj):
        sizes, _ = super()._generate_plan__parse_size(auth_context, size_obj)
        extra_attrs = None

        try:
            accelerators = size_obj.get('accelerators')
        except AttributeError:
            # size_obj is a string
            accelerators = None

        if accelerators:
            try:
                accelerator_type = accelerators['accelerator_type']
                accelerator_count = accelerators['accelerator_count']
            except KeyError:
                raise BadRequestError(
                    'Both accelerator_type and accelerator_count'
                    ' are required')
            except TypeError:
                raise BadRequestError('Invalid type for accelerators')

            if not isinstance(accelerator_count, int):
                raise BadRequestError('Invalid type for accelerator_count')

            if accelerator_count <= 0:
                raise BadRequestError('Invalid value for accelerator_type')

            # accelerators are currently supported only on N1 sizes
            # https://cloud.google.com/compute/docs/gpus#introduction
            sizes = [size for size in sizes
                     if size.name.startswith('n1') and
                     size.extra.get('isSharedCpu') is False]

            extra_attrs = {
                'accelerator_type': accelerator_type,
                'accelerator_count': accelerator_count,
            }

        return sizes, extra_attrs

    def _generate_plan__parse_volume_attrs(self, volume_dict, vol_obj):
        ret_dict = {
            'id': vol_obj.id,
            'name': vol_obj.name
        }

        boot = volume_dict.get('boot')
        if boot is True:
            ret_dict['boot'] = boot

        return ret_dict

    def _generate_plan__parse_custom_volume(self, volume_dict):
        try:
            size = int(volume_dict['size'])
        except KeyError:
            raise BadRequestError('Volume size parameter is required')
        except (TypeError, ValueError):
            raise BadRequestError('Invalid volume size type')

        if size < 1:
            raise BadRequestError('Volume size should be at least 1 GB')

        boot = volume_dict.get('boot')
        name = None
        try:
            name = str(volume_dict['name'])
        except KeyError:
            # name is not required in boot volume
            if boot is not True:
                raise BadRequestError('Volume name parameter is required')

        volume_type = volume_dict.get('type', 'pd-standard')
        if volume_type not in ('pd-standard', 'pd-ssd'):
            raise BadRequestError(
                'Invalid value for volume type, valid values are: '
                'pd-standard, pd-ssd'
            )

        ret_dict = {
            'size': size,
            'type': volume_type
        }
        # boot volumes use machine's name
        if name and boot is not True:
            ret_dict['name'] = name

        if boot is True:
            ret_dict['boot'] = boot

        return ret_dict

    def _get_allowed_image_size_location_combinations(self,
                                                      images,
                                                      locations,
                                                      sizes,
                                                      image_extra_attrs,
                                                      size_extra_attrs):
        # pre-filter locations based on selected accelerator type availability
        size_extra_attrs = size_extra_attrs or {}
        accelerator_type = size_extra_attrs.get('accelerator_type')
        accelerator_count = size_extra_attrs.get('accelerator_count')
        if accelerator_type and accelerator_count:
            filtered_locations = []
            for location in locations:
                try:
                    max_accelerators = \
                        location.extra['acceleratorTypes'][accelerator_type]
                except (KeyError, TypeError):
                    continue

                # check if location supports these many accelerators
                if max_accelerators >= accelerator_count:
                    filtered_locations.append(location)

            locations = filtered_locations

        return super()._get_allowed_image_size_location_combinations(
            images, locations, sizes,
            image_extra_attrs,
            size_extra_attrs)

    def _generate_plan__parse_extra(self, extra, plan) -> None:
        try:
            service_account = extra['service_account']
        except KeyError:
            return

        if not isinstance(service_account, dict):
            raise BadRequestError(
                'Invalid type for service account parameter')

        # use the default service account & scopes if one of the values
        # is not provided
        email = service_account.get('email') or 'default'
        scopes = service_account.get('scopes') or ['devstorage.read_only']

        if not isinstance(email, str) or not isinstance(scopes, list):
            raise BadRequestError(
                'Invalid type for service_account email/scopes parameter')

        plan['service_account'] = {
            'email': email,
            'scopes': scopes
        }

    def _generate_plan__post_parse_plan(self, plan):
        from mist.api.images.models import CloudImage
        image = CloudImage.objects.get(id=plan['image']['id'])

        try:
            image_min_size = int(image.min_disk_size)
        except TypeError:
            image_min_size = 10

        volumes = plan.get('volumes', [])
        # make sure boot drive is first if it exists
        volumes.sort(key=lambda k: k.get('boot') or False,
                     reverse=True)

        if len(volumes) > 1:
            # make sure only one boot volume is set
            if volumes[1].get('boot') is True:
                raise BadRequestError('Up to 1 volume must be set as boot')

        if len(volumes) == 0 or volumes[0].get('boot') is not True:
            boot_volume = {
                'size': image_min_size,
                'type': 'pd-standard',
                'boot': True,
            }
            volumes.insert(0, boot_volume)

        boot_volume = volumes[0]
        if boot_volume.get('size') and boot_volume['size'] < image_min_size:
            raise BadRequestError(f'Boot volume must be '
                                  f'at least {image_min_size} GBs '
                                  f'for image: {image.name}')
        elif boot_volume.get('id'):
            from mist.api.volumes.models import Volume
            vol = Volume.objects.get(id=boot_volume['id'])
            if vol.size < image_min_size:
                raise BadRequestError(f'Boot volume must be '
                                      f'at least {image_min_size} GBs '
                                      f'for image: {image.name}')

        plan['volumes'] = volumes

    def _create_machine__compute_kwargs(self, plan):
        kwargs = super()._create_machine__compute_kwargs(plan)
        key = kwargs.pop('auth')
        username = plan.get('key', {}).get('user') or 'user'
        metadata = {
            'sshKeys': '%s:%s' % (username, key.public)
        }
        if plan.get('cloudinit'):
            metadata['user-data'] = plan['cloudinit']
        kwargs['ex_metadata'] = metadata

        boot_volume = plan['volumes'].pop(0)
        if boot_volume.get('id'):
            from mist.api.volumes.models import Volume
            from libcloud.compute.base import StorageVolume
            vol = Volume.objects.get(id=boot_volume['id'])
            libcloud_vol = StorageVolume(id=vol.external_id,
                                         name=vol.name,
                                         size=vol.size,
                                         driver=self.connection,
                                         extra=vol.extra)
            kwargs['ex_boot_disk'] = libcloud_vol
        else:
            kwargs['disk_size'] = boot_volume.get('size')
            kwargs['ex_disk_type'] = boot_volume.get('type') or 'pd-standard'

        kwargs['ex_network'] = plan['networks'].get('network')
        kwargs['ex_subnetwork'] = plan['networks'].get('subnet')

        if plan['size'].get('accelerator_type'):
            kwargs['ex_accelerator_type'] = plan['size']['accelerator_type']
            kwargs['ex_accelerator_count'] = plan['size']['accelerator_count']
            # required when attaching accelerators to an instance
            kwargs['ex_on_host_maintenance'] = 'TERMINATE'

        if plan.get('service_account'):
            kwargs['ex_service_accounts'] = [plan['service_account']]
        return kwargs

    def _create_machine__post_machine_creation_steps(self, node, kwargs, plan):
        from mist.api.volumes.models import Volume
        from libcloud.compute.base import StorageVolume
        location = kwargs['location']
        volumes = plan['volumes']
        for volume in volumes:
            if volume.get('id'):
                vol = Volume.objects.get(id=volume['id'])
                libcloud_vol = StorageVolume(id=vol.external_id,
                                             name=vol.name,
                                             size=vol.size,
                                             driver=self.connection,
                                             extra=vol.extra)
                try:
                    self.connection.attach_volume(node, libcloud_vol)
                except Exception as exc:
                    log.exception('Attaching volume failed')
            else:
                try:
                    size = volume['size']
                    name = volume['name']
                    volume_type = volume.get('type') or 'pd-standard'
                except KeyError:
                    log.exception('Missing required volume parameter')
                    continue
                try:
                    libcloud_vol = self.connection.create_volume(
                        size,
                        name,
                        location=location,
                        ex_disk_type=volume_type)
                except Exception as exc:
                    log.exception('Failed to create volume')
                    continue
                try:
                    self.connection.attach_volume(node, libcloud_vol)
                except Exception as exc:
                    log.exception('Attaching volume failed')

    def _create_machine__get_size_object(self, size):
        # when providing a Libcloud NodeSize object
        # gce driver tries to get `selfLink` key of size.extra
        # dictionary. Mist sizes do not save selfLink in extra
        # so a KeyError is thrown. Providing only size id
        # seems to resolve this issue
        size_obj = super()._create_machine__get_size_object(size)
        return size_obj.id

    def _list_images__get_os_distro(self, image):
        try:
            os_distro = image.extra.get('family').split('-')[0]
        except AttributeError:
            return super()._list_images__get_os_distro(image)

        # windows sql server
        if os_distro == 'sql':
            os_distro = 'windows'
        return os_distro

