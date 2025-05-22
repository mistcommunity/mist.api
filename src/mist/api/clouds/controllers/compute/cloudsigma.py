import base64
import mongoengine as me
from time import sleep

from libcloud.compute.base import NodeLocation
from libcloud.compute.providers import get_driver
from libcloud.compute.types import Provider, NodeState
from mist.api.clouds.controllers.compute.base import BaseComputeController
from mist.api.clouds.controllers.compute.base import (
    log, copy, config, BadRequestError, NotFoundError, InternalServerError,
    node_to_dict, NodeState, BaseHTTPError
)

from mist.api.exceptions import BadRequestError


class CloudSigmaComputeController(BaseComputeController):
    def _connect(self, **kwargs):
        return get_driver(Provider.CLOUDSIGMA)(
            key=self.cloud.username,
            secret=self.cloud.password.value,
            region=self.cloud.region)

    def _list_machines__machine_creation_date(self, machine, node_dict):
        if node_dict['extra'].get('runtime'):
            return node_dict['extra']['runtime'].get('active_since')

    def _list_machines__cost_machine(self, machine, node_dict):
        from mist.api.volumes.models import Volume
        try:
            pricing = machine.location.extra['pricing']
        except KeyError:
            return 0, 0

        # cloudsigma calculates pricing using GHz/hour
        # where 2 GHz = 1 core
        cpus = node_dict['extra']['cpus'] * 2
        # machine memory in GBs as pricing uses GB/hour
        memory = node_dict['extra']['memory'] / 1024

        volume_uuids = [item['drive']['uuid'] for item
                        in node_dict['extra']['drives']]
        volumes = Volume.objects(cloud=self.cloud,
                                 missing_since=None,
                                 external_id__in=volume_uuids)
        ssd_size = 0
        hdd_size = 0
        for volume in volumes:
            if volume.extra['storage_type'] == 'dssd':
                ssd_size += volume.size
            else:
                hdd_size += volume.size
        # cpu and memory pricing per hour
        cpu_price = cpus * float(pricing['intel_cpu']['price'])
        memory_price = memory * float(pricing['intel_mem']['price'])
        # disk pricing per month
        ssd_price = ssd_size * float(pricing['dssd']['price'])
        hdd_price = hdd_size * float(pricing['zadara']['price'])
        cost_per_month = ((24 * 30 * (cpu_price + memory_price)) +
                          ssd_price + hdd_price)
        return 0, cost_per_month

    def _list_machines__get_location(self, node):
        return self.connection.region

    def _list_machines__get_size(self, node):
        return node['size'].get('id')

    def _list_machines__get_custom_size(self, node_dict):
        from mist.api.clouds.models import CloudSize
        updated = False
        try:
            _size = CloudSize.objects.get(
                cloud=self.cloud,
                external_id=str(node_dict['size'].get('id')))
        except me.DoesNotExist:
            _size = CloudSize(cloud=self.cloud,
                              external_id=str(node_dict['size'].get('id')))
            updated = True

        if _size.ram != node_dict['size'].get('ram'):
            _size.ram = node_dict['size'].get('ram')
            updated = True
        if _size.cpus != node_dict['size'].get('cpu'):
            _size.cpus = node_dict['size'].get('cpu')
            updated = True
        if _size.disk != node_dict['size'].get('disk'):
            _size.disk = node_dict['size'].get('disk')
            updated = True
        if _size.name != node_dict['size'].get('name'):
            _size.name = node_dict['size'].get('name')
            updated = True

        if updated:
            _size.save()
        return _size

    def _destroy_machine(self, machine, node):
        if node.state == NodeState.RUNNING.value:
            self.connection.ex_stop_node(node)
        ret_val = False
        for _ in range(10):
            try:
                self.connection.destroy_node(node)
            except Exception:
                sleep(1)
                continue
            else:
                ret_val = True
                break
        return ret_val

    def _list_locations__fetch_locations(self):
        from libcloud.common.cloudsigma import API_ENDPOINTS_2_0
        attributes = API_ENDPOINTS_2_0[self.connection.region]
        pricing = self.connection.ex_get_pricing()
        # get only the default burst level pricing for resources in USD
        pricing = {item.pop('resource'): item for item in pricing['objects']
                   if item['level'] == 0 and item['currency'] == 'USD'}

        location = NodeLocation(id=self.connection.region,
                                name=attributes['name'],
                                country=attributes['country'],
                                driver=self.connection,
                                extra={
                                    'pricing': pricing,
                                })
        return [location]

    def _list_sizes__get_cpu(self, size):
        cpus = int(round(size.cpu))
        if cpus == 0:
            cpus = 1
        return cpus

    def _generate_plan__parse_custom_volume(self, volume_dict):
        try:
            size = int(volume_dict['size'])
        except KeyError:
            raise BadRequestError('Volume size parameter is required')
        except (TypeError, ValueError):
            raise BadRequestError('Invalid volume size type')
        if size < 1:
            raise BadRequestError('Volume size should be at least 1 GBs')

        try:
            name = volume_dict['name']
        except KeyError:
            raise BadRequestError('Volume name parameter is required')

        return {
            'name': name,
            'size': size,
        }

    def _generate_plan__parse_disks(self,
                                    auth_context,
                                    disks_dict):
        disk_size = disks_dict.get('disk_size')
        if disk_size:
            try:
                disk_size = int(disk_size)
            except (TypeError, ValueError):
                raise BadRequestError('Invalid disk size type')

            return {
                'size': disk_size
            }

    def _generate_plan__post_parse_plan(self, plan) -> None:
        # In CloudSigma we have both custom sizes and "standard" sizes
        # from their "Simple Server Creation" wizard.
        # If a custom size is provided then it's necessary to provide
        # the disk size.

        if plan['size'].get('cpus'):
            try:
                plan['size']['disk'] = plan['disks']['size']
            except KeyError:
                raise BadRequestError(
                    'Disk size is required when providing a custom size'
                )

    def _create_machine__get_size_object(self, size):
        from libcloud.compute.drivers.cloudsigma import CloudSigmaNodeSize
        if isinstance(size, str):
            from mist.api.clouds.models import CloudSize
            size = CloudSize.objects.get(id=size)
            cpus = size.cpus
            ram = size.ram
            disk = size.disk
        else:
            cpus = size['cpus']
            ram = size['ram']
            disk = size['disk']

        return CloudSigmaNodeSize(
            id=None,
            name=None,
            cpu=cpus,
            ram=ram,
            disk=disk,
            bandwidth=None,
            price=None,
            driver=self.connection
        )

    def _create_machine__compute_kwargs(self, plan):
        kwargs = super()._create_machine__compute_kwargs(plan)

        mist_key = kwargs.pop('auth')
        key_pairs = self.connection.list_key_pairs()
        key = next((key_pair for key_pair in key_pairs
                    if key_pair.public_key == mist_key.public),
                   None)
        if key is None:
            key = self.connection.import_key_pair_from_string(
                mist_key.name,
                mist_key.public)
        kwargs['public_keys'] = [key.extra['uuid']]

        if plan.get('cloudinit'):
            kwargs['ex_metadata'] = {
                'base64_fields': 'cloudinit-user-data',
                'cloudinit-user-data': base64.b64encode(
                    plan['cloudinit'].encode('utf-8')).decode('utf-8')
            }

        # Volumes can be attached only when the machine is stopped
        if plan.get('volumes'):
            kwargs['ex_boot'] = False

        return kwargs

    def _create_machine__create_node(self, kwargs):
        node = super()._create_machine__create_node(kwargs)
        node.extra['username'] = 'cloudsigma'
        return node

    def _create_machine__post_machine_creation_steps(self, node, kwargs, plan):
        from mist.api.volumes.models import Volume
        from libcloud.compute.base import StorageVolume

        volumes = plan.get('volumes', [])
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
                except Exception:
                    log.exception(
                        'Failed to attach existing volume to machine')
            else:
                name = volume['name']
                size = volume['size']
                try:
                    libcloud_vol = self.connection.create_volume(name=name,
                                                                 size=size)
                except Exception:
                    log.exception('Failed to create volume')
                else:
                    try:
                        self.connection.attach_volume(node, libcloud_vol)
                    except Exception:
                        log.exception('Failed to attach volume to machine')

        if kwargs.get('ex_boot') is False:
            self.connection.start_node(node)
