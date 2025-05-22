from libcloud.compute.providers import get_driver
from libcloud.compute.types import Provider
from mist.api.clouds.controllers.compute.base import BaseComputeController
from mist.api.clouds.controllers.compute.base import (
    log, copy, config, BadRequestError, NotFoundError, InternalServerError,
    node_to_dict, NodeState, BaseHTTPError
)

from mist.api.exceptions import BadRequestError


class DigitalOceanComputeController(BaseComputeController):

    def _connect(self, **kwargs):
        return get_driver(Provider.DIGITAL_OCEAN)(self.cloud.token.value)

    def _list_machines__postparse_machine(self, machine, node_dict):
        updated = False
        cpus = machine.extra.get('size', {}).get('vcpus', 0)
        if machine.extra.get('cpus') != cpus:
            machine.extra['cpus'] = cpus
            updated = True
        return updated

    def _list_machines__machine_creation_date(self, machine, node_dict):
        return node_dict['extra'].get('created_at')  # iso8601 string

    def _list_machines__machine_actions(self, machine, node_dict):
        super(DigitalOceanComputeController,
              self)._list_machines__machine_actions(machine, node_dict)
        machine.actions.rename = True
        machine.actions.resize = True
        machine.actions.power_cycle = True

    def _resize_machine(self, machine, node, node_size, kwargs):
        try:
            self.connection.ex_resize_node(node, node_size)
        except Exception as exc:
            raise BadRequestError('Failed to resize node: %s' % exc)

    def _list_machines__cost_machine(self, machine, node_dict):
        size = node_dict['extra'].get('size', {})
        return size.get('price_hourly', 0), size.get('price_monthly', 0)

    def _stop_machine(self, machine, node):
        self.connection.ex_shutdown_node(node)

    def _start_machine(self, machine, node):
        self.connection.ex_power_on_node(node)

    def _power_cycle_machine(self, node):
        try:
            self.connection.ex_hard_reboot(node)
        except Exception as exc:
            raise BadRequestError('Failed to execute power_cycle on \
                node: %s' % exc)

    def _list_machines__get_location(self, node):
        return node['extra'].get('region')

    def _list_machines__get_size(self, node):
        return node['extra'].get('size_slug')

    def _list_sizes__get_name(self, size):
        cpus = str(size.extra.get('vcpus', ''))
        ram = str(size.ram / 1024)
        disk = str(size.disk)
        bandwidth = str(size.bandwidth)
        price_monthly = str(size.extra.get('price_monthly', ''))
        if cpus:
            name = cpus + ' CPU, ' if cpus == '1' else cpus + ' CPUs, '
        if ram:
            name += ram + ' GB, '
        if disk:
            name += disk + ' GB SSD Disk, '
        if price_monthly:
            name += '$' + price_monthly + '/month'

        return name

    def _list_sizes__get_cpu(self, size):
        return size.extra.get('vcpus')

    def _generate_plan__parse_custom_volume(self, volume_dict):
        size = volume_dict.get('size')
        name = volume_dict.get('name')
        fs_type = volume_dict.get('filesystem_type', '')
        if not size and name:
            raise BadRequestError('Size and name are mandatory'
                                  'for volume creation')
        volume = {
            'size': size,
            'name': name,
            'filesystem_type': fs_type
        }
        return volume

    def _create_machine__get_key_object(self, key):
        key_obj = super()._create_machine__get_key_object(key)
        server_key = ''
        libcloud_keys = self.connection.list_key_pairs()
        for libcloud_key in libcloud_keys:
            if libcloud_key.public_key == key_obj.public:
                server_key = libcloud_key
                break
        if not server_key:
            server_key = self.connection.create_key_pair(
                key_obj.name, key_obj.public
            )
        return server_key.extra.get('id')

    def _create_machine__get_size_object(self, size):
        size_obj = super()._create_machine__get_size_object(size)
        size_obj.name = size_obj.id
        return size_obj

    def _create_machine__compute_kwargs(self, plan):
        kwargs = super()._create_machine__compute_kwargs(plan)
        # apiV1 function _create_machine_digital_ocean checks for
        # `private_networking` in location.extra but no location
        # seems to return it.
        kwargs['ex_create_attr'] = {
            'private_networking': True,
            'ssh_keys': [kwargs.pop('auth')]
        }

        volumes = []
        from mist.api.volumes.models import Volume
        for volume in plan.get('volumes', []):
            if volume.get('id'):
                try:
                    mist_vol = Volume.objects.get(id=volume['id'])
                    volumes.append(mist_vol.external_id)
                except me.DoesNotExist:
                    # this shouldn't happen as during plan creation
                    # volume id existed in mongo
                    continue
            else:
                fs_type = volume.get('filesystem_type', '')
                name = volume.get('name')
                size = int(volume.get('size'))
                location = kwargs['location']
                # TODO create_volume might raise ValueError
                new_volume = self.connection.create_volume(
                    size, name, location=location, filesystem_type=fs_type)
                volumes.append(new_volume.id)
        kwargs['volumes'] = volumes

        return kwargs

    def _list_images__get_os_distro(self, image):
        try:
            os_distro = image.extra.get('distribution').lower()
        except AttributeError:
            return super()._list_images__get_os_distro(image)
        return os_distro

    def _list_sizes__get_available_locations(self, mist_size):
        from mist.api.clouds.models import CloudLocation
        CloudLocation.objects(
            cloud=self.cloud,
            external_id__in=mist_size.extra.get('regions', [])
        ).update(add_to_set__available_sizes=mist_size)

    def _list_images__fetch_images(self, search=None):
        snapshots = self.connection.ex_list_snapshots(resource_type='droplet')
        images = self.connection.list_images()

        return images + snapshots

    def _list_images__get_available_locations(self, mist_image):
        from mist.api.clouds.models import CloudLocation
        CloudLocation.objects(
            cloud=self.cloud,
            external_id__in=mist_image.extra.get('regions', [])
        ).update(add_to_set__available_images=mist_image)

    def _list_images__get_min_disk_size(self, image):
        try:
            min_disk_size = int(image.extra.get('min_disk_size'))
        except (TypeError, ValueError):
            return None
        return min_disk_size

    def _list_images__get_origin(self, image):
        from libcloud.compute.drivers.digitalocean import DigitalOceanSnapshot
        if isinstance(image, DigitalOceanSnapshot):
            return 'snapshot'

        if image.extra.get('public'):
            return 'system'
        return 'custom'
