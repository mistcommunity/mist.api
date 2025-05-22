import iso8601
import pytz
import time

from libcloud.compute.base import Node
from libcloud.compute.providers import get_driver
from libcloud.compute.types import Provider

from mist.api.clouds.controllers.compute.base import BaseComputeController
from mist.api.clouds.controllers.compute.base import (
    log, copy, config, BadRequestError, NotFoundError, InternalServerError,
    node_to_dict, NodeState, BaseHTTPError
)

from mist.api.exceptions import BadRequestError
from mist.api.exceptions import NotFoundError
from mist.api.exceptions import MachineCreationError


class VultrComputeController(BaseComputeController):

    def _connect(self, **kwargs):
        return get_driver(Provider.VULTR)(self.cloud.apikey.value)

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

    def _list_machines__machine_creation_date(self, machine, node_dict):
        try:
            created_at = node_dict['created_at']
        except KeyError:
            return None

        try:
            created_at = iso8601.parse_date(created_at)
        except iso8601.ParseError as exc:
            log.error(repr(exc))
            return None

        created_at = pytz.UTC.normalize(created_at)
        return created_at

    def _list_machines__cost_machine(self, machine, node_dict):
        from mist.api.clouds.models import CloudSize
        external_id = node_dict.get('size')
        try:
            size_ = CloudSize.objects.get(external_id=external_id,
                                          cloud=self.cloud)
        except CloudSize.DoesNotExist:
            log.error("Machine's size with external_id: %s not found",
                      external_id)
            return 0, 0

        monthly_cost = size_.extra.get('price') or 0

        features = node_dict['extra'].get('features', [])
        if 'auto_backups' in features:
            try:
                monthly_cost += config.VULTR_BACKUP_PRICE_PER_SIZE[
                    size_.external_id]
            except KeyError:
                pass

        if 'ddos_protection' in features:
            # DDOS protection is free on Dedicated Cloud sizes
            # and not supported on Bare Metal sizes
            if size_.extra.get('type') in ('vc2', 'vhf'):
                monthly_cost += config.VULTR_DDOS_PROTECTION_PRICE

        return 0, monthly_cost

    def _list_machines__get_location(self, node_dict):
        return node_dict['extra'].get('location')

    def _list_machines__machine_actions(self, machine, node_dict):
        super()._list_machines__machine_actions(machine, node_dict)
        size = node_dict.get('size', '')
        # Bare metal nodes don't support resize & snapshot
        if size.startswith('vbm'):
            machine.actions.resize = False
        else:
            machine.actions.resize = True

    def _list_sizes__get_name(self, size):
        # Vultr doesn't have names on sizes.
        # We name them after their 9 different size types & their specs.
        # - High Frequency
        # - Cloud Compute
        # - Bare Metal
        # - Dedicated Cloud
        # - High Performance
        # - General Purpose Optimized Cloud
        # - CPU Optimized Cloud
        # - Memory Optimized Cloud
        # - Storage Optimized Cloud
        if size.name.startswith('vc2'):
            type_ = 'Cloud Compute'
        elif size.name.startswith('vdc'):
            type_ = 'Dedicated Cloud'
        elif size.name.startswith('vhf'):
            type_ = 'High Frequency'
        elif size.name.startswith('vbm'):
            type_ = 'Bare Metal'
        elif size.name.startswith('vhp'):
            type_ = 'High Performance'
        elif size.name.startswith('voc-g'):
            type_ = 'General Purpose Optimized Cloud'
        elif size.name.startswith('voc-c'):
            type_ = 'CPU Optimized Cloud'
        elif size.name.startswith('voc-m'):
            type_ = 'Memory Optimized Cloud'
        elif size.name.startswith('voc-s'):
            type_ = 'Storage Optimized Cloud'
        else:
            log.warning('Unknown Vultr size id: %s', size.id)
            type_ = 'Unknown'
        cpus = self._list_sizes__get_cpu(size)

        return (f'{type_}: {cpus} CPUs {size.ram} MBs RAM'
                f' {size.disk} GBs disk {size.price}$')

    def _list_sizes__get_cpu(self, size):
        try:
            return size.extra['vcpu_count']
        except KeyError:
            # bare metal size
            return size.extra['cpu_count']

    def _list_sizes__get_available_locations(self, mist_size):
        avail_locations = [str(loc)
                           for loc in mist_size.extra.get('locations', [])]
        from mist.api.clouds.models import CloudLocation
        CloudLocation.objects(
            cloud=self.cloud,
            external_id__in=avail_locations
        ).update(add_to_set__available_sizes=mist_size)

    def _list_images__fetch_images(self, search=None):
        # Vultr has some legacy "dummy" images that were provided when
        # a node was booted from snapshot, iso, application or backup,
        # that are no longer necessary on their API v2.
        images = self.connection.list_images()
        return [image for image in images
                if image.name not in {'Custom',
                                      'Snapshot',
                                      'Backup',
                                      'Application'}]

    def _list_images__get_os_distro(self, image):
        try:
            os_distro = image.extra.get('family').lower()
        except AttributeError:
            return super()._list_images__get_os_distro(image)
        return os_distro

    def _generate_plan__parse_networks(self, auth_context, networks_dict,
                                       location):
        from mist.api.methods import list_resources
        ret_dict = {
            'ipv6': networks_dict.get('ipv6') is True,
            'hostname': networks_dict.get('hostname')
        }

        networks = networks_dict.get('networks', [])
        if not isinstance(networks, list):
            raise BadRequestError('Invalid "networks" type, expected an array')

        ret_networks = []
        for net in networks:
            networks, _ = list_resources(auth_context,
                                         'network',
                                         search=net,
                                         cloud=self.cloud.id,
                                         )
            networks = networks.filter(location=location)
            try:
                network = networks[0]
            except IndexError:
                raise NotFoundError(f'Network {net} does not exist in'
                                    f' location: {location.name}')
            ret_networks.append({
                'id': network.id,
                'name': network.name,
                'external_id': network.network_id,
            })
        if ret_networks:
            ret_dict['networks'] = ret_networks

        return ret_dict

    def _generate_plan__parse_volume_attrs(self, volume_dict, vol_obj):
        return {
            'id': vol_obj.id,
            'name': vol_obj.name,
            'external_id': vol_obj.external_id
        }

    def _generate_plan__parse_custom_volume(self, volume_dict):
        try:
            size = int(volume_dict['size'])
            name = volume_dict['name']
        except KeyError:
            raise BadRequestError('name and size are required')
        except (TypeError, ValueError):
            raise BadRequestError('Invalid size type')
        if size < 10:
            raise BadRequestError('Size should be at least 10 GBs')

        return {
            'name': name,
            'size': size,
        }

    def _generate_plan__parse_extra(self, extra, plan):
        plan['backups'] = extra.get('backups') is True
        plan['ddos_protection'] = extra.get('ddos_protection') is True

    def _generate_plan__post_parse_plan(self, plan):
        from mist.api.clouds.models import CloudSize, CloudLocation

        size = CloudSize.objects.get(id=plan['size']['id'])
        bare_metal = size.extra['is_bare_metal']
        location = CloudLocation.objects.get(id=plan['location']['id'])

        if plan.get('volumes'):
            if 'block_storage' not in location.extra.get('option', []):
                raise BadRequestError(
                    f'Volumes are not supported in "{location.name}"')
            if bare_metal:
                raise BadRequestError(
                    'Bare Metal metal sizes do not support volume attachment')

        if plan['networks'].get('networks') and bare_metal:
            raise BadRequestError(
                'Bare Metal sizes do not support network attachment')

        if plan['ddos_protection']:
            if 'ddos_protection' not in location.extra.get('option'):
                raise BadRequestError(
                    f'DDoS protection is not supported in "{location.name}"')
            if bare_metal:
                raise BadRequestError(
                    'Bare Metal sizes do not support DDoS protection')

        if plan['backups'] and (bare_metal or
                                size.name.startswith('Dedicated Cloud')):
            raise BadRequestError(
                'Backups are not supported on the given size type')

        hostname = plan['networks']['hostname']
        if hostname is None:
            plan['networks']['hostname'] = plan['machine_name']

    def _create_machine__compute_kwargs(self, plan):
        kwargs = super()._create_machine__compute_kwargs(plan)
        mist_key = kwargs.pop('auth', None)
        if mist_key:
            vultr_keys = self.connection.list_key_pairs()
            key = next((vultr_key for vultr_key in vultr_keys
                        if vultr_key.public_key.replace('\n', '') == mist_key.public),  # noqa
                       None)
            if key is None:
                try:
                    key = self.connection.import_key_pair_from_string(
                        mist_key.name,
                        mist_key.public)
                except Exception as exc:
                    raise MachineCreationError(
                        f'Failed to import key: {repr(exc)}') from None

            kwargs['ex_ssh_key_ids'] = [key.extra['id']]

        if plan.get('cloudinit'):
            kwargs['ex_userdata'] = plan['cloudinit']

        kwargs['ex_hostname'] = plan['networks']['hostname']
        kwargs['ex_enable_ipv6'] = plan['networks']['ipv6']
        if plan['networks'].get('networks'):
            kwargs['ex_private_network_ids'] = [network['external_id']
                                                for network in plan['networks']['networks']]  # noqa

        kwargs['ex_ddos_protection'] = plan['ddos_protection']
        kwargs['ex_backups'] = plan['backups']

        return kwargs

    def _create_machine__post_machine_creation_steps(self, node, kwargs, plan):
        from mist.api.clouds.models import CloudLocation
        from mist.api.volumes.models import Volume
        from libcloud.compute.base import StorageVolume

        volumes = plan.get('volumes', [])
        location = CloudLocation.objects.get(id=plan['location']['id'])

        # wait till machine is in active state to attach volumes
        if volumes:
            for _ in range(10):
                time.sleep(5)
                try:
                    node = self.connection.ex_get_node(node.id)
                except Exception:
                    continue
                if node.state == 'running':
                    break

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
                    log.exception('Failed to attach volume')
            else:
                try:
                    libcloud_vol = self.connection.create_volume(
                        size=volume['size'],
                        name=volume['name'],
                        location=location.external_id
                    )
                except Exception:
                    log.exception('Failed to create volume')
                    continue
                try:
                    self.connection.attach_volume(node, libcloud_vol)
                except Exception:
                    log.exception('Failed to attach volume')
