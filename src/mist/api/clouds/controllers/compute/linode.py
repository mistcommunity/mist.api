from libcloud.compute.providers import get_driver
from libcloud.compute.types import Provider
from mist.api.clouds.controllers.compute.base import BaseComputeController
from mist.api.clouds.controllers.compute.base import (
    log, copy, config, BadRequestError, NotFoundError, InternalServerError,
    node_to_dict, NodeState, BaseHTTPError
)

from mist.api.exceptions import BadRequestError


class LinodeComputeController(BaseComputeController):

    def _connect(self, **kwargs):
        if self.cloud.apiversion is not None:
            return get_driver(Provider.LINODE)(
                self.cloud.apikey.value,
                api_version=self.cloud.apiversion)
        else:
            return get_driver(Provider.LINODE)(self.cloud.apikey.value)

    def _list_machines__machine_creation_date(self, machine, node_dict):
        if self.cloud.apiversion is not None:
            return node_dict['extra'].get('CREATE_DT')  # iso8601 string
        else:
            return node_dict.get('created_at')

    def _list_machines__machine_actions(self, machine, node_dict):
        super(LinodeComputeController, self)._list_machines__machine_actions(
            machine, node_dict)
        machine.actions.rename = True
        machine.actions.resize = True
        # machine.actions.stop = False
        # After resize, node gets to pending mode, needs to be started.
        if node_dict['state'] is NodeState.PENDING.value:
            machine.actions.start = True

    def _list_machines__cost_machine(self, machine, node_dict):
        if self.cloud.apiversion is not None:
            size = node_dict['extra'].get('PLANID')
            try:
                price = get_size_price(driver_type='compute',
                                       driver_name='linode',
                                       size_id=size)
            except KeyError:
                price = 0
            return 0, price or 0
        else:
            size = node_dict.get('size')
            from mist.api.clouds.models import CloudSize
            try:
                _size = CloudSize.objects.get(external_id=size,
                                              cloud=self.cloud)
            except CloudSize.DoesNotExist:
                log.warn("Linode size %s not found", size)
                return 0, 0

            price_per_month = _size.extra.get('monthly_price', 0.0)
            price_per_hour = _size.extra.get('price', 0.0)

            return price_per_hour, price_per_month

    def _list_machines__get_size(self, node):
        if self.cloud.apiversion is not None:
            return node['extra'].get('PLANID')
        else:
            return node.get('size')

    def _list_machines__get_location(self, node):
        if self.cloud.apiversion is not None:
            return str(node['extra'].get('DATACENTERID'))
        else:
            return node['extra'].get('location')

    def _list_images__fetch_images(self, search=None):
        """ Convert datetime object to isoformat
        """
        images = self.connection.list_images()
        from datetime import datetime
        for image in images:
            if 'created' in image.extra and \
                    isinstance(image.extra['created'], datetime):
                image.extra['created'] = image.extra['created'].isoformat()
        return images

    def _list_images__get_os_distro(self, image):
        try:
            os_distro = image.extra.get('vendor').lower()
        except AttributeError:
            return super()._list_images__get_os_distro(image)
        return os_distro

    def _list_images__get_min_disk_size(self, image):
        try:
            min_disk_size = int(image.extra.get('size')) / 1000
        except (TypeError, ValueError):
            return None
        return min_disk_size

    def _list_images__get_origin(self, image):
        if image.extra.get('public'):
            return 'system'
        return 'custom'

    def _list_sizes__get_cpu(self, size):
        if self.cloud.apiversion is not None:
            return super()._list_sizes__get_cpu(size)
        return int(size.extra.get('vcpus') or 1)

    def _generate_plan__parse_volume_attrs(self, volume_dict, vol_obj):
        persist_across_boots = True if volume_dict.get(
            'persist_across_boots', True) is True else False
        ret = {
            'id': vol_obj.id,
            'name': vol_obj.name,
            'persist_across_boots': persist_across_boots
        }
        return ret

    def _generate_plan__parse_custom_volume(self, volume_dict):
        try:
            size = int(volume_dict['size'])
        except KeyError:
            raise BadRequestError('Volume size parameter is required')
        except (TypeError, ValueError):
            raise BadRequestError('Invalid volume size type')

        if size < 10:
            raise BadRequestError('Volume size should be at least 10 GBs')

        try:
            name = str(volume_dict['name'])
        except KeyError:
            raise BadRequestError('Volume name parameter is required')

        return {'name': name, 'size': size}

    def _generate_plan__parse_networks(self, auth_context, networks_dict,
                                       location):
        private_ip = True if networks_dict.get(
            'private_ip', True) is True else False
        return {'private_ip': private_ip}

    def _generate_plan__parse_extra(self, extra, plan):
        try:
            root_pass = extra['root_pass']
        except KeyError:
            root_pass = generate_secure_password()
        else:
            if validate_password(root_pass) is False:
                raise BadRequestError(
                    "Your password must contain at least one "
                    "lowercase character, one uppercase and one digit")
        plan['root_pass'] = root_pass

    def _create_machine__compute_kwargs(self, plan):
        kwargs = super()._create_machine__compute_kwargs(plan)
        key = kwargs.pop('auth')
        kwargs['ex_authorized_keys'] = [key.public]
        kwargs['ex_private_ip'] = plan['networks']['private_ip']
        kwargs['root_pass'] = plan['root_pass']
        return kwargs

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
                    self.connection.attach_volume(
                        node,
                        libcloud_vol,
                        persist_across_boots=volume['persist_across_boots'])
                except Exception as exc:
                    log.exception('Failed to attach volume')
            else:
                try:
                    self.connection.create_volume(volume['name'],
                                                  volume['size'],
                                                  node=node)
                except Exception as exc:
                    log.exception('Failed to create volume')
