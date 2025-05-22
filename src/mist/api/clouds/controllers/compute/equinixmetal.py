from libcloud.compute.providers import get_driver
from libcloud.compute.types import Provider
from mist.api.clouds.controllers.compute.base import BaseComputeController
from mist.api.clouds.controllers.compute.base import (
    log, copy, config, BadRequestError, NotFoundError, InternalServerError,
    node_to_dict, NodeState, BaseHTTPError
)

from mist.api.exceptions import BadRequestError


class EquinixMetalComputeController(BaseComputeController):

    def _connect(self, **kwargs):
        project_id = self.cloud.project_id.value if self.cloud.project_id \
            else ''
        return get_driver(
            Provider.EQUINIXMETAL)(self.cloud.apikey.value,
                                   project=project_id)

    def _list_machines__machine_creation_date(self, machine, node_dict):
        return node_dict['extra'].get('created_at')  # iso8601 string

    def _list_machines__cost_machine(self, machine, node_dict):
        size = node_dict['extra'].get('plan')
        from mist.api.clouds.models import CloudSize
        try:
            _size = CloudSize.objects.get(external_id=size, cloud=self.cloud)
        except CloudSize.DoesNotExist:
            # for some sizes, part of the name instead of id is returned
            # eg. t1.small.x86 for size is returned for size with external_id
            # baremetal_0 and name t1.small.x86 - 8192 RAM
            try:
                _size = CloudSize.objects.get(cloud=self.cloud,
                                              name__contains=size)
            except CloudSize.DoesNotExist:
                log.warn('EquinixMetal size %s not found', size)
                return 0, 0

        price = _size.extra.get('price', 0.0)
        if machine.extra.get('billing_cycle') == 'hourly':
            return price, 0

    def _list_machines__get_location(self, node_dict):
        return node_dict['extra'].get('facility', {}).get('id', '')

    def _list_machines__get_size(self, node_dict):
        return node_dict['extra'].get('plan')

    def _list_images__get_os_distro(self, image):
        try:
            os_distro = image.extra.get('distro').lower()
        except AttributeError:
            return super()._list_images__get_os_distro(image)
        return os_distro

    def _list_sizes__get_cpu(self, size):
        return int(size.extra.get('cpu_cores') or 1)

    def _list_sizes__get_available_locations(self, mist_size):
        from mist.api.clouds.models import CloudLocation
        CloudLocation.objects(
            cloud=self.cloud,
            external_id__in=mist_size.extra.get('regions', [])
        ).update(add_to_set__available_sizes=mist_size)

    def _list_images__get_allowed_sizes(self, mist_image):
        from mist.api.clouds.models import CloudSize
        CloudSize.objects(
            cloud=self.cloud,
            external_id__in=mist_image.extra.get('provisionable_on', [])
        ).update(add_to_set__allowed_images=mist_image)

    def _list_images__get_architecture(self, image):
        ret_list = []
        sizes = image.extra.get('provisionable_on', [])
        if any('arm' in size for size in sizes):
            ret_list.append('arm')
        if any('x86' in size for size in sizes):
            ret_list.append('x86')
        return ret_list or ['x86']

    def _generate_plan__parse_networks(self, auth_context, networks_dict,
                                       location):
        try:
            ip_addresses = networks_dict['ip_addresses']
        except KeyError:
            return None
        # one private IPv4 is required
        private_ipv4 = False
        for address in ip_addresses:
            try:
                address_family = address['address_family']
                cidr = address['cidr']
                public = address['public']
            except KeyError:
                raise BadRequestError(
                    'Required parameter missing on ip_addresses'
                )
            if address_family == 4 and public is True:
                private_ipv4 = True
            if address_family not in (4, 6):
                raise BadRequestError(
                    'Valid values for address_family are: 4, 6'
                )
            if address_family == 4 and cidr not in range(28, 33):
                raise BadRequestError(
                    'Invalid value for cidr block'
                )
            if address_family == 6 and cidr not in range(124, 128):
                raise BadRequestError(
                    'Invalid value for cidr block'
                )
            if type(public) != bool:
                raise BadRequestError(
                    'Invalid value for public'
                )
        if private_ipv4 is False:
            raise BadRequestError(
                'A private IPv4 needs to be included in ip_addresses'
            )
        return {'ip_addresses': ip_addresses}

    def _generate_plan__parse_extra(self, extra, plan):
        project_id = extra.get('project_id')
        if not project_id:
            if self.connection.project_id:
                project_id = self.connection.project_id
            else:
                try:
                    project_id = self.connection.projects[0].id
                except IndexError:
                    raise BadRequestError(
                        "You don't have any projects on Equinix Metal"
                    )
        else:
            for project in self.connection.projects:
                if project_id in (project.name, project.id):
                    project_id = project.id
                    break
            else:
                raise BadRequestError(
                    "Project does not exist"
                )
        plan['project_id'] = project_id

    def _create_machine__get_key_object(self, key):
        from libcloud.utils.publickey import get_pubkey_openssh_fingerprint
        key_obj = super()._create_machine__get_key_object(key)
        fingerprint = get_pubkey_openssh_fingerprint(key_obj.public)
        keys = self.connection.list_key_pairs()
        for k in keys:
            if fingerprint == k.fingerprint:
                ssh_keys = [{
                    'label': k.extra['label'],
                    'key': k.public_key
                }]
                break
        else:
            ssh_keys = [{
                'label': f'mistio-{key_obj.name}',
                'key': key_obj.public
            }]
        return ssh_keys

    def _create_machine__compute_kwargs(self, plan):
        kwargs = super()._create_machine__compute_kwargs(plan)
        kwargs['ex_project_id'] = plan['project_id']
        kwargs['cloud_init'] = plan.get('cloudinit')
        kwargs['ssh_keys'] = kwargs.pop('auth')
        try:
            kwargs['ip_addresses'] = plan['networks']['ip_addresses']
        except (KeyError, TypeError):
            pass
        return kwargs
