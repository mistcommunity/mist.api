from libcloud.compute.providers import get_driver
from libcloud.compute.types import Provider
from mist.api.clouds.controllers.compute.base import BaseComputeController
from mist.api.clouds.controllers.compute.base import (
    log, copy, config, BadRequestError, NotFoundError, InternalServerError,
    node_to_dict, NodeState, BaseHTTPError
)


class RackSpaceComputeController(BaseComputeController):

    def _connect(self, **kwargs):
        driver = get_driver(Provider.RACKSPACE)
        return driver(self.cloud.username, self.cloud.apikey.value,
                      region=self.cloud.region)

    def _list_machines__machine_creation_date(self, machine, node_dict):
        return node_dict['extra'].get('created')  # iso8601 string

    def _list_machines__machine_actions(self, machine, node_dict):
        super(RackSpaceComputeController,
              self)._list_machines__machine_actions(machine, node_dict)
        machine.actions.rename = True

    def _list_machines__cost_machine(self, machine, node_dict):
        # Need to get image in order to specify the OS type
        # out of the image id.
        size = node_dict['extra'].get('flavorId')
        location = self.connection.region[:3]
        driver_name = 'rackspacenova' + location
        price = None
        try:
            price = get_size_price(driver_type='compute',
                                   driver_name=driver_name,
                                   size_id=size)
        except KeyError:
            log.error('Pricing for %s:%s was not found.' % (driver_name, size))

        if price:
            plan_price = price.get(machine.os_type) or price.get('linux')
            # 730 is the number of hours per month as on
            # https://www.rackspace.com/calculator
            return plan_price, float(plan_price) * 730

            # TODO: RackSpace mentions on
            # https://www.rackspace.com/cloud/public-pricing
            # there's a minimum service charge of $50/mo across all servers.
        return 0, 0

    def _list_machines__postparse_machine(self, machine, node_dict):
        updated = False
        # Find os_type. TODO: Look in extra
        os_type = machine.os_type or 'linux'
        if machine.os_type != os_type:
            machine.os_type = os_type
            updated = True
        return updated

    def _list_machines__get_size(self, node):
        return node['extra'].get('flavorId')

    def _list_sizes__get_cpu(self, size):
        return size.vcpus

    def _list_images__get_os_type(self, image):
        if image.extra.get('metadata', '').get('os_type', ''):
            return image.extra.get('metadata').get('os_type').lower()
        if 'windows' in image.name.lower():
            return 'windows'
        else:
            return 'linux'

    def _list_images__get_os_distro(self, image):
        try:
            os_distro = image.extra.get('metadata', {}).get('os_distro').lower()  # noqa
        except AttributeError:
            return super()._list_images__get_os_distro(image)
        return os_distro

    def _list_images__get_min_disk_size(self, image):
        try:
            min_disk_size = int(image.extra.get('minDisk'))
        except (TypeError, ValueError):
            return None
        return min_disk_size

    def _list_images__get_min_memory_size(self, image):
        try:
            min_memory_size = int(image.extra.get('minRam'))
        except (TypeError, ValueError):
            return None
        return min_memory_size
