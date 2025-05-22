import iso8601
import pytz

from libcloud.compute.providers import get_driver
from libcloud.compute.types import Provider
from mist.api.clouds.controllers.compute.base import BaseComputeController
from mist.api.clouds.controllers.compute.base import (
    log, copy, config, BadRequestError, NotFoundError, InternalServerError,
    node_to_dict, NodeState, BaseHTTPError
)

from mist.api.exceptions import BadRequestError


class OnAppComputeController(BaseComputeController):

    def _connect(self, **kwargs):
        return get_driver(Provider.ONAPP)(key=self.cloud.username,
                                          secret=self.cloud.apikey.value,
                                          host=self.cloud.host,
                                          verify=self.cloud.verify)

    def _list_machines__machine_actions(self, machine, node_dict):
        super(OnAppComputeController, self)._list_machines__machine_actions(
            machine, node_dict)
        machine.actions.resize = True
        if node_dict['state'] is NodeState.RUNNING.value:
            machine.actions.suspend = True
        if node_dict['state'] is NodeState.SUSPENDED.value:
            machine.actions.resume = True

    def _list_machines__machine_creation_date(self, machine, node_dict):
        created_at = node_dict['extra'].get('created_at')
        created_at = iso8601.parse_date(created_at)
        created_at = pytz.UTC.normalize(created_at)
        return created_at

    def _list_machines__postparse_machine(self, machine, node_dict):
        updated = False

        os_type = node_dict['extra'].get('operating_system', 'linux')
        # on a VM this has been freebsd and it caused list_machines to raise
        # exception due to validation of machine model
        if os_type not in ('unix', 'linux', 'windows', 'coreos'):
            os_type = 'linux'
        if os_type != machine.os_type:
            machine.os_type = os_type
            updated = True

        image_id = machine.extra.get('template_label') \
            or machine.extra.get('operating_system_distro')
        if image_id != machine.extra.get('image_id'):
            machine.extra['image_id'] = image_id
            updated = True

        if machine.extra.get('template_label'):
            machine.extra.pop('template_label', None)
            updated = True

        size = "%scpu, %sM ram" % \
            (machine.extra.get('cpus'), machine.extra.get('memory'))
        if size != machine.extra.get('size'):
            machine.extra['size'] = size
            updated = True

        return updated

    def _list_machines__cost_machine(self, machine, node_dict):
        if node_dict['state'] == NodeState.STOPPED.value:
            cost_per_hour = node_dict['extra'].get(
                'price_per_hour_powered_off', 0)
        else:
            cost_per_hour = node_dict['extra'].get('price_per_hour', 0)
        return cost_per_hour, 0

    def _list_machines__get_custom_size(self, node):
        # FIXME: resolve circular import issues
        from mist.api.clouds.models import CloudSize
        _size = CloudSize(cloud=self.cloud,
                          external_id=str(node['extra'].get('id')))
        _size.ram = node['extra'].get('memory')
        _size.cpus = node['extra'].get('cpus')
        _size.save()
        return _size

    def _resume_machine(self, machine, node):
        return self.connection.ex_resume_node(node)

    def _suspend_machine(self, machine, node):
        return self.connection.ex_suspend_node(node)

    def _resize_machine(self, machine, node, node_size, kwargs):
        # send only non empty valid args
        valid_kwargs = {}
        for param in kwargs:
            if param in ['memory', 'cpus', 'cpu_shares', 'cpu_units'] \
                    and kwargs[param]:
                valid_kwargs[param] = kwargs[param]
        try:
            return self.connection.ex_resize_node(node,
                                                  **valid_kwargs)
        except Exception as exc:
            raise BadRequestError('Failed to resize node: %s' % exc)

    def _list_locations__fetch_locations(self):
        """Get locations

        We will perform a few calls to get hypervisor_group_id
        parameter sent for create machine, and the max sizes to
        populate the create machine wizard for cpu/disk/memory,
        since this info can be retrieved per location.
        We will also get network information and match it per
        location, useful only to choose network on new VMs

        """
        # calls performed:
        # 1) get list of compute zones - associate
        # location with hypervisor_group_id, max_cpu, max_memory
        # 2) get data store zones and data stores to get max_disk_size
        # 3) get network ids per location

        locations = self.connection.list_locations()
        if locations:
            hypervisors = self.connection.connection.request(
                "/settings/hypervisor_zones.json")
            for loc in locations:
                for hypervisor in hypervisors.object:
                    h = hypervisor.get("hypervisor_group")
                    if str(h.get("location_group_id")) == loc.id:
                        # get max_memory/max_cpu
                        loc.extra["max_memory"] = h.get("max_host_free_memory")
                        loc.extra["max_cpu"] = h.get("max_host_cpu")
                        loc.extra["hypervisor_group_id"] = h.get("id")
                        break

            try:
                data_store_zones = self.connection.connection.request(
                    "/settings/data_store_zones.json").object
                data_stores = self.connection.connection.request(
                    "/settings/data_stores.json").object
            except:
                pass

            for loc in locations:
                # get data store zones, and match with locations
                # through location_group_id
                # then calculate max_disk_size per data store,
                # by matching data store zones and data stores
                try:
                    store_zones = [dsg for dsg in data_store_zones if loc.id is
                                   str(dsg['data_store_group']
                                       ['location_group_id'])]
                    for store_zone in store_zones:
                        stores = [store for store in data_stores if
                                  store['data_store']['data_store_group_id'] is
                                  store_zone['data_store_group']['id']]
                        for store in stores:
                            loc.extra['max_disk_size'] = store['data_store']
                            ['data_store_size'] - store['data_store']['usage']
                except:
                    pass

            try:
                networks = self.connection.connection.request(
                    "/settings/network_zones.json").object
            except:
                pass

            for loc in locations:
                # match locations with network ids (through location_group_id)
                loc.extra['networks'] = []

                try:
                    for network in networks:
                        net = network["network_group"]
                        if str(net["location_group_id"]) == loc.id:
                            loc.extra['networks'].append({'name': net['label'],
                                                          'id': net['id']})
                except:
                    pass

        return locations

    def _list_images__get_min_disk_size(self, image):
        try:
            min_disk_size = int(image.extra.get('min_disk_size'))
        except (TypeError, ValueError):
            return None
        return min_disk_size

    def _list_images__get_min_memory_size(self, image):
        try:
            min_memory_size = int(image.extra.get('min_memory_size'))
        except (TypeError, ValueError):
            return None
        return min_memory_size
