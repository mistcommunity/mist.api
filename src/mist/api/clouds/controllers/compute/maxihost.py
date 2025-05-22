from libcloud.compute.providers import get_driver
from libcloud.compute.types import Provider
from mist.api.clouds.controllers.compute.base import BaseComputeController
from mist.api.clouds.controllers.compute.base import (
    log, copy, config, BadRequestError, NotFoundError, InternalServerError,
    node_to_dict, NodeState, BaseHTTPError
)


class MaxihostComputeController(BaseComputeController):

    def _connect(self, **kwargs):
        return get_driver(Provider.MAXIHOST)(self.cloud.token.value)

    def _list_machines__machine_actions(self, machine, node_dict):
        super(MaxihostComputeController, self)._list_machines__machine_actions(
            machine, node_dict)
        if node_dict['state'] is NodeState.PAUSED.value:
            machine.actions.start = True

    def _list_machines__postparse_machine(self, machine, node_dict):
        updated = False
        if node_dict['extra'].get('ips', []):
            name = node_dict['extra'].get('ips')[0].get(
                'device_hostname')
            if machine.hostname != name:
                machine.hostname = name
                updated = True
        return updated

    def _list_machines__get_location(self, node):
        return node['extra'].get('location').get('facility_code')

    def _start_machine(self, machine, node):
        node.id = node.extra.get('id', '')
        return self.connection.ex_start_node(node)

    def _stop_machine(self, machine, node):
        node.id = node.extra.get('id', '')
        return self.connection.ex_stop_node(node)

    def _reboot_machine(self, machine, node):
        node.id = node.extra.get('id', '')
        return self.connection.reboot_node(node)

    def _destroy_machine(self, machine, node):
        node.id = node.extra.get('id', '')
        return self.connection.destroy_node(node)

    def _list_sizes__get_name(self, size):
        name = size.extra['specs']['cpus']['type']
        try:
            cpus = int(size.extra['specs']['cpus']['cores'])
        except ValueError:  # 'N/A'
            cpus = None
        memory = size.extra['specs']['memory']['total']
        disk_count = size.extra['specs']['drives'][0]['count']
        disk_size = size.extra['specs']['drives'][0]['size']
        disk_type = size.extra['specs']['drives'][0]['type']
        cpus_info = str(cpus) + ' cores/' if cpus else ''
        return name + '/ ' + cpus_info \
                           + memory + ' RAM/ ' \
                           + str(disk_count) + ' * ' + disk_size + ' ' \
                           + disk_type

    def _list_images__get_os_type(self, image):
        if image.extra.get('operating_system', ''):
            return image.extra.get('operating_system').lower()
        if 'windows' in image.name.lower():
            return 'windows'
        else:
            return 'linux'

