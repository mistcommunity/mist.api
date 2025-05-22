import iso8601
import pytz
from libcloud.compute.providers import get_driver
from libcloud.compute.types import Provider
from mist.api.clouds.controllers.compute.base import BaseComputeController
from mist.api.clouds.controllers.compute.base import (
    log, copy, config, BadRequestError, NotFoundError, InternalServerError,
    node_to_dict, NodeState, BaseHTTPError
)


class SoftLayerComputeController(BaseComputeController):

    def _connect(self, **kwargs):
        return get_driver(Provider.SOFTLAYER)(self.cloud.username,
                                              self.cloud.apikey.value)

    def _list_machines__machine_creation_date(self, machine, node_dict):
        try:
            created_at = node_dict['extra']['created']
        except KeyError:
            return None

        try:
            created_at = iso8601.parse_date(created_at)
        except iso8601.ParseError as exc:
            log.error(str(exc))
            return created_at

        created_at = pytz.UTC.normalize(created_at)
        return created_at

    def _list_machines__postparse_machine(self, machine, node_dict):
        updated = False
        os_type = 'linux'
        if 'windows' in str(
                node_dict['extra'].get('image', '')).lower():
            os_type = 'windows'
        if os_type != machine.os_type:
            machine.os_type = os_type
            updated = True

        # Get number of vCPUs for bare metal and cloud servers, respectively.
        if 'cpu' in node_dict['extra'] and \
                node_dict['extra'].get('cpu') != machine.extra.get(
                    'cpus'):
            machine.extra['cpus'] = node_dict['extra'].get['cpu']
            updated = True
        elif 'maxCpu' in node_dict.extra and \
                machine.extra['cpus'] != node_dict['extra']['maxCpu']:
            machine.extra['cpus'] = node_dict['extra']['maxCpu']
            updated = True
        return updated

    def _list_machines__cost_machine(self, machine, node_dict):
        # SoftLayer includes recurringFee on the VM metadata but
        # this is only for the compute - CPU pricing.
        # Other costs (ram, bandwidth, image) are included
        # on billingItemChildren.

        extra_fee = 0
        if not node_dict['extra'].get('hourlyRecurringFee'):
            cpu_fee = float(node_dict['extra'].get('recurringFee'))
            for item in node_dict['extra'].get('billingItemChildren',
                                               ()):
                # don't calculate billing that is cancelled
                if not item.get('cancellationDate'):
                    extra_fee += float(item.get('recurringFee'))
            return 0, cpu_fee + extra_fee
        else:
            # node_dict['extra'].get('recurringFee')
            # here will show what it has cost for the current month, up to now.
            cpu_fee = float(
                node_dict['extra'].get('hourlyRecurringFee'))
            for item in node_dict['extra'].get('billingItemChildren',
                                               ()):
                # don't calculate billing that is cancelled
                if not item.get('cancellationDate'):
                    extra_fee += float(item.get('hourlyRecurringFee'))

            return cpu_fee + extra_fee, 0

    def _list_machines__get_location(self, node):
        return node['extra'].get('datacenter')

    def _reboot_machine(self, machine, node):
        self.connection.reboot_node(node)
        return True

    def _destroy_machine(self, machine, node):
        self.connection.destroy_node(node)

    def _parse_networks_from_request(self, auth_context, networks_dict):
        ret_networks = {}
        vlan = networks_dict.get('vlan')
        if vlan:
            ret_networks['vlan'] = vlan
        return ret_networks

    def _parse_extra_from_request(self, extra, plan):
        plan['metal'] = extra.get('metal', False)
        plan['hourly'] = extra.get('hourly', False)

    def _post_parse_plan(self, plan):
        machine_name = plan.get('machine_name')
        if '.' in machine_name:
            plan['domain'] = '.'.join(machine_name.split('.')[1:])
            plan['machine_name'] = machine_name.split('.')[0]
