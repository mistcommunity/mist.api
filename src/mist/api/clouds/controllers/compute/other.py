import datetime

from libcloud.compute.providers import get_driver
from libcloud.compute.types import Provider
from mist.api.clouds.controllers.compute.base import BaseComputeController
from mist.api.clouds.controllers.compute.base import (
    log, copy, config, BadRequestError, NotFoundError, InternalServerError,
    node_to_dict, NodeState, BaseHTTPError
)


class OtherComputeController(BaseComputeController):

    def _connect(self, **kwargs):
        return None

    def _list_machines__fetch_machines(self):
        return []

    def _list_machines__update_generic_machine_state(self, machine):
        """Update generic machine state (based on ping/ssh probes)

        It is only used in generic machines.
        """

        # Defaults
        machine.unreachable_since = None

        # If any of the probes has succeeded, then state is running
        if (
            machine.ssh_probe and not machine.ssh_probe.unreachable_since or
            machine.ping_probe and not machine.ping_probe.unreachable_since
        ):
            machine.state = config.STATES[NodeState.RUNNING.value]
        # If ssh probe failed, then unreachable since then
        elif machine.ssh_probe and machine.ssh_probe.unreachable_since:
            machine.unreachable_since = machine.ssh_probe.unreachable_since
            machine.state = config.STATES[NodeState.UNKNOWN.value]
        # Else if ssh probe has never succeeded and ping probe failed,
        # then unreachable since then
        elif (not machine.ssh_probe and
              machine.ping_probe and machine.ping_probe.unreachable_since):
            machine.unreachable_since = machine.ping_probe.unreachable_since
            machine.state = config.STATES[NodeState.UNKNOWN.value]
        else:  # Assume running if no indication otherwise
            machine.state = config.STATES[NodeState.RUNNING.value]

    def _list_machines__generic_machine_actions(self, machine):
        """Update an action for a bare metal machine

        Bare metal machines only support remove, reboot and tag actions"""

        super(OtherComputeController,
              self)._list_machines__generic_machine_actions(machine)
        machine.actions.remove = True

    def _get_libcloud_node(self, machine):
        return None

    def _list_machines__fetch_generic_machines(self):
        from mist.api.machines.models import Machine
        return Machine.objects(cloud=self.cloud, missing_since=None)

    def reboot_machine(self, machine):
        return self.reboot_machine_ssh(machine)

    def remove_machine(self, machine):
        from mist.api.machines.models import KeyMachineAssociation
        KeyMachineAssociation.objects(machine=machine).delete()
        machine.missing_since = datetime.datetime.now()
        machine.save()

    def list_images(self, persist=True, search=None):
        return []

    def list_sizes(self, persist=True):
        return []

    def list_locations(self, persist=True):
        return []
