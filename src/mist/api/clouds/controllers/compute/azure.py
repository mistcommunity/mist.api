import tempfile
from libcloud.compute.base import Node
from libcloud.compute.providers import get_driver
from libcloud.compute.types import Provider
from mist.api.clouds.controllers.compute.base import BaseComputeController
from mist.api.clouds.controllers.compute.base import (
    log, copy, config, BadRequestError, NotFoundError, InternalServerError,
    node_to_dict, NodeState, BaseHTTPError
)
from mist.api.exceptions import MachineNotFoundError


class AzureComputeController(BaseComputeController):
    def _connect(self, **kwargs):
        tmp_cert_file = tempfile.NamedTemporaryFile(delete=False)
        tmp_cert_file.write(self.cloud.certificate.value.encode())
        tmp_cert_file.close()
        return get_driver(Provider.AZURE)(self.cloud.subscription_id.value,
                                          tmp_cert_file.name)

    def _list_machines__postparse_machine(self, machine, node_dict):
        updated = False
        os_type = node_dict['extra'].get('os_type', 'linux')
        if machine.os_type != os_type:
            machine.os_type = os_type
            updated = True
        return updated

    def _list_machines__cost_machine(self, machine, node_dict):
        if node_dict['state'] not in [NodeState.RUNNING.value,
                                      NodeState.PAUSED.value]:
            return 0, 0
        return node_dict['extra'].get('cost_per_hour', 0), 0

    def _list_images__fetch_images(self, search=None):
        images = self.connection.list_images()
        images = [image for image in images
                  if 'RightImage' not in image.name and
                  'Barracude' not in image.name and
                  'BizTalk' not in image.name]
        # There are many builds for some images eg Ubuntu.
        # All have the same name!
        images_dict = {}
        for image in images:
            if image.name not in images_dict:
                images_dict[image.name] = image
        return list(images_dict.values())

    def _cloud_service(self, node_id):
        """
        Azure libcloud driver needs the cloud service
        specified as well as the node
        """
        cloud_service = self.connection.get_cloud_service_from_node_id(
            node_id)
        return cloud_service

    def _get_libcloud_node(self, machine, no_fail=False):
        cloud_service = self._cloud_service(machine.external_id)
        for node in self.connection.list_nodes(
                ex_cloud_service_name=cloud_service):
            if node.id == machine.external_id:
                return node
            if no_fail:
                return Node(machine.external_id, name=machine.external_id,
                            state=0, public_ips=[], private_ips=[],
                            driver=self.connection)
            raise MachineNotFoundError("Machine with id '%s'." %
                                       machine.external_id)

    def _start_machine(self, machine, node):
        cloud_service = self._cloud_service(machine.external_id)
        return self.connection.ex_start_node(
            node, ex_cloud_service_name=cloud_service)

    def _stop_machine(self, machine, node):
        cloud_service = self._cloud_service(machine.external_id)
        return self.connection.ex_stop_node(
            node, ex_cloud_service_name=cloud_service)

    def _reboot_machine(self, machine, node):
        cloud_service = self._cloud_service(machine.external_id)
        return self.connection.reboot_node(
            node, ex_cloud_service_name=cloud_service)

    def _destroy_machine(self, machine, node):
        cloud_service = self._cloud_service(machine.external_id)
        return self.connection.destroy_node(
            node, ex_cloud_service_name=cloud_service)

    def _list_machines__machine_actions(self, machine, node_dict):
        super(AzureComputeController, self)._list_machines__machine_actions(
            machine, node_dict)
        if node_dict['state'] is NodeState.PAUSED.value:
            machine.actions.start = True

