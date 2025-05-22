import tempfile
import mongoengine as me

from libcloud.compute.providers import get_driver
from libcloud.compute.types import Provider
from mist.api.clouds.controllers.compute.base import BaseComputeController
from mist.api.clouds.controllers.compute.base import (
    log, copy, config, BadRequestError, NotFoundError, InternalServerError,
    node_to_dict, NodeState, BaseHTTPError
)

from mist.api.exceptions import BadRequestError
from mist.api.exceptions import NotFoundError

from mist.api import config
if config.HAS_VPN:
    from mist.vpn.methods import destination_nat as dnat
else:
    from mist.api.dummy.methods import dnat

class VSphereComputeController(BaseComputeController):

    def _connect(self, **kwargs):
        from libcloud.compute.drivers.vsphere import VSphereNodeDriver
        from libcloud.compute.drivers.vsphere import VSphere_6_7_NodeDriver
        ca_cert = None
        if self.cloud.ca_cert_file:
            ca_cert_temp_file = tempfile.NamedTemporaryFile(delete=False)
            ca_cert_temp_file.write(self.cloud.ca_cert_file.value.encode())
            ca_cert_temp_file.close()
            ca_cert = ca_cert_temp_file.name

        host, port = dnat(self.cloud.owner, self.cloud.host, 443)
        driver_6_5 = VSphereNodeDriver(host=host,
                                       username=self.cloud.username,
                                       password=self.cloud.password.value,
                                       port=port,
                                       ca_cert=ca_cert)
        self.version = driver_6_5._get_version()
        if '6.7' in self.version and config.ENABLE_VSPHERE_REST:
            self.version = '6.7'
            return VSphere_6_7_NodeDriver(self.cloud.username,
                                          secret=self.cloud.password.value,
                                          host=host,
                                          port=port,
                                          ca_cert=ca_cert)
        else:
            self.version = "6.5-"
            return driver_6_5

    def check_connection(self):
        """Check connection without performing `list_machines`

        In vSphere we are sure we got a successful connection with the provider
        if `self.connect` works, no need to run a `list_machines` to find out.

        """
        self.connect()

    def _list_machines__get_location(self, node_dict):
        cluster = node_dict['extra'].get('cluster', '')
        host = node_dict['extra'].get('host', '')
        return cluster or host

    def list_vm_folders(self):
        all_folders = self.connection.ex_list_folders()
        vm_folders = [folder for folder in all_folders if
                      "VirtualMachine" in folder[
                          'type'] or "VIRTUAL_MACHINE" in folder['type']]
        return vm_folders

    def list_datastores(self):
        datastores_raw = self.connection.ex_list_datastores()
        return datastores_raw

    def _list_locations__fetch_locations(self):
        """List locations for vSphere

        Return all locations, clusters and hosts
        """
        return self.connection.list_locations()

    def _list_machines__fetch_machines(self):
        """Perform the actual libcloud call to get list of nodes"""
        machine_list = []
        for node in self.connection.list_nodes(
                max_properties=self.cloud.max_properties_per_request,
                extra=config.VSPHERE_FETCH_ALL_EXTRA):
            # Check for VMs without uuid
            if node.id is None:
                log.error("Skipping machine {} on cloud {} - {}): uuid is "
                          "null".format(node.name,
                                        self.cloud.name,
                                        self.cloud.id))
                continue
            machine_list.append(node_to_dict(node))
        return machine_list

    def _list_machines__get_size(self, node_dict):
        """Return key of size_map dict for a specific node

        Subclasses MAY override this method.
        """
        return None

    def _list_machines__get_custom_size(self, node_dict):
        # FIXME: resolve circular import issues
        from mist.api.clouds.models import CloudSize
        updated = False
        try:
            _size = CloudSize.objects.get(
                cloud=self.cloud,
                external_id=node_dict['size'].get('id'))
        except me.DoesNotExist:
            _size = CloudSize(cloud=self.cloud,
                              external_id=str(node_dict['size'].get('id')))
            updated = True
        if _size.ram != node_dict['size'].get('ram'):
            _size.ram = node_dict['size'].get('ram')
            updated = True
        if _size.cpus != node_dict['size'].get('extra', {}).get('cpus'):
            _size.cpus = node_dict['size'].get('extra', {}).get('cpus')
            updated = True
        if _size.disk != node_dict['size'].get('disk'):
            _size.disk = node_dict['size'].get('disk')
            updated = True
        name = ""
        if _size.cpus:
            name += f'{_size.cpus}vCPUs, '
        if _size.ram:
            name += f'{_size.ram}MB RAM, '
        if _size.disk:
            name += f'{_size.disk}GB disk.'
        if _size.name != name:
            _size.name = name
            updated = True
        if updated:
            _size.save()
        return _size

    def _list_machines__machine_actions(self, machine, node_dict):
        super(VSphereComputeController, self)._list_machines__machine_actions(
            machine, node_dict)
        machine.actions.clone = True
        machine.actions.rename = True
        machine.actions.create_snapshot = True
        machine.actions.remove_snapshot = True
        machine.actions.revert_to_snapshot = True

    def _stop_machine(self, machine, node):
        return self.connection.stop_node(node)

    def _start_machine(self, machine, node):
        return self.connection.start_node(node)

    def _create_machine_snapshot(self, machine, node,
                                 snapshot_name, description='',
                                 dump_memory=False, quiesce=False):
        """Create a snapshot for a given machine"""
        return self.connection.ex_create_snapshot(
            node, snapshot_name, description,
            dump_memory=dump_memory, quiesce=quiesce)

    def _revert_machine_to_snapshot(self, machine, node,
                                    snapshot_name=None):
        """Revert a given machine to a previous snapshot"""
        return self.connection.ex_revert_to_snapshot(node,
                                                     snapshot_name)

    def _remove_machine_snapshot(self, machine, node,
                                 snapshot_name=None):
        """Removes a given machine snapshot"""
        return self.connection.ex_remove_snapshot(node,
                                                  snapshot_name)

    def _list_machine_snapshots(self, machine, node):
        return self.connection.ex_list_snapshots(node)

    def _list_images__fetch_images(self, search=None):
        image_folders = []
        if config.VSPHERE_IMAGE_FOLDERS:
            image_folders = config.VSPHERE_IMAGE_FOLDERS
        image_list = self.connection.list_images(folder_ids=image_folders)
        # Check for templates without uuid
        for image in image_list[:]:
            if image.id is None:
                log.error("Skipping machine {} on cloud {} - {}): uuid is "
                          "null".format(image.name,
                                        self.cloud.name,
                                        self.cloud.id))
                image_list.remove(image)
        return image_list

    def _clone_machine(self, machine, node, name, resume):
        locations = self.connection.list_locations()
        node_location = None
        if not machine.location:
            vm = self.connection.find_by_uuid(node.id)
            location_id = vm.summary.runtime.host.name
        else:
            location_id = machine.location.external_id
        for location in locations:
            if location.id == location_id:
                node_location = location
                break
        folder = node.extra.get('folder', None)

        if not folder:
            try:
                folder = vm.parent._moId
            except Exception as exc:
                raise BadRequestError(
                    "Failed to find folder the folder containing the machine")
                log.error(
                    "Clone Machine: Exception when "
                    "looking for folder: {}".format(exc))
        datastore = node.extra.get('datastore', None)
        node = self.connection.create_node(name=name, image=node,
                                           size=node.size,
                                           location=node_location,
                                           ex_folder=folder,
                                           ex_datastore=datastore)
        return node_to_dict(node)

    def _get_libcloud_node(self, machine):
        vm = self.connection.find_by_uuid(machine.external_id)
        return self.connection._to_node_recursive(vm)

    def _generate_plan__parse_networks(self, auth_context, networks_dict,
                                       location):

        try:
            network_search = networks_dict['network']
        except KeyError:
            return None

        from mist.api.methods import list_resources

        try:
            [network], _ = list_resources(auth_context,
                                          'network',
                                          search=network_search,
                                          cloud=self.cloud.id,
                                          limit=1)
        except ValueError:
            raise BadRequestError(f'Network: {network_search} not found')

        return {
            'id': network.id,
            'name': network.name,
            'external_id': network.network_id,
        }

    def _generate_plan__parse_extra(self, extra, plan):
        folder = extra.get('folder')
        if folder:
            folders = self.connection.ex_list_folders()
            folder_dict = next((item for item in folders
                                if (item.get('id') == folder or
                                    item.get('name') == folder)),
                               None)
            if folder_dict is None:
                raise NotFoundError(
                    f'Folder: {folder} not found')

            folder_features = folder_dict.get('type') or []
            if 'VirtualMachine' not in folder_features:
                raise BadRequestError(
                    f'Folder: {folder} does not support machine provisioning'
                )
            plan['folder'] = {
                'id': folder_dict['id'],
                'name': folder_dict['name'],
            }

        datastore = extra.get('datastore')
        if datastore:
            datastores = self.connection.ex_list_datastores()
            datastore_dict = next((item for item in datastores
                                   if (item.get('id') == datastore or
                                       item.get('name') == datastore)),
                                  None)

            if datastore_dict is None:
                raise NotFoundError(
                    f'Datastore: {datastore} not found'
                )
            plan['datastore'] = {
                'id': datastore_dict['id'],
                'name': datastore_dict['name'],
            }

    def _create_machine__get_size_object(self, size):
        # even though vsphere has custom sizes `create_node`
        # expects a libcloud NodeSize object. Create a dummy
        # one with only the attributes necessary
        from libcloud.compute.base import NodeSize
        nodesize = NodeSize(id=None,
                            name=None,
                            ram=size['ram'],
                            disk=None,
                            bandwidth=None,
                            price=None,
                            driver=self.connection,
                            extra={
                                'cpus': size['cpus']
                            })
        return nodesize

    def _create_machine__compute_kwargs(self, plan):
        kwargs = super()._create_machine__compute_kwargs(plan)

        try:
            kwargs['ex_network'] = plan['networks']['external_id']
        except KeyError:
            kwargs['ex_network'] = None

        try:
            kwargs['ex_folder'] = plan['folder']['id']
        except KeyError:
            kwargs['ex_folder'] = None
        try:
            kwargs['ex_datastore'] = plan['datastore']['id']
        except KeyError:
            kwargs['ex_datastore'] = None
        return kwargs

