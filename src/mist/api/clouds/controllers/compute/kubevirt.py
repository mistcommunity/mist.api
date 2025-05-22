from libcloud.compute.types import Provider
from mist.api.clouds.controllers.compute.kubernetes import _KubernetesBaseComputeController


class KubeVirtComputeController(_KubernetesBaseComputeController):
    def _connect(self, **kwargs):
        return super()._connect(Provider.KUBEVIRT,
                                use_container_driver=False,
                                **kwargs)

    def _list_machines__postparse_machine(self, machine, node_dict):
        updated = False
        if machine.machine_type != 'container':
            machine.machine_type = 'container'
            updated = True

        if node_dict['extra']['pvcs']:
            pvcs = node_dict['extra']['pvcs']
            from mist.api.models import Volume
            volumes = Volume.objects.filter(
                cloud=self.cloud, missing_since=None)
            for volume in volumes:
                if 'pvc' in volume.extra:
                    if volume.extra['pvc']['name'] in pvcs:
                        if machine not in volume.attached_to:
                            volume.attached_to.append(machine)
                            volume.save()
                            updated = True
        return updated

    def _list_machines__machine_actions(self, machine, node_dict):
        super()._list_machines__machine_actions(machine, node_dict)
        machine.actions.expose = True

    def expose_port(self, machine, port_forwards):
        machine_libcloud = self._get_libcloud_node(machine)

        # validate input
        from mist.api.machines.methods import validate_portforwards_kubevirt
        data = validate_portforwards_kubevirt(port_forwards)

        self.connection.ex_create_service(machine_libcloud, data.get(
                                          'ports', []),
                                          service_type=data.get(
                                              'service_type'),
                                          override_existing_ports=True,
                                          cluster_ip=data.get(
                                              'cluster_ip', None),
                                          load_balancer_ip=data.get(
                                              'load_balancer_ip', None))
