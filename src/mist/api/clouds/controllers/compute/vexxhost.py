from libcloud.compute.providers import get_driver
from libcloud.compute.types import Provider
from mist.api.clouds.controllers.compute.base import BaseComputeController
from mist.api.clouds.controllers.compute.base import (
    log, copy, config, BadRequestError, NotFoundError, InternalServerError,
    node_to_dict, NodeState, BaseHTTPError
)

from mist.api.clouds.controllers.compute.openstack import OpenStackComputeController

class VexxhostComputeController(OpenStackComputeController):
    def _generate_plan__parse_networks(self, auth_context, networks_dict,
                                       location):
        ret_dict = super()._generate_plan__parse_networks(
            auth_context,
            networks_dict,
            location
        )

        # Vexxhost assigns a public IP when a machine is attached to the
        # 'public' network, so there's no need to assign a floating IP
        # when a user hasn't explicitly asked for it.
        if networks_dict.get('associate_floating_ip') is None:
            ret_dict['associate_floating_ip'] = False

        return ret_dict
