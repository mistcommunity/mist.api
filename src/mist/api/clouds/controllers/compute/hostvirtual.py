from libcloud.compute.providers import get_driver
from libcloud.compute.types import Provider
from mist.api.clouds.controllers.compute.base import BaseComputeController
from mist.api.clouds.controllers.compute.base import (
    log, copy, config, BadRequestError, NotFoundError, InternalServerError,
    node_to_dict, NodeState, BaseHTTPError
)


class HostVirtualComputeController(BaseComputeController):

    def _connect(self, **kwargs):
        return get_driver(Provider.HOSTVIRTUAL)(self.cloud.apikey)

