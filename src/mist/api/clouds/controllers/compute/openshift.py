import socket

from libcloud.container.providers import get_driver as get_container_driver
from libcloud.container.types import Provider as Container_Provider

from mist.api.clouds.controllers.compute.kubernetes import KubernetesComputeController
from mist.api.helpers import sanitize_host


from mist.api import config
if config.HAS_VPN:
    from mist.vpn.methods import destination_nat as dnat
else:
    from mist.api.dummy.methods import dnat


class OpenShiftComputeController(KubernetesComputeController):
    def _connect(self, **kwargs):
        host, port = dnat(self.cloud.owner,
                          self.cloud.host, self.cloud.port)
        try:
            socket.setdefaulttimeout(15)
            so = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            so.connect((sanitize_host(host), int(port)))
            so.close()
        except Exception:
            raise Exception("Make sure host is accessible "
                            "and kubernetes port is specified")
        # username/password auth
        if self.cloud.username and self.cloud.password:
            key = self.cloud.username
            secret = self.cloud.password
            return get_container_driver(Container_Provider.OPENSHIFT)(
                key=key,
                secret=secret,
                secure=True,
                host=host,
                port=port)
        else:
            msg = '''Necessary parameters for authentication are missing.
            Either a key_file/cert_file pair or a username/pass pair
            or a bearer token.'''
            raise ValueError(msg)

