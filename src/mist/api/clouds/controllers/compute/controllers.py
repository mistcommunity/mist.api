"""Cloud ComputeControllers

A cloud controller handles all operations that can be performed on a cloud,
commonly using libcloud under the hood.

It also performs several steps and combines the information stored in the
database with that returned from API calls to providers.

For each different cloud type, there is a corresponding cloud controller
defined here. All the different classes inherit BaseComputeController and share
a common interface, with the exception that some controllers may not have
implemented all methods.

A cloud controller is initialized given a cloud. Most of the time it will be
accessed through a cloud model, using the `ctl` abbreviation, like this:

    cloud = mist.api.clouds.models.Cloud.objects.get(id=cloud_id)
    print cloud.ctl.compute.list_machines()

"""

import socket
import logging
import netaddr

from mist.api.clouds.controllers.compute.alibaba import AlibabaComputeController
from mist.api.clouds.controllers.compute.amazon import AmazonComputeController
from mist.api.clouds.controllers.compute.azure import AzureComputeController
from mist.api.clouds.controllers.compute.azure_arm import AzureArmComputeController
from mist.api.clouds.controllers.compute.base import BaseComputeController
from mist.api.clouds.controllers.compute.cloudsigma import CloudSigmaComputeController
from mist.api.clouds.controllers.compute.digitalocean import DigitalOceanComputeController
from mist.api.clouds.controllers.compute.docker import DockerComputeController
from mist.api.clouds.controllers.compute.equinixmetal import EquinixMetalComputeController
from mist.api.clouds.controllers.compute.google import GoogleComputeController
from mist.api.clouds.controllers.compute.hostvirtual import HostVirtualComputeController
from mist.api.clouds.controllers.compute.kubernetes import KubernetesComputeController
from mist.api.clouds.controllers.compute.kubevirt import KubeVirtComputeController
from mist.api.clouds.controllers.compute.libvirt import LibvirtComputeController
from mist.api.clouds.controllers.compute.linode import LinodeComputeController
from mist.api.clouds.controllers.compute.lxd import LXDComputeController
from mist.api.clouds.controllers.compute.maxihost import MaxihostComputeController
from mist.api.clouds.controllers.compute.onapp import OnAppComputeController
from mist.api.clouds.controllers.compute.openshift import OpenShiftComputeController
from mist.api.clouds.controllers.compute.openstack import OpenStackComputeController
from mist.api.clouds.controllers.compute.other import OtherComputeController
from mist.api.clouds.controllers.compute.rackspace import RackSpaceComputeController
from mist.api.clouds.controllers.compute.softlayer import SoftLayerComputeController
from mist.api.clouds.controllers.compute.vexxhost import VexxhostComputeController
from mist.api.clouds.controllers.compute.vsphere import VSphereComputeController
from mist.api.clouds.controllers.compute.vultr import VultrComputeController

log = logging.getLogger(__name__)

def is_private_subnet(host):
    try:
        ip_addr = netaddr.IPAddress(host)
    except netaddr.AddrFormatError:
        try:
            ip_addr = netaddr.IPAddress(socket.gethostbyname(host))
        except socket.gaierror:
            return False
    return ip_addr.is_private()

