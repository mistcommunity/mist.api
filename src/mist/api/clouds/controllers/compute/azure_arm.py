import json
import secrets
import time
import re
import os
import mongoengine as me

from libcloud.compute.base import NodeImage
from libcloud.compute.base import NodeAuthSSHKey, NodeAuthPassword
from libcloud.compute.providers import get_driver
from libcloud.compute.types import Provider

from mist.api.clouds.controllers.compute.base import BaseComputeController
from mist.api.clouds.controllers.compute.base import (
    log, copy, config, BadRequestError, NotFoundError, InternalServerError,
    node_to_dict, NodeState, BaseHTTPError
)

from mist.api.exceptions import BadRequestError
from mist.api.exceptions import MachineCreationError

from mist.api.helpers import validate_password


class AzureArmComputeController(BaseComputeController):

    def _connect(self, **kwargs):
        return get_driver(Provider.AZURE_ARM)(self.cloud.tenant_id,
                                              self.cloud.subscription_id,
                                              self.cloud.key,
                                              self.cloud.secret.value)

    def _list_machines__postparse_machine(self, machine, node_dict):
        updated = False
        os_type = node_dict['extra'].get('os_type', 'linux')
        if os_type != machine.os_type:
            machine.os_type = os_type
            updated = True

        subnet = node_dict['extra'].get('subnet')
        if subnet:
            network_id = subnet.split('/subnets')[0]
            from mist.api.networks.models import Network
            try:
                network = Network.objects.get(cloud=self.cloud,
                                              external_id=network_id,
                                              missing_since=None)
                if network != machine.network:
                    machine.network = network
                    updated = True
            except me.DoesNotExist:
                pass

        network_id = machine.network.external_id if machine.network else ''
        if machine.extra.get('network') != network_id:
            machine.extra['network'] = network_id
            updated = True

        return updated

    def _list_machines__cost_machine(self, machine, node_dict):
        if node_dict['state'] not in [NodeState.RUNNING.value,
                                      NodeState.PAUSED.value]:
            return 0, 0
        return node_dict['extra'].get('cost_per_hour', 0), 0

    def _list_machines__machine_actions(self, machine, node_dict):
        super(AzureArmComputeController, self)._list_machines__machine_actions(
            machine, node_dict)
        if node_dict['state'] is NodeState.PAUSED.value:
            machine.actions.start = True

    def _list_machines__get_location(self, node):
        return node['extra'].get('location')

    def _list_machines__get_size(self, node):
        return node['extra'].get('size')

    def _list_images__fetch_images(self, search=None):
        images_file = os.path.join(config.MIST_API_DIR,
                                   config.AZURE_IMAGES_FILE)
        with open(images_file, 'r') as f:
            default_images = json.load(f)
        images = [NodeImage(id=image, name=name,
                            driver=self.connection, extra={})
                  for image, name in list(default_images.items())]
        return images

    def _reboot_machine(self, machine, node):
        self.connection.reboot_node(node)

    def _destroy_machine(self, machine, node):
        self.connection.destroy_node(node)

    def _list_sizes__fetch_sizes(self):
        location = self.connection.list_locations()[0]
        return self.connection.list_sizes(location)

    def _list_sizes__get_cpu(self, size):
        return size.extra.get('numberOfCores')

    def _list_sizes__get_name(self, size):
        return size.name + ' ' + str(size.extra['numberOfCores']) \
                         + ' cpus/' + str(size.ram / 1024) + 'GB RAM/ ' \
                         + str(size.disk) + 'GB SSD'

    def _list_locations__get_available_sizes(self, location):
        libcloud_size_ids = [size.id
                          for size in self.connection.list_sizes(location=location)]  # noqa

        from mist.api.clouds.models import CloudSize

        return CloudSize.objects(cloud=self.cloud,
                                 external_id__in=libcloud_size_ids)

    def _list_machines__machine_creation_date(self, machine, node_dict):
        # workaround to avoid overwriting creation time
        # as Azure updates it when a machine stops, reboots etc.

        if machine.created is not None:
            return machine.created

        return super()._list_machines__machine_creation_date(machine,
                                                             node_dict)

    def _generate_plan__parse_networks(self, auth_context, networks_dict,
                                       location):
        return networks_dict.get('network')

    def _generate_plan__parse_custom_volume(self, volume_dict):
        try:
            size = int(volume_dict['size'])
        except KeyError:
            raise BadRequestError('Volume size parameter is required')
        except (TypeError, ValueError):
            raise BadRequestError('Invalid volume size type')

        if size < 1:
            raise BadRequestError('Volume size should be at least 1 GB')

        try:
            name = volume_dict['name']
        except KeyError:
            raise BadRequestError('Volume name parameter is required')

        storage_account_type = volume_dict.get('storage_account_type',
                                               'StandardSSD_LRS')
        # https://docs.microsoft.com/en-us/rest/api/compute/virtual-machines/create-or-update#storageaccounttypes  # noqa
        if storage_account_type not in {'Premium_LRS',
                                        'Premium_ZRS',
                                        'StandardSSD_LRS',
                                        'Standard_LRS',
                                        'StandardSSD_ZRS',
                                        'UltraSSD_LRS'}:
            raise BadRequestError('Invalid storage account type for volume')

        caching_type = volume_dict.get('caching_type', 'None')
        if caching_type not in {'None',
                                'ReadOnly',
                                'ReadWrite',
                                }:
            raise BadRequestError('Invalid caching type')

        return {
            'name': name,
            'size': size,
            'storage_account_type': storage_account_type,
            'caching_type': caching_type,
        }

    def _generate_plan__parse_extra(self, extra, plan):
        from mist.api.clouds.models import CloudLocation

        location = CloudLocation.objects.get(
            id=plan['location']['id'], cloud=self.cloud)

        resource_group_name = extra.get('resource_group') or 'mist'
        if not re.match(r'^[-\w\._\(\)]+$', resource_group_name):
            raise BadRequestError('Invalid resource group name')

        resource_group_exists = self.connection.ex_resource_group_exists(
            resource_group_name)
        plan['resource_group'] = {
            'name': resource_group_name,
            'exists': resource_group_exists
        }

        storage_account_type = extra.get('storage_account_type',
                                         'StandardSSD_LRS')
        # https://docs.microsoft.com/en-us/rest/api/compute/virtual-machines/create-or-update#storageaccounttypes    # noqa
        if storage_account_type not in {'Premium_LRS',
                                        'Premium_ZRS',
                                        'StandardSSD_LRS',
                                        'StandardSSD_ZRS',
                                        'Standard_LRS'}:
            raise BadRequestError('Invalid storage account type for OS disk')
        plan['storage_account_type'] = storage_account_type

        plan['user'] = extra.get('user') or 'azureuser'
        if extra.get('password'):
            if validate_password(extra['password']) is False:
                raise BadRequestError(
                    'Password  must be between 8-123 characters long and '
                    'contain: an uppercase character, a lowercase character'
                    ' and a numeric digit')
            plan['password'] = extra['password']

    def _generate_plan__post_parse_plan(self, plan):
        from mist.api.images.models import CloudImage
        from mist.api.clouds.models import CloudLocation

        location = CloudLocation.objects.get(
            id=plan['location']['id'], cloud=self.cloud)
        image = CloudImage.objects.get(
            id=plan['image']['id'], cloud=self.cloud)

        if image.os_type == 'windows':
            plan.pop('key', None)
            if plan.get('password') is None:
                raise BadRequestError('Password is required on Windows images')

        if image.os_type == 'linux':
            # we don't use password in linux images
            # so don't return it in plan
            plan.pop('password', None)
            if plan.get('key') is None:
                raise BadRequestError('Key is required on Unix-like images')

        try:
            network_name = plan.pop('networks')
        except KeyError:
            if plan['resource_group']['name'] == 'mist':
                network_name = (f'mist-{location.external_id}')
            else:
                network_name = (f"mist-{plan['resource_group']['name']}"
                                f"-{location.external_id}")

        if plan['resource_group']['exists'] is True:
            try:
                network = self.connection.ex_get_network(
                    network_name,
                    plan['resource_group']['name'])
            except BaseHTTPError as exc:
                if exc.code == 404:
                    # network doesn't exist so we'll have to create it
                    network_exists = False
                else:
                    # TODO Consider what to raise on other status codes
                    raise BadRequestError(exc)
            else:
                # make sure network is in the same location
                if network.location != location.external_id:
                    raise BadRequestError(
                        'Network is in a different location'
                        ' from the one given')
                network_exists = True
        else:
            network_exists = False
        plan['networks'] = {
            'name': network_name,
            'exists': network_exists
        }

    def _create_machine__get_image_object(self, image):
        from mist.api.images.models import CloudImage
        from libcloud.compute.drivers.azure_arm import AzureImage
        cloud_image = CloudImage.objects.get(id=image)

        publisher, offer, sku, version = cloud_image.external_id.split(':')
        image_obj = AzureImage(version, sku, offer, publisher, None, None)
        return image_obj

    def _create_machine__compute_kwargs(self, plan):
        kwargs = super()._create_machine__compute_kwargs(plan)
        kwargs['ex_user_name'] = plan['user']
        kwargs['ex_use_managed_disks'] = True
        kwargs['ex_storage_account_type'] = plan['storage_account_type']
        kwargs['ex_customdata'] = plan.get('cloudinit', '')

        key = kwargs.pop('auth', None)
        if key:
            kwargs['auth'] = NodeAuthSSHKey(key.public)
        else:
            kwargs['auth'] = NodeAuthPassword(plan['password'])

        if plan['resource_group']['exists'] is False:
            try:
                self.connection.ex_create_resource_group(
                    plan['resource_group']['name'], kwargs['location'])
            except BaseHTTPError as exc:
                raise MachineCreationError(
                    'Could not create resource group: %s' % exc)
            # add delay because sometimes the resource group is not yet ready
            time.sleep(5)
        kwargs['ex_resource_group'] = plan['resource_group']['name']

        if plan['networks']['exists'] is False:
            try:
                security_group = self.connection.ex_create_network_security_group(  # noqa
                    plan['networks']['name'],
                    kwargs['ex_resource_group'],
                    location=kwargs['location'],
                    securityRules=config.AZURE_SECURITY_RULES
                )
            except BaseHTTPError as exc:
                raise MachineCreationError(
                    'Could not create security group: %s' % exc)

            # add delay because sometimes the security group is not yet ready
            time.sleep(3)

            try:
                network = self.connection.ex_create_network(
                    plan['networks']['name'],
                    kwargs['ex_resource_group'],
                    location=kwargs['location'],
                    networkSecurityGroup=security_group.id)
            except BaseHTTPError as exc:
                raise MachineCreationError(
                    'Could not create network: %s' % exc)
            time.sleep(3)
        else:
            try:
                network = self.connection.ex_get_network(
                    plan['networks']['name'],
                    kwargs['ex_resource_group'],
                )
            except BaseHTTPError as exc:
                raise MachineCreationError(
                    'Could not fetch network: %s' % exc)

        try:
            subnet = self.connection.ex_list_subnets(network)[0]
        except BaseHTTPError as exc:
            raise MachineCreationError(
                'Could not create network: %s' % exc)

        # avoid naming collisions when nic/ip with the same name exists
        temp_name = f"{kwargs['name']}-{secrets.token_hex(3)}"
        try:
            ip = self.connection.ex_create_public_ip(
                temp_name,
                kwargs['ex_resource_group'],
                kwargs['location'])
        except BaseHTTPError as exc:
            raise MachineCreationError('Could not create new ip: %s' % exc)

        try:
            nic = self.connection.ex_create_network_interface(
                temp_name,
                subnet,
                kwargs['ex_resource_group'],
                location=kwargs['location'],
                public_ip=ip)
        except Exception as exc:
            raise MachineCreationError(
                'Could not create network interface: %s' % exc)
        kwargs['ex_nic'] = nic

        data_disks = []
        for volume in plan.get('volumes', []):
            if volume.get('id'):
                from mist.api.volumes.models import Volume
                try:
                    mist_vol = Volume.objects.get(id=volume['id'])
                except me.DoesNotExist:
                    continue
                data_disks.append({'id': mist_vol.external_id})
            else:
                data_disks.append({
                    'name': volume['name'],
                    'size': volume['size'],
                    'storage_account_type': volume['storage_account_type'],
                    'host_caching': volume['caching_type'],
                })
        if data_disks:
            kwargs['ex_data_disks'] = data_disks
        return kwargs
