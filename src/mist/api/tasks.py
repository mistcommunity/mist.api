import uuid
import logging
import datetime
import secrets

import mongoengine as me

from time import time, sleep

import paramiko

from dramatiq.errors import Retry

from libcloud.compute.types import NodeState

from paramiko.ssh_exception import SSHException

from mist.api.exceptions import PolicyUnauthorizedError
from mist.api.exceptions import ServiceUnavailableError
from mist.api.exceptions import MachineNotFoundError
from mist.api.exceptions import MachineUnavailableError, MistError

from mist.api.shell import Shell

from mist.api.users.models import Owner, Organization
from mist.api.clouds.models import Cloud, CloudLocation, CloudSize
from mist.api.networks.models import Network
from mist.api.volumes.models import Volume
from mist.api.machines.models import Machine, KeyMachineAssociation
from mist.api.images.models import CloudImage
from mist.api.objectstorage.models import Bucket
from mist.api.scripts.models import Script
from mist.api.schedules.models import Schedule
from mist.api.dns.models import RECORDS
from mist.api.keys.models import Key
from mist.api.tag.methods import add_tags_to_resource

from mist.api.rules.models import NoDataRule

from mist.api.poller.models import PollingSchedule
from mist.api.poller.models import ListMachinesPollingSchedule
from mist.api.poller.models import ListNetworksPollingSchedule
from mist.api.poller.models import ListZonesPollingSchedule
from mist.api.poller.models import ListVolumesPollingSchedule
from mist.api.poller.models import ListClustersPollingSchedule
from mist.api.poller.models import ListLocationsPollingSchedule
from mist.api.poller.models import ListSizesPollingSchedule
from mist.api.poller.models import ListImagesPollingSchedule
from mist.api.poller.models import ListBucketsPollingSchedule

from mist.api.helpers import send_email as helper_send_email
from mist.api.helpers import trigger_session_update
from mist.api.helpers import docker_run, docker_connect, create_helm_command
from mist.api.auth.methods import AuthContext

from mist.api.logs.methods import log_event

from mist.api.dramatiq_app import dramatiq

from mist.api import config


logging.basicConfig(level=config.PY_LOG_LEVEL,
                    format=config.PY_LOG_FORMAT,
                    datefmt=config.PY_LOG_FORMAT_DATE)
log = logging.getLogger(__name__)

__all__ = [
    'ssh_command',
    'post_deploy_steps',
    'openstack_post_create_steps',
    'azure_post_create_steps',
    'rackspace_first_gen_post_create_steps',
    'create_machine_async',
    'send_email',
    'group_resources_actions',
    'run_resource_action',
    'group_run_script',
    'run_script',
    'update_poller',
    'gc_tasks_schedulers',
    'set_missing_since',
    'delete_periodic_tasks',
    'async_session_update'
]


@dramatiq.actor(queue_name='dramatiq_scripts')
def ssh_command(owner_id, cloud_id, machine_id, host, command,
                key_id=None, username=None, password=None, port=22):

    owner = Owner.objects.get(id=owner_id)
    shell = Shell(host)
    key_id, ssh_user = shell.autoconfigure(owner, cloud_id, machine_id,
                                           key_id, username, password, port)
    retval, output = shell.command(command)
    shell.disconnect()
    if retval:
        from mist.api.methods import notify_user
        notify_user(owner, "Async command failed for machine %s (%s)" %
                    (machine_id, host), output)


@dramatiq.actor(queue_name='dramatiq_provisioning')
def post_deploy_steps(auth_context_serialized, cloud_id, external_id,
                      monitoring, key_id=None, username=None, password=None,
                      port=22, script_id='', script_params='', job_id=None,
                      job=None, hostname='', plugins=None, script='',
                      post_script_id='', post_script_params='', schedule={},
                      location_id=None):
    # TODO: break into subtasks
    from mist.api.methods import probe_ssh_only
    from mist.api.methods import notify_user, notify_admin
    from mist.api.monitoring.methods import enable_monitoring
    auth_context = AuthContext.deserialize(auth_context_serialized)
    owner_id = auth_context.owner.id
    job_id = job_id or uuid.uuid4().hex
    owner = Owner.objects.get(id=owner_id)

    def tmp_log(msg, *args):
        log.error('Post deploy: %s' % msg, *args)
    tmp_log('Entering post deploy steps for %s %s %s',
            owner.id, cloud_id, external_id)

    try:
        cloud = Cloud.objects.get(owner=owner, id=cloud_id, deleted=None)
    except Exception as e:
        log.error('%r' % e)
        raise e

    try:
        machine = Machine.objects.get(cloud=cloud, external_id=external_id,
                                      state__ne='terminated')
    except Machine.DoesNotExist:
        raise Retry(delay=10_000)

    msg = "Cloud:\n  Name: %s\n  Id: %s\n" % (cloud.name, cloud_id)
    msg += "Machine:\n  Name: %s\n  Id: %s\n" % (machine.name, machine.id)
    tmp_log('Machine found, proceeding to post deploy steps\n%s' % msg)

    # filter out IPv6 addresses
    ips = [ip for ip in machine.public_ips + machine.private_ips
           if ':' not in ip]
    if not ips:
        tmp_log('no ip available')
        raise Retry(delay=30_000)
    host = ips[0]

    if machine.state != 'running':
        tmp_log('not running state')
        raise Retry(delay=30_000)

    log_dict = {
        'owner_id': owner.id,
        'event_type': 'job',
        'cloud': cloud_id,
        'machine': machine.id,
        'external_id': external_id,
        'job_id': job_id,
        'job': job,
        'host': host,
        'key_id': key_id,
    }

    if schedule and schedule.get('name'):  # ugly hack to prevent dupes
        try:
            name = (schedule.get('action') + '-' + schedule.pop('name') +
                    '-' + external_id[:4])

            auth_context = AuthContext.deserialize(
                schedule.pop('auth_context'))
            tmp_log('Add scheduler entry %s', name)
            schedule['selectors'] = [{
                'type': 'machines',
                'ids': [machine.id]
            }]
            schedule_info = Schedule.add(auth_context, name, **schedule)
            tmp_log("A new scheduler was added")
            log_event(action='Add scheduler entry',
                      scheduler=schedule_info.as_dict(), **log_dict)
        except Exception as e:
            print(repr(e))
            error = repr(e)
            notify_user(owner, "add scheduler entry failed for "
                               "machine %s" % external_id, repr(e),
                        error=error)
            log_event(action='Add scheduler entry failed',
                      error=error, **log_dict)
    if hostname:
        try:
            kwargs = {}
            kwargs['name'] = hostname
            kwargs['type'] = 'A'
            kwargs['data'] = host
            kwargs['ttl'] = 3600

            dns_cls = RECORDS[kwargs['type']]
            dns_cls.add(owner=owner, **kwargs)
            log_event(action='Create_A_record', hostname=hostname,
                      **log_dict)
        except Exception as exc:
            log_event(action='Create_A_record', hostname=hostname,
                      error=str(exc), **log_dict)

    try:
        cloud_post_deploy_steps = config.CLOUD_POST_DEPLOY.get(
            cloud_id, [])
    except AttributeError:
        cloud_post_deploy_steps = []

    try:
        from mist.api.shell import Shell
        shell = Shell(host)
        for post_deploy_step in cloud_post_deploy_steps:
            predeployed_key_id = post_deploy_step.get('key')
            if predeployed_key_id and key_id:
                # Use predeployed key to deploy the user selected key
                shell.autoconfigure(
                    owner, cloud_id, machine.id, predeployed_key_id,
                    username, password, port
                )
                retval, output = shell.command(
                    'echo %s >> ~/.ssh/authorized_keys' % Key.objects.get(
                        id=key_id).public)
                if retval > 0:
                    notify_admin('Deploy user key failed for machine %s'
                                 % machine.name)
            command = post_deploy_step.get('script', '').replace(
                '${machine.name}', machine.name)
            if command and key_id:
                tmp_log('Executing cloud post deploy cmd: %s' % command)
                shell.autoconfigure(
                    owner, cloud_id, machine.id, key_id, username,
                    password, port
                )
                retval, output = shell.command(command)
                if retval > 0:
                    notify_admin('Cloud post deploy command `%s` failed '
                                 'for machine %s' % (
                                     command, machine.name))

        if key_id:
            # connect with ssh even if no command, to create association
            # to be able to enable monitoring
            tmp_log('attempting to connect to shell')
            key_id, ssh_user = shell.autoconfigure(
                owner, cloud_id, machine.id, key_id, username, password,
                port
            )
            tmp_log('connected to shell')
            result = probe_ssh_only(owner, cloud_id, machine.id, host=None,
                                    key_id=key_id, ssh_user=ssh_user,
                                    shell=shell)
            log_dict = {
                'owner_id': owner.id,
                'event_type': 'job',
                'cloud': cloud_id,
                'machine': machine.id,
                'external_id': external_id,
                'job_id': job_id,
                'job': job,
                'host': host,
                'key': key_id,
                'ssh_user': ssh_user,
            }
            log_event(action='probe', result=result, **log_dict)

        error = False
        if script_id:
            tmp_log('will run script_id %s', script_id)
            ret = run_script(
                auth_context.serialize(), script_id, machine.id,
                params=script_params, host=host, job_id=job_id
            )
            error = ret['error']
            tmp_log('executed script_id %s', script_id)
        elif script:
            tmp_log('will run script')
            log_event(action='deployment_script_started', command=script,
                      **log_dict)
            start_time = time()
            retval, output = shell.command(script)
            tmp_log('executed script %s', script)
            execution_time = time() - start_time
            title = "Deployment script %s" % ('failed' if retval
                                              else 'succeeded')
            error = retval > 0
            notify_user(owner, title,
                        cloud_id=cloud_id,
                        external_id=external_id,
                        machine_name=machine.name,
                        command=script,
                        output=output,
                        duration=execution_time,
                        retval=retval,
                        error=retval > 0)
            log_event(action='deployment_script_finished',
                      error=retval > 0,
                      return_value=retval,
                      command=script,
                      stdout=output,
                      **log_dict)

        shell.disconnect()

        if monitoring:
            try:
                enable_monitoring(
                    owner, cloud_id, machine.id,
                    no_ssh=False, dry=False, job_id=job_id,
                    plugins=plugins, deploy_async=False,
                )
            except Exception as e:
                print(repr(e))
                error = True
                notify_user(
                    owner,
                    "Enable monitoring failed for machine %s" % external_id,
                    repr(e)
                )
                notify_admin('Enable monitoring on creation failed for '
                             'user %s machine %s: %r' % (
                                 str(owner), external_id, e))
                log_event(action='enable_monitoring_failed', error=repr(e),
                          **log_dict)

        if post_script_id:
            tmp_log('will run post_script_id %s', post_script_id)
            ret = run_script(
                auth_context.serialize(), post_script_id, machine.id,
                params=post_script_params, host=host, job_id=job_id,
                action_prefix='post_',
            )
            error = ret['error']
            tmp_log('executed post_script_id %s', post_script_id)

        log_event(action='post_deploy_finished', error=error, **log_dict)

    except (ServiceUnavailableError, SSHException) as exc:
        tmp_log(repr(exc))
        raise
    except Exception as exc:
        tmp_log(repr(exc))
        notify_admin("Deployment script failed for machine %s (%s) in cloud %s"
                     " (%s) by user %s" % (machine.name, external_id,
                                           cloud.name, cloud_id, str(owner)),
                     repr(exc))
        log_event(
            owner.id,
            event_type='job',
            action='post_deploy_finished',
            cloud_id=cloud_id,
            external_id=external_id,
            enable_monitoring=bool(monitoring),
            command=script,
            error="Couldn't connect to run post deploy steps.",
            job_id=job_id,
            job=job
        )


@dramatiq.actor(queue_name='dramatiq_provisioning')
def openstack_post_create_steps(auth_context_serialized, cloud_id, external_id,
                                monitoring, key_id, username, password,
                                public_key, script='',
                                script_id='', script_params='', job_id=None,
                                job=None, hostname='', plugins=None,
                                post_script_id='', post_script_params='',
                                networks=[], schedule={}):
    from mist.api.methods import connect_provider
    auth_context = AuthContext.deserialize(auth_context_serialized)

    try:
        cloud = Cloud.objects.get(
            owner=auth_context.owner, id=cloud_id, deleted=None)
        conn = connect_provider(cloud)
        nodes = conn.list_nodes()
        node = None

        for n in nodes:
            if n.id == external_id:
                node = n
                break

        if node and node.state == 0 and len(node.public_ips):
            post_deploy_steps.send(
                auth_context_serialized, cloud_id, external_id, monitoring,
                key_id, script=script, script_id=script_id,
                script_params=script_params, job_id=job_id, job=job,
                hostname=hostname, plugins=plugins,
                post_script_id=post_script_id,
                post_script_params=post_script_params, schedule=schedule,
            )
        else:
            try:
                conn = connect_provider(cloud)
                floating_ips = conn.ex_list_floating_ips()

                # From the already created floating ips try to find one
                # that is not associated to a node
                unassociated_floating_ip = None
                for ip in floating_ips:
                    if ip.status == "DOWN":
                        unassociated_floating_ip = ip
                        break

                # Find the ports which are associated to the machine
                # (e.g. the ports of the private ips)
                # and use one to associate a floating ip
                ports = conn.ex_list_ports()
                machine_port_id = None
                for port in ports:
                    if port.extra.get('device_id') == node.id:
                        machine_port_id = port.id
                        break

                if unassociated_floating_ip:
                    log.info("Associating floating "
                             "ip with machine: %s" % node.id)
                    conn.ex_associate_floating_ip_to_node(
                        unassociated_floating_ip.id, machine_port_id)
                else:
                    # Find the external network
                    log.info("Create and associating floating ip with "
                             "machine: %s" % node.id)
                    ext_net_id = networks['public'][0]['network_id']
                    conn.ex_create_floating_ip(ext_net_id, machine_port_id)

                post_deploy_steps.send(
                    auth_context_serialized, cloud_id, external_id, monitoring,
                    key_id, script=script,
                    script_id=script_id, script_params=script_params,
                    job_id=job_id, job=job, hostname=hostname, plugins=plugins,
                    post_script_id=post_script_id,
                    post_script_params=post_script_params,
                )

            except:
                raise
    except Exception as exc:
        if str(exc).startswith('Retry'):
            raise


@dramatiq.actor(queue_name='dramatiq_provisioning')
def azure_post_create_steps(auth_context_serialized, cloud_id, external_id,
                            monitoring, key_id, username, password,
                            public_key, script='',
                            script_id='', script_params='', job_id=None,
                            job=None, hostname='', plugins=None,
                            post_script_id='', post_script_params='',
                            schedule={}):
    from mist.api.methods import connect_provider
    auth_context = AuthContext.deserialize(auth_context_serialized)
    try:
        # find the node we're looking for and get its hostname
        cloud = Cloud.objects.get(
            owner=auth_context.owner, id=cloud_id, deleted=None)
        conn = connect_provider(cloud)
        nodes = conn.list_nodes()
        node = None
        for n in nodes:
            if n.id == external_id:
                node = n
                break
        if node and node.state == NodeState.RUNNING and len(node.public_ips):
            # filter out IPv6 addresses
            ips = [ip for ip in node.public_ips if ':' not in ip]
            host = ips[0]
        else:
            raise

        try:
            # login with user, password. Deploy the public key, enable sudo
            # access for username, disable password authentication
            # and reload ssh.
            # After this is done, call post_deploy_steps if deploy script
            # or monitoring is provided
            ssh = paramiko.SSHClient()
            ssh.load_system_host_keys()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(host, username=username, password=password,
                        timeout=None, allow_agent=False, look_for_keys=False)

            ssh.exec_command('mkdir -p ~/.ssh && '
                             'echo "%s" >> ~/.ssh/authorized_keys && '
                             'chmod -R 700 ~/.ssh/' % public_key)

            chan = ssh.get_transport().open_session()
            chan.get_pty()
            chan.exec_command(
                'sudo su -c \'echo "%s ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers\' ' %  # noqa
                username)
            chan.send('%s\n' % password)

            check_sudo_command = 'sudo su -c \'whoami\''

            chan = ssh.get_transport().open_session()
            chan.get_pty()
            chan.exec_command(check_sudo_command)
            output = chan.recv(1024)

            if not output.startswith('root'):
                raise
            cmd = 'sudo su -c \'sed -i "s|[#]*PasswordAuthentication yes|PasswordAuthentication no|g" /etc/ssh/sshd_config &&  /etc/init.d/ssh reload; service ssh reload\' '  # noqa
            ssh.exec_command(cmd)

            ssh.close()

            post_deploy_steps.send(
                auth_context_serialized, cloud_id, external_id, monitoring,
                key_id, script=script,
                script_id=script_id, script_params=script_params,
                job_id=job_id, job=job, hostname=hostname, plugins=plugins,
                post_script_id=post_script_id,
                post_script_params=post_script_params, schedule=schedule,
            )

        except Exception as exc:
            raise
    except Exception as exc:
        if str(exc).startswith('Retry'):
            raise


@dramatiq.actor(queue_name='dramatiq_provisioning')
def rackspace_first_gen_post_create_steps(
        auth_context_serialized, cloud_id, external_id, monitoring, key_id,
        password, public_key, username='root', script='', script_id='',
        script_params='', job_id=None, job=None, hostname='', plugins=None,
        post_script_id='', post_script_params='', schedule={}):
    from mist.api.methods import connect_provider
    auth_context = AuthContext.deserialize(auth_context_serialized)
    try:
        # find the node we're looking for and get its hostname
        cloud = Cloud.objects.get(
            owner=auth_context.owner, id=cloud_id, deleted=None)
        conn = connect_provider(cloud)
        nodes = conn.list_nodes()
        node = None
        for n in nodes:
            if n.id == external_id:
                node = n
                break

        if node and node.state == 0 and len(node.public_ips):
            # filter out IPv6 addresses
            ips = [ip for ip in node.public_ips if ':' not in ip]
            host = ips[0]
        else:
            raise

        try:
            # login with user, password and deploy the ssh public key.
            # Disable password authentication and reload ssh.
            # After this is done, call post_deploy_steps
            # if deploy script or monitoring
            # is provided
            ssh = paramiko.SSHClient()
            ssh.load_system_host_keys()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(host, username=username, password=password,
                        timeout=None, allow_agent=False, look_for_keys=False)

            ssh.exec_command('mkdir -p ~/.ssh && '
                             'echo "%s" >> ~/.ssh/authorized_keys && '
                             'chmod -R 700 ~/.ssh/' % public_key)

            cmd = 'sudo su -c \'sed -i "s|[#]*PasswordAuthentication yes|PasswordAuthentication no|g" /etc/ssh/sshd_config &&  /etc/init.d/ssh reload; service ssh reload\' '  # noqa
            ssh.exec_command(cmd)

            ssh.close()

            post_deploy_steps.send(
                auth_context_serialized, cloud_id, external_id, monitoring,
                key_id, script=script,
                script_id=script_id, script_params=script_params,
                job_id=job_id, job=job, hostname=hostname, plugins=plugins,
                post_script_id=post_script_id,
                post_script_params=post_script_params, schedule=schedule,
            )

        except Exception as exc:
            raise
    except Exception as exc:
        raise


@dramatiq.actor(queue_name='dramatiq_provisioning')
def clone_machine_async(auth_context_serialized, machine_id, name,
                        job=None, job_id=None):
    from mist.api.exceptions import MachineCreationError
    machine = Machine.objects.get(id=machine_id)
    auth_context = AuthContext.deserialize(auth_context_serialized)
    job_id = job_id or uuid.uuid4().hex
    msg = f"clone job starting for {machine_id} with name {machine.name}"
    log.warn(msg)
    log_event(auth_context.owner.id, 'job', 'clone_machine_started',
              user_id=auth_context.user.id, job_id=job_id, job=job,
              cloud_id=machine.cloud.id, machine_name=machine.name)
    error = False
    node = {}
    try:
        node = getattr(machine.ctl, 'clone')(name)
    except MachineCreationError as err:
        error = str(err)
    except Exception as exc:
        error = repr(exc)
    finally:
        log_event(
            auth_context.owner.id, 'job', 'clone_machine_finished',
            job=job, job_id=job_id, cloud_id=machine.cloud.id,
            machine_name=name, error=error,
            id=node.get('id', ''),
            user_id=auth_context.user.id
        )
    for i in range(0, 10):
        try:
            cloned_machine = Machine.objects.get(cloud=machine.cloud,
                                                 external_id=node.get('id',
                                                                      ''))
            break
        except me.DoesNotExist:
            if i < 6:
                sleep(i * 10)
                continue
    try:
        before = cloned_machine.as_dict()
        cloned_machine.assign_to(auth_context.user)
        for key_assoc in [
                ka for ka in KeyMachineAssociation.objects(machine=machine)]:
            try:
                auth_context.check_perm('key', 'read', key_assoc.key.id)
                cloned_machine.ctl.associate_key(key=key_assoc.key,
                                                 username=key_assoc.ssh_user,
                                                 port=key_assoc.port,
                                                 no_connect=True)
            except PolicyUnauthorizedError:
                continue

        tags, constraints = auth_context.check_perm('machine', 'create',
                                                    None)
        expiration = constraints.get('expiration')
        if expiration:
            try:
                from mist.rbac.methods import apply_expiration_constraint
                apply_expiration_constraint(auth_context, cloned_machine,
                                            expiration)
            except ImportError:
                pass

        cloned_machine.save()
        cloned_machine.cloud.ctl.compute.produce_and_publish_patch(
            [before], [cloned_machine])

        if tags:
            add_tags_to_resource(auth_context.owner,
                                 [{'resource_type': 'machine',
                                   'resource_id': cloned_machine.id}],
                                 tags)
    except NameError as exc:
        print(exc)
        log.error("Cloned machine is not present in the database yet."
                  "Post clone processes failed.")
    print('clone_machine_async: results: {}'.format(node))


@dramatiq.actor(queue_name='dramatiq_provisioning')
def create_machine_async(
    auth_context_serialized, cloud_id, key_id, machine_name, location_id,
    image_id, size, image_extra, disk,
    image_name, size_name, location_name, ips, monitoring,
    storage_account, machine_password, resource_group, storage_account_type,
    networks, subnetwork, docker_env, docker_command, script='',
    script_id='', script_params='',
    post_script_id='', post_script_params='',
    quantity=1, persist=False, job_id=None, job=None,
    docker_port_bindings={}, docker_exposed_ports={},
    azure_port_bindings='', hostname='', plugins=None,
    disk_size=None, disk_path=None, cloud_init='', subnet_id='',
    associate_floating_ip=False,
    associate_floating_ip_subnet=None, project_id=None,
    tags=None, schedule={}, bare_metal=False, hourly=True,
    softlayer_backend_vlan_id=None, machine_username='',
    folder=None, datastore=None,
    ephemeral=False, lxd_image_source=None,
    volumes=[], ip_addresses=[], expiration={}, sec_groups=None, vnfs=[],
    description='', port_forwards={}
):
    from concurrent.futures import ThreadPoolExecutor
    from mist.api.machines.methods import create_machine
    from mist.api.exceptions import MachineCreationError
    log.warn('MULTICREATE ASYNC %d' % quantity)

    # Re-construct AuthContext.
    auth_context = AuthContext.deserialize(auth_context_serialized)

    job_id = job_id or uuid.uuid4().hex

    names = []
    if quantity == 1:
        names = [machine_name]
    else:
        names = []
        for i in range(1, quantity + 1):
            names.append('%s-%d' % (machine_name, i))

    log_event(auth_context.owner.id, 'job', 'async_machine_creation_started',
              user_id=auth_context.user.id, job_id=job_id, job=job,
              cloud_id=cloud_id, script=script, script_id=script_id,
              script_params=script_params, monitoring=monitoring,
              persist=persist, quantity=quantity, key_id=key_id,
              machine_names=names, volumes=volumes)

    specs = []
    for name in names:
        specs.append((
            (auth_context, cloud_id, key_id, name, location_id, image_id,
             size, image_extra, disk, image_name, size_name,
             location_name, ips, monitoring, storage_account,
             machine_password, resource_group, storage_account_type, networks,
             subnetwork, docker_env, docker_command, 22, script, script_id,
             script_params, job_id, job),
            {'hostname': hostname, 'plugins': plugins,
             'post_script_id': post_script_id,
             'post_script_params': post_script_params,
             'azure_port_bindings': azure_port_bindings,
             'associate_floating_ip': associate_floating_ip,
             'subnet_id': subnet_id,
             'cloud_init': cloud_init,
             'disk_size': disk_size,
             'disk_path': disk_path,
             'project_id': project_id,
             'tags': tags,
             'schedule': schedule,
             'softlayer_backend_vlan_id': softlayer_backend_vlan_id,
             'bare_metal': bare_metal,
             'hourly': hourly,
             'machine_username': machine_username,
             'volumes': volumes,
             'ip_addresses': ip_addresses,
             'subnet_id': subnet_id,
             'expiration': expiration,
             'ephemeral': ephemeral,
             'lxd_image_source': lxd_image_source,
             'sec_groups': sec_groups,
             'folder': folder,
             'datastore': datastore,
             'vnfs': vnfs,
             'description': description,
             'port_forwards': port_forwards,
             }
        ))

    def create_machine_wrapper(args_kwargs):
        args, kwargs = args_kwargs
        error = False
        node = {}
        try:
            node = create_machine(*args, **kwargs)
        except MachineCreationError as exc:
            error = str(exc)
        except Exception as exc:
            error = repr(exc)
        finally:
            name = args[3]
            log_event(
                auth_context.owner.id, 'job', 'machine_creation_finished',
                job=job, job_id=job_id, cloud_id=cloud_id, machine_name=name,
                error=error, external_id=node.get('id', ''),
                user_id=auth_context.user.id
            )
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = executor.map(create_machine_wrapper, specs)
    print('create_machine_async: unprocessed results {}'.format(results))
    print('create_machine_async: waiting for real results')
    real_results = list(results)
    print('create_machine_async: results: {}'.format(real_results))


@dramatiq.actor(max_retries=3)
def send_email(subject, body, recipients, sender=None, bcc=None,
               html_body=None):
    if not helper_send_email(subject, body, recipients,
                             sender=sender, bcc=bcc, attempts=1,
                             html_body=html_body):
        raise
    return True


@dramatiq.actor(queue_name='dramatiq_schedules')
def group_resources_actions(owner_id, action, name, resources_ids):
    """
    Pass resource information to run_resource_action, like a group

    :param owner_id:
    :param action:
    :param name:
    :param resources_ids:
    :return: log_dict
    """

    schedule = Schedule.objects.get(owner=owner_id, name=name, deleted=None)
    resource_type = schedule.resource_model_name
    resource_cls = schedule.selector_resource_cls
    resources_match_key = f'{resource_type}s_match'
    resource_action_key = f'{resource_type}_action'
    log_dict = {
        'schedule_id': schedule.id,
        'schedule_name': schedule.name,
        'description': schedule.description or '',
        'schedule_type': str(schedule.when.type or ''),
        'owner_id': owner_id,
        resources_match_key: schedule.get_ids(),
        resource_action_key: action,
        'expires': str(schedule.expires or ''),
        'task_enabled': schedule.task_enabled,
        'run_immediately': schedule.run_immediately,
        'event_type': 'job',
        'error': False,
    }
    log_event(action='schedule_started', **log_dict)
    log.info('Schedule action started: %s', log_dict)
    tasks = []
    for rid in resources_ids:
        found = False
        _action = action
        try:
            resource = resource_cls.objects.get(id=rid)
            found = True
        except me.DoesNotExist:
            log_dict['error'] = \
                f'{resource_type.capitalize()} with id {rid} does not exist.'

        if found:
            if resource_type == 'machine' and \
                    action in ['destroy'] and \
                    config.SAFE_EXPIRATION and \
                    resource.expiration == schedule and \
                    resource.state != 'stopped':
                from mist.api.machines.methods import machine_safe_expire
                machine_safe_expire(owner_id, resource)
                # change action to be executed now
                _action = 'stop'

            try:
                task = run_resource_action.message(
                    owner_id, _action, name, rid)
                tasks.append(task)
            except Exception as exc:
                log_dict['error'] = '%s %r\n' % (log_dict.get('error', ''),
                                                 exc)
    # Apply all tasks in parallel
    from dramatiq import group
    g = group(tasks).run()
    g.wait(timeout=3600_000)
    log_dict.update({
        'last_run_at': str(schedule.last_run_at or ''),
        'total_run_count': schedule.total_run_count or 0,
        'error': log_dict['error']
    })
    log_event(action='schedule_finished', **log_dict)
    if log_dict['error']:
        log.info('Schedule action failed: %s', log_dict)
    else:
        log.info('Schedule action succeeded: %s', log_dict)

    schedule.total_run_count += 1
    schedule.save()

    owner = Owner.objects.get(id=owner_id)
    trigger_session_update(owner, ['schedules'])
    return log_dict


@dramatiq.actor(queue_name='dramatiq_schedules',
                time_limit=3_600_000)
def run_resource_action(owner_id, action, name, resource_id):
    """
    Calls specific action for a resource and log the info

    :param owner_id:
    :param action:
    :param name:
    :param cloud_id:
    :param resource_id:
    :return:
    """

    schedule = Schedule.objects.get(owner=owner_id, name=name, deleted=None)
    resource_type = schedule.resource_model_name
    resource_cls = schedule.selector_resource_cls
    resource_id_key = f'{resource_type}_id'
    log_dict = {
        'owner_id': owner_id,
        'event_type': 'job',
        resource_id_key: resource_id,
        'schedule_id': schedule.id,
    }

    external_id = ''
    cloud_id = ''
    owner = Owner.objects.get(id=owner_id)
    started_at = time()
    query = dict(id=resource_id)
    if resource_type == 'machine':
        query['state__ne'] = 'terminated'
    try:
        resource = resource_cls.objects.get(**query)
    except me.DoesNotExist:
        log_dict['error'] = "Resource with that id does not exist."
        msg = action + ' failed'
        log_event(action=msg, **log_dict)
    except Exception as exc:
        log_dict['error'] = str(exc)
        msg = action + ' failed'
        log_event(action=msg, **log_dict)

    if not log_dict.get('error'):
        if resource_type == 'machine':
            machine = resource
            log_dict['cloud_id'] = cloud_id = machine.cloud.id
            log_dict['external_id'] = external_id = machine.external_id
            if action in ('start', 'stop', 'reboot', 'destroy', 'notify'):
                # call list machines here cause we don't have another way
                # to update machine state if user isn't logged in
                from mist.api.machines.methods import list_machines
                from mist.api.machines.methods import destroy_machine
                # TODO change this to compute.ctl.list_machines
                list_machines(owner, cloud_id)

                if action == 'start':
                    log_event(action='Start', **log_dict)
                    try:
                        machine.ctl.start()
                    except Exception as exc:
                        log_dict['error'] = '%s Machine in %s state' % (
                            exc, machine.state)
                        log_event(action='Start failed', **log_dict)
                    else:
                        log_event(action='Start succeeded', **log_dict)
                elif action == 'stop':
                    log_event(action='Stop', **log_dict)
                    try:
                        machine.ctl.stop()
                    except Exception as exc:
                        log_dict['error'] = '%s Machine in %s state' % (
                            exc, machine.state)
                        log_event(action='Stop failed', **log_dict)
                    else:
                        log_event(action='Stop succeeded', **log_dict)
                elif action == 'reboot':
                    log_event(action='Reboot', **log_dict)
                    try:
                        machine.ctl.reboot()
                    except Exception as exc:
                        log_dict['error'] = '%s Machine in %s state' % (
                            exc, machine.state)
                        log_event(action='Reboot failed', **log_dict)
                    else:
                        log_event(action='Reboot succeeded', **log_dict)
                elif action == 'destroy':
                    log_event(action='Destroy', **log_dict)
                    try:
                        destroy_machine(owner, cloud_id, external_id)
                    except Exception as exc:
                        log_dict['error'] = '%s Machine in %s state' % (
                            exc, machine.state)
                        log_event(action='Destroy failed', **log_dict)
                    else:
                        log_event(action='Destroy succeeded', **log_dict)
                elif action == 'notify':
                    mails = []
                    for _user in [machine.owned_by, machine.created_by]:
                        if _user:
                            mails.append(_user.email)
                    for mail in list(set(mails)):
                        if mail == machine.owned_by.email:
                            user = machine.owned_by
                        else:
                            user = machine.created_by
                        subject = \
                            config.MACHINE_EXPIRE_NOTIFY_EMAIL_SUBJECT.format(
                                portal_name=config.PORTAL_NAME
                            )
                        if schedule.when.type == 'reminder' and \
                           schedule.when.message:
                            custom_msg = '\n%s\n' % \
                                schedule.when.message
                        else:
                            custom_msg = ''
                        machine_uri = config.PORTAL_URI + \
                            '/machines/%s' % machine.id
                        main_body = config.MACHINE_EXPIRE_NOTIFY_EMAIL_BODY
                        sch_entry = machine.expiration.when.entry
                        body = main_body.format(
                            fname=user.first_name,
                            machine_name=machine.name,
                            expiration=sch_entry,
                            uri=machine_uri + '/expiration',
                            custom_msg=custom_msg,
                            portal_name=config.PORTAL_NAME)
                        log.info('About to send email...')
                        if not helper_send_email(subject, body, user.email):
                            raise ServiceUnavailableError(
                                "Could not send notification email "
                                "about machine that is about to expire.")
        elif resource_type == 'cluster':
            cluster = resource
            log_dict.update({'cloud_id': cluster.cloud.id,
                             'external_id': cluster.external_id})
            if action == 'destroy':
                log_event(action='Destroy', **log_dict)
                try:
                    cluster.ctl.destroy()
                except Exception as exc:
                    log_dict['error'] = str(exc)
                    log_event(action='Destroy failed', **log_dict)
                else:
                    log_event(action='Destroy succeeded', **log_dict)
        elif resource_type == 'network':
            network = resource
            log_dict.update({'cloud_id': network.cloud.id,
                             'network_id': network.network_id})
            if action == 'delete':
                log_event(action='Delete', **log_dict)
                try:
                    network.ctl.delete()
                except Exception as exc:
                    log_dict['error'] = str(exc)
                    log_event(action='Delete failed', **log_dict)
                else:
                    log_event(action='Delete succeeded', **log_dict)
        elif resource_type == 'volume':
            volume = resource
            log_dict.update({'cloud_id': volume.cloud.id,
                             'external_id': volume.external_id})
            if action == 'delete':
                log_event(action='Delete', **log_dict)
                try:
                    volume.ctl.delete()
                except Exception as exc:
                    log_dict['error'] = str(exc)
                    log_event(action='Delete failed', **log_dict)
                else:
                    log_event(action='Delete succeeded', **log_dict)

    if action != 'notify' and log_dict.get('error'):
        # TODO markos asked this
        log_dict['started_at'] = started_at
        log_dict['finished_at'] = time()
        title = "Execution of '%s' action " % action
        title += "failed" if log_dict.get('error') else "succeeded"
        from mist.api.methods import notify_user
        notify_user(
            owner, title,
            cloud_id=cloud_id,
            external_id=external_id,
            duration=log_dict['finished_at'] - log_dict['started_at'],
            error=log_dict.get('error'),
        )


@dramatiq.actor(queue_name='dramatiq_schedules',
                time_limit=3_900_000,
                throws=(me.DoesNotExist,))
def group_run_script(auth_context_serialized, script_id, name, machine_ids,
                     params='', owner_id=None):
    """
    Accepts a list of lists in form  cloud_id,machine_id and pass them
    to run_resource_action like a group

    :param owner_id:
    :param script_id:
    :param name
    :param cloud_machines_pairs:
    :return:
    """

    if auth_context_serialized:
        try:
            auth_context = AuthContext.deserialize(auth_context_serialized)
        except TypeError:
            group_run_script.logger.error(
                'Invalid serialized AuthContext type, exiting')
            return
        owner = auth_context.owner
    else:
        owner = Organization.objects.get(id=owner_id)
        auth_context = None

    job_id = uuid.uuid4().hex
    schedule = Schedule.objects.get(owner=owner.id, name=name, deleted=None)

    log_dict = {
        'schedule_id': schedule.id,
        'schedule_name': schedule.name,
        'description': schedule.description or '',
        'schedule_type': str(schedule.when.type or ''),
        'owner_id': owner.id,
        'machines_match': schedule.get_ids(),
        'script_id': script_id,
        'expires': str(schedule.expires or ''),
        'task_enabled': schedule.task_enabled,
        'run_immediately': schedule.run_immediately,
        'event_type': 'job',
        'error': False,
        'job': 'schedule',
        'job_id': job_id,
    }

    log_event(action='schedule_started', **log_dict)
    log.info('Schedule started: %s', log_dict)
    tasks = []
    for machine_id in machine_ids:
        try:
            task = run_script.message(auth_context_serialized, script_id,
                                      machine_id, params=params,
                                      job_id=job_id, job='schedule',
                                      owner_id=owner.id)
            tasks.append(task)
        except Exception as exc:
            log_dict['error'] = "%s %r\n" % (log_dict.get('error', ''), exc)
    # Apply all tasks in parallel
    from dramatiq import group
    g = group(tasks).run()
    g.wait(timeout=3_600_000)
    log_dict.update({'last_run_at': str(schedule.last_run_at or ''),
                     'total_run_count': schedule.total_run_count or 0,
                     'error': log_dict['error']}
                    )
    log_event(action='schedule_finished', **log_dict)
    if log_dict['error']:
        log.info('Schedule run_script failed: %s', log_dict)
    else:
        log.info('Schedule run_script succeeded: %s', log_dict)

    schedule.total_run_count += 1
    schedule.save()

    # This seems wasteful and may contribute to UI performance issues
    trigger_session_update(owner, ['schedules'])
    return log_dict


@dramatiq.actor(queue_name='dramatiq_schedules',
                time_limit=3_600_000,
                max_retries=0,
                throws=(me.DoesNotExist,))
def run_script(auth_context_serialized, script_id, machine_id, params='',
               host='', key_id='', username='', password='', port=22,
               job_id='', job='', action_prefix='', su=False, env="",
               owner_id=None):
    from mist.api.methods import notify_admin, notify_user
    if auth_context_serialized:
        try:
            auth_context = AuthContext.deserialize(auth_context_serialized)
        except TypeError:
            run_script.logger.error(
                'Invalid serialized AuthContext type, exiting')
            return
        owner = auth_context.owner
    else:
        owner = Organization.objects.get(id=owner_id)
        auth_context = None
    # ssh_user should be removed in the future
    # as we are going to support all types of
    # machines: docker,lxd containers,k8s pods
    # etc...
    ret = {
        'owner_id': owner.id,
        'job_id': job_id or uuid.uuid4().hex,
        'job': job,
        'script': script_id,
        'machine': machine_id,
        'params': params,
        'env': env,
        'su': su,
        'host': host,
        'key_id': key_id,
        'ssh_user': username,
        'port': port,
        'command': '',
        'stdout': '',
        'exit_code': -255,
        'error': False,
    }
    machine_name = ''
    cloud_id = ''

    try:
        machine = Machine.objects.get(id=machine_id, state__ne='terminated')
        cloud_id = machine.cloud.id
        external_id = machine.external_id
        ret.update({'cloud': cloud_id, 'external_id': external_id})
        script = Script.objects.get(
            owner=owner, id=script_id, deleted=None)
        from mist.api.machines.methods import find_best_ssh_params
        from mist.api.machines.models import KeyMachineAssociation

        if not key_id:
            key_association_id, host, username, port = find_best_ssh_params(
                machine, auth_context=auth_context
            )
            key_id = KeyMachineAssociation.objects(
                id=key_association_id)[0].key.id

        if not host:
            raise MistError("No host provided and none could be discovered.")
        started_at = time()
        result = script.ctl.run(
            auth_context, machine, host=host, port=port, username=username,
            password=password, su=su, key_id=key_id, params=params,
            job_id=job_id, env=env, owner=owner, ret=ret,
            action_prefix=action_prefix
        )

        ret.update(result)
        log.info("Script result: %s" % result)
    except TypeError as exc:
        ret['error'] = str(exc)
        log.error("Script error: %s" % exc)
    if not ret['error']:
        if ret['exit_code'] > 0:
            ret['error'] = 'Script exited with code %s' % ret['exit_code']
    log_event(event_type='job', action=action_prefix + 'script_finished',
              **ret)
    if ret['error']:
        log.info('Script failed: %s', ret)
    else:
        log.info('Script succeeded: %s', ret)
    ret['started_at'] = started_at
    ret['finished_at'] = time()
    title = "Execution of '%s' script " % script.name
    title += "failed" if ret['error'] else "succeeded"
    if ret['error']:
        notify_user(
            owner,
            title,
            cloud_id=cloud_id,
            external_id=external_id,
            machine_name=machine_name,
            output=ret['stdout'],
            duration=ret['finished_at'] - ret['started_at'],
            retval=ret['exit_code'],
            error=ret['error'],
        )
    if ret['error']:
        title += " for user %s" % str(owner)
        notify_admin(
            title, "%s\n\n%s" % (ret['stdout'], ret['error']), team='dev'
        )
    return ret


@dramatiq.actor(queue_name='dramatiq_polling',
                max_age=90_000)
def update_poller(org_id):
    org = Organization.objects.get(id=org_id)
    update_threshold = datetime.datetime.now() - datetime.timedelta(
        seconds=90)
    if org.poller_updated and org.poller_updated > update_threshold:
        return  # Poller was recently updated
    log.info("Updating poller for %s", org)
    for cloud in Cloud.objects(owner=org, deleted=None, enabled=True):
        log.info("Updating poller for cloud %s", cloud)
        ListMachinesPollingSchedule.add(cloud=cloud, interval=10, ttl=120)
        ListLocationsPollingSchedule.add(cloud=cloud, interval=60 * 60 * 24,
                                         ttl=120)
        ListSizesPollingSchedule.add(cloud=cloud, interval=60 * 60 * 24,
                                     ttl=120)
        ListImagesPollingSchedule.add(cloud=cloud, interval=60 * 60 * 24,
                                      ttl=120)
        if hasattr(cloud.ctl, 'network'):
            ListNetworksPollingSchedule.add(cloud=cloud, interval=60, ttl=120)
        if hasattr(cloud.ctl, 'dns') and cloud.dns_enabled:
            ListZonesPollingSchedule.add(cloud=cloud, interval=60, ttl=120)
        if hasattr(cloud.ctl, 'storage'):
            ListVolumesPollingSchedule.add(cloud=cloud, interval=60, ttl=120)
        if hasattr(cloud.ctl, 'container') and cloud.container_enabled:
            ListClustersPollingSchedule.add(cloud=cloud, interval=60, ttl=120)
        if hasattr(cloud.ctl, 'objectstorage') and \
                cloud.object_storage_enabled:
            ListBucketsPollingSchedule.add(cloud=cloud, interval=60 * 60 * 24,
                                           ttl=120)

    org.poller_updated = datetime.datetime.now()
    org.save()


@dramatiq.actor
def gc_tasks_schedulers():
    """Delete disabled schedules.

    This takes care of:

    1. Removing disabled list_machines polling schedules.
    2. Removing ssh/ping probe schedules, whose machines are missing or
       corresponding clouds have been deleted.
    3. Removing inactive no-data rules. They are added idempotently the
       first time get_stats receives data for a newly monitored machine.

    Note that this task does not run GC on user-defined schedules.

    """
    for collection in (PollingSchedule, NoDataRule, ):
        for entry in collection.objects():
            try:
                if not entry.enabled:
                    log.warning('Removing %s', entry)
                    entry.delete()
            except me.DoesNotExist:
                entry.delete()
            except Exception as exc:
                log.error(exc)


@dramatiq.actor
def set_missing_since(cloud_id):
    for Model in (Machine, CloudLocation, CloudSize, CloudImage,
                  Network, Volume, Bucket):
        Model.objects(cloud=cloud_id, missing_since=None).update(
            missing_since=datetime.datetime.utcnow()
        )


@dramatiq.actor
def delete_periodic_tasks(cloud_id):
    from mist.api.concurrency.models import PeriodicTaskInfo
    for section in ['machines', 'volumes', 'networks', 'zones', 'buckets']:
        try:
            key = 'cloud:list_%s:%s' % (section, cloud_id)
            PeriodicTaskInfo.objects.get(key=key).delete()
            log.info('Deleted periodic task: %s' % key)
        except PeriodicTaskInfo.DoesNotExist:
            pass


@dramatiq.actor(queue_name='dramatiq_sessions')
def async_session_update(owner, sections=None):
    if sections is None:
        sections = [
            'org', 'user', 'keys', 'clouds', 'stacks',
            'scripts', 'schedules', 'templates', 'monitoring'
        ]
    trigger_session_update(owner, sections)


def tmp_log_error(msg, *args):
    log.error("Post deploy: %s" % msg, *args)


def tmp_log(msg, *args):
    log.info("Post deploy: %s" % msg, *args)


@dramatiq.actor(queue_name="dramatiq_provisioning",
                time_limit=2_400_000,
                max_retries=0)
def create_cluster_async(auth_context_serialized, cloud_id,
                         job_id=None, job=None, helm_charts=None,
                         waiters=None, **kwargs):
    auth_context = AuthContext.deserialize(auth_context_serialized)
    job_id = job_id or uuid.uuid4().hex
    log_event(auth_context.owner.id, 'job', 'cluster_creation_started',
              user_id=auth_context.user.id, job_id=job_id, job=job,
              **kwargs)
    try:
        cloud = Cloud.objects.get(id=cloud_id, owner=auth_context.owner)
    except me.DoesNotExist:
        log_event(auth_context.owner.id, 'job', 'cluster_creation_finished',
                  user_id=auth_context.user.id, job_id=job_id, job=job,
                  error=f'Cloud with id: {cloud_id} does not exist')
        raise

    try:
        cluster = cloud.ctl.container.create_cluster(auth_context, **kwargs)
    except Exception as exc:
        log_event(auth_context.owner.id, 'job', 'cluster_creation_finished',
                  user_id=auth_context.user.id, job_id=job_id, job=job,
                  cloud_id=cloud.id,
                  error=f'Failed to create cluster with {repr(exc)}',
                  **kwargs)
        raise
    else:
        log_event(auth_context.owner.id, 'job', 'cluster_creation_finished',
                  user_id=auth_context.user.id, job_id=job_id, job=job,
                  cloud_id=cloud.id, **kwargs)
        cluster_post_deploy_steps.send(auth_context_serialized,
                                       cluster.id,
                                       job_id,
                                       job,
                                       helm_charts,
                                       waiters)


@dramatiq.actor(queue_name="dramatiq_provisioning",
                max_retries=0)
def multicreate_async_v2(
    auth_context_serialized, plan, job_id=None, job=None
):
    job_id = job_id or uuid.uuid4().hex
    auth_context = AuthContext.deserialize(auth_context_serialized)
    log_event(auth_context.owner.id, 'job', 'async_machine_creation_started',
              user_id=auth_context.user.id, job_id=job_id, job=job,
              **plan)

    messages = []
    name = plan['machine_name']
    quantity = plan['quantity']

    if quantity == 1:
        messages.append(create_machine_async_v2.message(
            auth_context_serialized, plan, job_id, job))
    else:
        for _ in range(quantity):
            temp_plan = plan.copy()
            temp_plan['machine_name'] = name + '-' + secrets.token_hex(5)
            messages.append(create_machine_async_v2.message(
                auth_context_serialized, temp_plan, job_id, job))

    dramatiq.group(messages).run()


@dramatiq.actor(queue_name="dramatiq_provisioning",
                max_retries=0)
def create_machine_async_v2(
    auth_context_serialized, plan, job_id=None, job=None
):
    job_id = job_id or uuid.uuid4().hex
    auth_context = AuthContext.deserialize(auth_context_serialized)
    cloud = Cloud.objects.get(id=plan["cloud"]["id"])

    log_event(
        auth_context.owner.id, 'job', 'sending_create_machine_request',
        job=job, job_id=job_id, cloud_id=plan['cloud']['id'],
        machine_name=plan['machine_name'], user_id=auth_context.user.id,)

    try:
        node = cloud.ctl.compute.create_machine(plan)
    except Exception as exc:
        error = f"Machine creation failed with exception: {str(exc)}"
        tmp_log_error(error)
        log_event(
            auth_context.owner.id, 'job', 'machine_creation_finished',
            job=job, job_id=job_id, cloud_id=plan['cloud']['id'],
            machine_name=plan['machine_name'], user_id=auth_context.user.id,
            error=error
        )
        raise

    tmp_log('Overriding default polling interval')
    schedule = ListMachinesPollingSchedule.objects.get(
        cloud=plan['cloud']['id'])
    schedule.add_interval(10, ttl=600)
    schedule.save()

    for i in range(1, 11):
        try:
            machine = Machine.objects.get(cloud=cloud, external_id=node.id)
            break
        except me.DoesNotExist:
            sleep(i * 10)
    else:
        error = f"Machine with external_id: {node.id} was not found"
        tmp_log_error(error)
        log_event(
            auth_context.owner.id, 'job', 'machine_creation_finished',
            job=job, job_id=job_id, cloud_id=plan['cloud']['id'],
            machine_name=plan['machine_name'], external_id=node.id,
            user_id=auth_context.user.id, error=error
        )
        raise MachineNotFoundError

    machine.assign_to(auth_context.user)

    if plan.get('expiration'):
        try:
            add_expiration_for_machine(auth_context, plan['expiration'],
                                       machine)
        except Exception as exc:
            tmp_log_error('Got exception %s while adding expiration'
                          % str(exc))
    # Associate key.
    if plan.get('key'):
        try:
            key = Key.objects.get(id=plan['key']['id'])
            username = (plan['key'].get('user') or
                        plan.get('user') or
                        node.extra.get('username', ''))
            port = node.extra.get('ssh_port') or 22
            machine.ctl.associate_key(
                key, username=username, port=port, no_connect=True
            )
        except Exception as exc:
            tmp_log_error('Got exception %s in key association'
                          % str(exc))

    machine = Machine.objects.get(cloud=cloud, external_id=node.id)

    if plan.get('tags'):
        add_tags_to_resource(auth_context.owner,
                             [{'resource_type': 'machine',
                               'resource_id': machine.id}],
                             plan['tags'])

    # first_run is set to True because poller has already
    # logged an observation event for this machine
    # and we don't want to send it again.
    cloud.ctl.compute.produce_and_publish_patch({},
                                                [machine],
                                                first_run=True
                                                )

    log_event(
        auth_context.owner.id, 'job', 'machine_creation_finished',
        job=job, job_id=job_id, cloud_id=plan['cloud']['id'],
        machine_name=plan['machine_name'], external_id=node.id,
        user_id=auth_context.user.id
    )

    post_deploy_v2.send(auth_context_serialized, cloud.id, machine.id,
                        node.id, plan, job_id=job_id, job=job)


@dramatiq.actor(queue_name="dramatiq_provisioning",
                throws=(me.DoesNotExist, MachineUnavailableError))
def post_deploy_v2(auth_context_serialized, cloud_id, machine_id, external_id,
                   plan, job_id=None, job=None):

    auth_context = AuthContext.deserialize(auth_context_serialized)
    job_id = job_id or uuid.uuid4().hex

    tmp_log("Entering post deploy steps for %s %s %s",
            auth_context.owner.id, cloud_id, machine_id)

    try:
        cloud = Cloud.objects.get(owner=auth_context.owner, id=cloud_id,
                                  deleted=None)
    except Cloud.DoesNotExist:
        tmp_log_error("Cloud %s not found. Exiting", cloud_id)
        raise me.DoesNotExist from None

    try:
        machine = Machine.objects.get(cloud=cloud, external_id=external_id)
    except Machine.DoesNotExist:
        tmp_log_error("Machine %s not found.Exiting", machine_id)
        raise me.DoesNotExist from None

    msg = "Cloud:\n  Name: %s\n  Id: %s\n" % (cloud.name, cloud_id)
    msg += "Machine:\n  Name: %s\n  Id: %s\n" % (machine.name, machine.id)
    tmp_log("Machine found, proceeding to post deploy steps\n%s" % msg)

    if machine.state == 'terminated':
        tmp_log_error("Machine %s terminated. Exiting", machine_id)
        raise MachineUnavailableError
    elif machine.state != 'running':
        tmp_log_error("not running state")
        raise Retry(delay=60000)

    ips = [
        ip for ip in machine.public_ips + machine.private_ips if ":" not in ip
    ]
    try:
        host = ips[0]
    except IndexError:
        tmp_log_error("ip not found, retrying")
        raise Retry(delay=60000) from None

    log_dict = {
        "owner_id": auth_context.owner.id,
        "event_type": "job",
        "cloud_id": cloud_id,
        "machine_id": machine_id,
        "external_id": external_id,
        "job_id": job_id,
        "job": job,
        "host": host,
        "key_id": plan.get("key", {}).get("id"),
    }

    add_schedules(auth_context, machine, log_dict, plan.get("schedules"))

    add_dns_record(auth_context, host, log_dict, plan.get("fqdn"))

    ssh_tasks.send(auth_context_serialized, cloud_id,
                   plan.get("key", {}).get("id"), host, external_id,
                   machine.name, machine_id, plan.get('scripts'), log_dict,
                   monitoring=plan.get('monitoring', False), plugins=None,
                   job_id=job_id, username=None, password=None, port=22)


@dramatiq.actor(queue_name="dramatiq_provisioning")
def ssh_tasks(auth_context_serialized, cloud_id, key_id, host, external_id,
              machine_name, machine_id, scripts, log_dict, monitoring=False,
              plugins=None, job_id=None, username=None, password=None,
              port=22):
    from mist.api.methods import notify_user, notify_admin
    from mist.api.monitoring.methods import enable_monitoring
    auth_context = AuthContext.deserialize(auth_context_serialized)
    try:
        shell = Shell(host)
        cloud_post_deploy(auth_context, cloud_id, shell, key_id, external_id,
                          machine_name, username=username, password=password,
                          port=port)
        create_key_association(auth_context, shell, cloud_id, key_id,
                               machine_id, host, log_dict, username=username,
                               password=password, port=port)
        run_scripts(auth_context, shell, scripts, cloud_id, host, machine_id,
                    machine_name, log_dict, job_id)
        shell.disconnect()
    except (ServiceUnavailableError, SSHException) as exc:
        tmp_log_error(repr(exc))
        raise Retry(delay=60000)

    if monitoring:
        try:
            enable_monitoring(auth_context.owner, cloud_id, machine_id,
                              no_ssh=False, dry=False, job_id=job_id,
                              plugins=plugins, deploy_async=False)
        except Exception as e:
            print(repr(e))
            notify_user(
                auth_context.owner,
                "Enable monitoring failed for machine %s" % machine_id,
                repr(e)
            )
            notify_admin('Enable monitoring on creation failed for '
                         'user %s machine %s: %r'
                         % (str(auth_context.owner), machine_id, e))
            log_event(action='enable_monitoring_failed', error=repr(e),
                      **log_dict)
    log_event(action='post_deploy_finished', error=False, **log_dict)


@dramatiq.actor(max_retries=0)
def pull_docker_image(cloud_id, image_name):
    from mist.api.helpers import pull_docker_image
    try:
        pull_docker_image(cloud_id, image_name)
    except Exception:
        pull_docker_image.logger.exception(
            'Failed to pull image for cloud: %s', cloud_id)


@dramatiq.actor(queue_name="dramatiq_provisioning",
                time_limit=2_400_000,
                max_retries=0,
                throws=(me.DoesNotExist,))
def destroy_cluster_async(auth_context_serialized,
                          cluster_id,
                          job_id=None,
                          job=None):
    from mist.api.containers.models import Cluster
    job_id = job_id or uuid.uuid4().hex
    cluster = Cluster.objects.get(id=cluster_id)
    cloud = cluster.cloud
    try:
        auth_context = AuthContext.deserialize(auth_context_serialized)
    except TypeError:
        destroy_cluster_async.logger.error(
            'Invalid serialized AuthContext type, exiting')
        return
    log_event(auth_context.owner.id, 'job', 'cluster_deletion_started',
              user_id=auth_context.user.id, job_id=job_id, job=job,
              cloud_id=cloud.id, cluster=cluster.id)

    try:
        cluster.ctl.destroy()
    except Exception as exc:
        destroy_cluster_async.logger.error(
            'Failed to destroy cluster %s with exception %r',
            cluster.id, exc)
        log_event(auth_context.owner.id, 'job', 'cluster_deletion_finished',
                  user_id=auth_context.user.id, job_id=job_id, job=job,
                  cloud_id=cloud.id, cluster=cluster.id, error=repr(exc))
        return

    log_event(auth_context.owner.id, 'job', 'cluster_deletion_finished',
              user_id=auth_context.user.id, job_id=job_id, job=job,
              cloud_id=cloud.id, cluster=cluster.id)


def add_expiration_for_machine(auth_context, expiration, machine):
    if expiration.get('notify'):
        # convert notify value from datetime str to seconds
        notify = datetime.datetime.strptime(expiration['date'],
                                            '%Y-%m-%d %H:%M:%S') \
            - datetime.datetime.strptime(expiration['notify'],
                                         '%Y-%m-%d %H:%M:%S')
        expiration['notify'] = int(notify.total_seconds())
    params = {
        "schedule_type": "one_off",
        "description": "Scheduled to run when machine expires",
        "schedule_entry": expiration.get("date"),
        "action": expiration.get("action"),
        "selectors": [{"type": "machines", "ids": [machine.id]}],
        "task_enabled": True,
        "notify": expiration.get("notify", ""),
        "notify_msg": expiration.get("notify_msg", ""),
    }
    name = (f'{machine.name}-expiration-{machine.external_id[:4]}'
            f'-{secrets.token_hex(3)}')
    machine.expiration = Schedule.add(auth_context, name, **params)
    machine.save()


def wait_on_cluster_conditions(cluster, waiters):
    """Waits on conditions for the given Kubernetes cluster after its
    initialization and helm charts installation. Returns logging information.

    Parameters:
        cluster(Object): The cluster to wait on conditions.
        waiters(List(Dict)): List of conditions to wait on.

    Returns:
        result(List): List of logging info.
        error(string): Returns the error.
    """
    results = []
    start = datetime.datetime.now()
    while waiters:
        new_waiters = []
        for waiter in waiters:
            type = waiter.get("type")
            name = waiter.get("name")
            timeout = waiter.get("timeout", 1800)  # 30 minutes
            expiry = waiter.get("expiry")
            namespace = waiter.get("namespace", "default")
            if timeout:
                if not expiry:
                    waiter["expiry"] = start + \
                        datetime.timedelta(seconds=timeout)
                if datetime.datetime.now() > waiter["expiry"]:
                    waiters = []
                    waiter.pop('expiry')
                    return None, f"Waiter: {waiter} expired on cluster: {cluster.id}"  # noqa
            if type == "ingress":
                ingress = cluster.ctl.get_ingress(
                    name=name, namespace=namespace)
                ips = ingress.get("ips")
                hostnames = ingress.get("hostnames")
                if ips or hostnames:
                    waiter.update({"result": ingress})
                    waiter.pop("expiry", None)
                    results.append(waiter)
                else:
                    new_waiters.append(waiter)
        waiters = new_waiters
        sleep(5)
    return results, None


@dramatiq.actor(
    queue_name="dramatiq_provisioning",
    time_limit=7_200_000,  # 2 hours
)
def cluster_post_deploy_steps(
    auth_context_serialized,
    cluster_external_id,
    job_id,
    job,
    helm_charts,
    waiters
):
    """Wrapper task for Helm Chart installations that makes sure
    the cluster is running and the Kubernetes API is up before the
    Helm Chart installations.
    """
    try:
        auth_context = AuthContext.deserialize(auth_context_serialized)
    except TypeError:
        cluster_post_deploy_steps.logger.error(
            "Invalid serialized AuthContext type, exiting"
        )
        log_event(
            auth_context.owner.id,
            "job",
            action="cluster_post_deploy_finished",
            job_id=job_id,
            job=job,
            cluster_external_id=cluster_external_id,
            error="Failed to deserialize auth_context",
        )
    from mist.api.containers.models import Cluster
    try:
        cluster = Cluster.objects.get(
            external_id=cluster_external_id,
            owner=auth_context.owner,
            missing_since=None,
        )
    except me.DoesNotExist:
        message = "Poller has not yet found the cluster"
        cluster_post_deploy_steps.logger.info(message)
        raise Retry(message=message, delay=60_000) from None

    if cluster.state != "running":
        message = "Cluster is not in running state"
        cluster_post_deploy_steps.logger.info(message)
        raise Retry(message=message, delay=60_000)

    for helm_chart in helm_charts:
        try:
            helm_install(
                auth_context_serialized=auth_context_serialized,
                cluster_id=cluster.id,
                repo_url=helm_chart["repo_url"],
                chart_name=helm_chart["chart_name"],
                release_name=helm_chart["release_name"],
                namespace=helm_chart.get("namespace"),
                values=helm_chart.get("values"),
                version=helm_chart.get("version"),
                job_id=job_id,
            )
        except Exception as exc:
            cluster_post_deploy_steps.logger.error(
                "Failed to install helm chart %s on cluster: %s with exception %s",  # noqa
                helm_chart["chart_name"],
                cluster.id,
                repr(exc),
            )

    if waiters:
        results, error = wait_on_cluster_conditions(cluster, waiters)
        log_event(
            auth_context.owner.id,
            "job",
            action="cluster_waiters_finished",
            job_id=job_id,
            job=job,
            cluster=cluster.id,
            results=results,
            error=error
        )

    log_event(
        auth_context.owner.id,
        "job",
        action="cluster_post_deploy_finished",
        job_id=job_id,
        job=job,
        cluster=cluster.id,
    )


@dramatiq.actor(
    queue_name="dramatiq_provisioning",
    time_limit=3_600_000,  # 1 hour
    throws=(me.DoesNotExist,),
)
def helm_install(
    auth_context_serialized,
    cluster_id,
    repo_url,
    chart_name,
    release_name,
    namespace=None,
    values=None,
    timeout="10m",
    version=None,
    job_id=None,
    job=None,
):
    """Install a Helm chart on the given Kubernetes cluster.

    The equivalent commands with Helm CLI:
        - helm repo add <random_repo_name> `repo_url`
        - helm repo update
        - helm install `release_name` <random_repo_name>/`chart_name` ...

    Parameters:
        auth_context_serialized(Dict): The serialized AuthContext of the user
                                       that made the request.
        cluster_id(str): The cluster ID to install the chart on.
        repo_url(str): The chart repository that contains the chart that will
                       be installed.
        chart_name(str): The name of the chart that will be installed.
        release_name(str): The name that will be given to Helm release.
        namespace(str): The Kubernetes namespace to install the release.
        values(str): A string containing values in YAML. Equivalent to
                     `-f values.yaml` in Helm.
        timeout(str): The timeout of the Helm install command.
                      A Golang duration string is expected.
                      https://pkg.go.dev/time#ParseDuration
        version(str): A version or a version constraint for the chart.
        job_id(str): The job UUID
    """
    try:
        auth_context = AuthContext.deserialize(auth_context_serialized)
    except TypeError:
        helm_install.logger.error(
            "Invalid serialized AuthContext type, exiting"
        )
        return
    from mist.api.containers.models import Cluster
    job_id = job_id or uuid.uuid4().hex
    log_event(
        auth_context.owner.id,
        "job",
        "helm_installation_started",
        user_id=auth_context.user.id,
        job_id=job_id,
        job=job,
        cluster=cluster_id,
        repo_url=repo_url,
        chart=chart_name,
        release=release_name,
    )

    cluster = Cluster.objects.get(id=cluster_id)
    try:
        host = cluster.credentials["host"]
        port = cluster.credentials["port"]
        token = cluster.credentials["token"]
        ca_cert = cluster.credentials["ca_cert"]
    except KeyError as exc:
        helm_install.logger.error(
            "Failed to get credentials for cluster %s with exception %r",
            cluster.id,
            exc,
        )
        error = (
            f"Failed to get required cluster "
            f"credentials with exc: {repr(exc)}"
        )
        log_event(
            auth_context.owner.id,
            "job",
            "helm_installation_finished",
            user_id=auth_context.user.id,
            job_id=job_id,
            job=job,
            cluster=cluster_id,
            repo_url=repo_url,
            chart=chart_name,
            release=release_name,
            error=error,
        )
        return

    # Since we can't mount a local volume to the Docker API, we have to pass
    # the CA cert & values.yaml file with env variables
    env = [f"CA_CERT={ca_cert}"]
    ca_cert_path = f"{config.HELM_DOCKER_IMAGE_WORKDIR}/ca_cert"
    if values:
        values_file_path = f"{config.HELM_DOCKER_IMAGE_WORKDIR}/values.yaml"
        env.append(f"VALUES={values}")
    else:
        values_file_path = None

    command = create_helm_command(
        repo_url=repo_url,
        release_name=release_name,
        chart_name=chart_name,
        host=host,
        port=port,
        token=token,
        ca_cert_path=ca_cert_path,
        namespace=namespace,
        values_file_path=values_file_path,
        timeout=timeout,
        version=version,
    )

    # NOTE the double quotes around variables are necessary
    # to preserve newline chars
    if values:
        command = f'echo "$VALUES" > {values_file_path} && {command}'
    command = f'echo "$CA_CERT" > {ca_cert_path} && {command}'
    entrypoint = ["/bin/sh", "-c", command]
    exit_code = True
    container_logs = None
    try:
        container = docker_run(
            name=f"helm_runner-{job_id}",
            image_id=config.HELM_DOCKER_IMAGE,
            command="",
            entrypoint=entrypoint,
            env=env,
        )
        connection = docker_connect()
        # Sleep to make sure container has started
        sleep(3)
        container = connection.get_container(container.id)
        while container.state != "stopped":
            container = connection.get_container(container.id)
            sleep(3)
        exit_code = container.extra["state"]["ExitCode"]
        container_logs = connection.ex_get_logs(container)
        helm_install.logger.info("Container logs: %s", container_logs)
    except Exception as exc:
        helm_install.logger.error(
            "Failed to run Helm container with exception %r", exc
        )
    finally:
        try:
            connection.destroy_container(container)
        except Exception as exc:
            helm_install.logger.error(
                "Failed to destroy Helm container with exception %r", exc
            )
        if exit_code is True or exit_code != 0:
            error = True
        else:
            error = False
        log_event(
            auth_context.owner.id,
            "job",
            "helm_installation_finished",
            user_id=auth_context.user.id,
            job_id=job_id,
            job=job,
            cluster=cluster_id,
            repo_url=repo_url,
            chart=chart_name,
            release=release_name,
            error=error,
            helm_output=container_logs,
        )


def add_schedules(auth_context, machine, log_dict, schedules):
    from mist.api.methods import notify_user
    schedules = schedules or []
    for schedule in schedules:
        type_ = schedule.get('action') or 'script'
        try:
            name = (f'{machine.name}-{type_}-'
                    f'{machine.external_id[:4]}-{secrets.token_hex(3)}')
            tmp_log("Add scheduler entry %s", name)
            schedule["selectors"] = [{"type": "machines",
                                      "ids": [machine.id]}]
            schedule_info = Schedule.add(auth_context, name, **schedule)
            tmp_log("A new scheduler was added")
            log_event(
                action="add_schedule_entry",
                scheduler=schedule_info.as_dict(),
                **log_dict
            )
        except Exception as e:
            tmp_log_error("Exception occurred %s", repr(e))
            error = repr(e)
            notify_user(
                auth_context.owner,
                "Add scheduler entry failed for machine %s"
                % machine.external_id,
                repr(e),
                error=error,
            )
            log_event(
                action="add_schedule_entry", error=error,
                **log_dict
            )


def add_dns_record(auth_context, host, log_dict, fqdn):
    if fqdn:
        kwargs = {}
        try:
            kwargs["name"] = fqdn
            kwargs["type"] = "A"
            kwargs["data"] = host
            kwargs["ttl"] = 3600

            dns_cls = RECORDS[kwargs["type"]]
            dns_cls.add(owner=auth_context.owner, **kwargs)
            log_event(action="create_A_record", hostname=fqdn, **log_dict)
            tmp_log("Added A Record, fqdn: %s IP: %s", fqdn, host)
        except Exception as exc:
            log_event(action="create_A_record", hostname=fqdn,
                      error=str(exc), **log_dict)


def cloud_post_deploy(auth_context, cloud_id, shell, key_id, external_id,
                      machine_name, username=None, password=None, port=22):
    from mist.api.methods import notify_admin
    try:
        cloud_post_deploy_steps = config.CLOUD_POST_DEPLOY.get(
            cloud_id, [])
    except AttributeError:
        cloud_post_deploy_steps = []
    for post_deploy_step in cloud_post_deploy_steps:
        predeployed_key_id = post_deploy_step.get('key')
        if predeployed_key_id and key_id:
            # Use predeployed key to deploy the user selected key
            shell.autoconfigure(
                auth_context.owner, cloud_id, external_id,
                predeployed_key_id,
                username, password, port
            )
            retval, output = shell.command(
                'echo %s >> ~/.ssh/authorized_keys'
                % Key.objects.get(id=key_id).public)
            if retval > 0:
                notify_admin('Deploy user key failed for machine %s'
                             % machine_name)
        command = post_deploy_step.get('script', '').replace(
            '${node.name}', machine_name)
        if command and key_id:
            tmp_log('Executing cloud post deploy cmd: %s' % command)
            shell.autoconfigure(
                auth_context.owner, cloud_id, machine_name,
                key_id, username, password, port
            )
            retval, output = shell.command(command)
            if retval > 0:
                notify_admin('Cloud post deploy command `%s` failed '
                             'for machine %s' % (command, machine_name))


def create_key_association(auth_context, shell, cloud_id, key_id, machine_id,
                           host, log_dict, username=None, password=None,
                           port=22):
    from mist.api.methods import probe_ssh_only
    if key_id:
        # connect with ssh even if no command, to create association
        # to be able to enable monitoring
        tmp_log('attempting to connect to shell')
        key_id, ssh_user = shell.autoconfigure(
            auth_context.owner, cloud_id, machine_id, key_id, username,
            password, port
        )
        tmp_log('connected to shell')
        result = probe_ssh_only(auth_context.owner, cloud_id, machine_id,
                                host=None, key_id=key_id,
                                ssh_user=ssh_user, shell=shell)

        log_dict['ssh_user'] = ssh_user
        log_event(action='probe', result=result, **log_dict)


def run_scripts(auth_context, shell, scripts, cloud_id, host, machine_id,
                machine_name, log_dict, job_id):
    from mist.api.methods import notify_user
    scripts = scripts or []
    for script in scripts:
        if script.get('id'):
            tmp_log('will run script_id %s', script['id'])
            params = script.get('params', '')
            ret = run_script.send(
                auth_context.serialize(), script['id'], machine_id,
                params=params, host=host, job_id=job_id
            )
            tmp_log('executed script_id %s', script['id'])
        elif script.get('inline'):
            tmp_log('will run inline script')
            log_event(action='script_started', command=script,
                      **log_dict)
            start_time = time()
            retval, output = shell.command(script['inline'])
            tmp_log('executed script')
            execution_time = time() - start_time
            title = "Deployment script %s" % ('failed' if retval
                                              else 'succeeded')
            notify_user(auth_context.owner, title, cloud_id=cloud_id,
                        machine_id=machine_id, machine_name=machine_name,
                        command=script, output=output, duration=execution_time,
                        retval=retval, error=retval > 0)
            log_event(action='script_finished',
                      error=retval > 0, return_value=retval,
                      command=script, stdout=output,
                      **log_dict)
