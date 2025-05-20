import logging
import requests
import datetime

from mist.api.dramatiq_app import dramatiq

from mist.api import config
from mist.api.rules.models import Rule
from mist.api.machines.models import Machine
from mist.api.clouds.models import Cloud
from mist.api.monitoring.methods import get_stats
from mist.api.monitoring.methods import get_cores


log = logging.getLogger(__name__)

__all__ = [
    'find_machine_cores',
    'push_metering_info',
]


def _skip_metering(machine):
    # Prevents counting the vCPUs of docker containers and KVM guests.
    if machine.cloud.ctl.provider == 'docker':
        if machine.machine_type != 'container-host':
            return True
    if machine.cloud.ctl.provider == 'libvirt':
        if machine.extra.get('tags', {}).get('type') != 'hypervisor':
            return True
    return False


@dramatiq.actor
def find_machine_cores(machine_id):
    """Decide on the number of vCPUs for all machines"""

    def _get_cores_from_unix(machine):
        return machine.ssh_probe.cores if machine.ssh_probe else 0

    def _get_cores_from_tsdb(machine):
        if machine.monitoring.hasmonitoring:
            if machine.monitoring.method.endswith('graphite'):
                metric = 'cpu.*.idle'
            elif machine.monitoring.method.endswith('tsfdb'):
                metric = ('fetch(\"{id}.cpu.*\d.usage_idle\"' +
                          ', start=\"{start}\", stop=\"{stop}\"' +
                          ', step=\"{step}\")')
            elif machine.monitoring.method.endswith('victoriametrics'):
                data = get_cores(machine.owner.id,
                                 start="-60sec", uuids=[machine.id])
                if data.get(machine.id) and data[machine.id].get("datapoints"):
                    datapoints = data[machine.id]["datapoints"]
                    if datapoints:
                        return datapoints[0][0]
            else:
                metric = 'cpu.cpu=/cpu\d/.usage_idle'
            return len(get_stats(machine, start='-60sec', metrics=[metric]))
        return 0

    def _get_cores_from_machine_extra(machine):
        try:
            return int(machine.extra.get('cpus', 0))
        except ValueError:
            return 0

    def _get_cores_from_libcloud_size(machine):
        return machine.size.cpus if machine.size else 0

    try:
        machine = Machine.objects.get(id=machine_id)
        machine.cores = (
            _get_cores_from_unix(machine) or
            _get_cores_from_tsdb(machine) or
            _get_cores_from_machine_extra(machine) or
            _get_cores_from_libcloud_size(machine)
        )
        machine.save()
    except Exception as exc:
        log.error('Failed to get cores of machine %s: %r', machine.id, exc)


@dramatiq.actor
def push_metering_info(owner_id):
    """Collect and push new metering data to InfluxDB"""
    now = datetime.datetime.utcnow()
    metering = {}

    # Base InfluxDB URL and headers
    url = config.INFLUX['host']
    headers = {
        'Authorization': f'Token {config.INFLUX["token"]}',
        'Content-Type': 'application/json'
    }
    org = config.INFLUX['org']
    bucket = config.INFLUX['bucket']

    # CPUs
    for machine in Machine.objects(owner=owner_id, last_seen__gte=now.date(),
                                   cloud__in=Cloud.objects(enabled=True,
                                                           deleted=None,
                                                           owner=owner_id)):
        metering.setdefault(
            owner_id,
            dict.fromkeys(('cores', 'checks', 'datapoints'), 0)
        )
        try:
            if _skip_metering(machine):
                continue
            metering[owner_id]['cores'] += machine.cores or 0
        except Exception as exc:
            log.error('Failed upon cores metering of %s: %r', machine.id, exc)

    # Checks
    for rule in Rule.objects(org_id=owner_id):
        try:
            metering[rule.org]['checks'] += rule.total_check_count
        except Exception as exc:
            log.error('Failed upon checks metering of %s: %r', rule.id, exc)

    # Datapoints
    query = f'''
    from(bucket: "{bucket}")
        |> range(start: -30m)
        |> filter(fn: (r) => r["owner"] == "{owner_id}")
        |> group(columns: ["machine", "gockyId"])
        |> max()
        |> group()
        |> sum()
    '''
    try:
        result = requests.post(
            f'{url}/api/v2/query?org={org}',
            headers=headers,
            json={'query': query}
        ).json()
        if result and 'results' in result:
            for series in result['results']:
                if series.get('series'):
                    for value in series['series'][0].get('values', []):
                        metering[owner_id]['datapoints'] += value[-1]
    except Exception as exc:
        log.error('Failed upon datapoints metering: %r', exc)

    # Assemble points
    points = []
    for owner, counters in metering.items():
        for metric, value in counters.items():
            point = {
                'measurement': 'usage',
                'tags': {'owner': owner},
                'fields': {metric: value},
                'time': now.isoformat()
            }
            points.append(point)

    # Write metering data
    if points:
        try:
            write = requests.post(
                f'{url}/api/v2/write?org={org}&bucket={bucket}',
                headers=headers,
                data='\n'.join(str(p) for p in points)
            )
            if not write.ok:
                log.error('Failed to write metering data: %s', write.text)
        except Exception as exc:
            log.error('Failed to write metering data: %r', exc)
