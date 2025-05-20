import requests

from mist.api import config

from mist.api.machines.models import Machine


TRAEFIK_API_URL = "%s/api" % config.TRAEFIK_API


def _gen_machine_config(machine):
    """Generate traefik frontend config for machine with monitoring"""
    if not machine.monitoring.hasmonitoring:
        raise Exception("Machine.monitoring.hasmonitoring is False")

    # Generate router configuration
    router = {
        "name": machine.id,
        "rule": f"PathPrefix(`/{machine.monitoring.collectd_password}`)",
        "service": machine.id,
        "entryPoints": ["http"],
        "middlewares": [f"{machine.id}-strip-prefix"]
    }

    # Generate middleware for stripping prefix
    middleware = {
        "name": f"{machine.id}-strip-prefix",
        "stripPrefix": {
            "prefixes": [f"/{machine.monitoring.collectd_password}"]
        }
    }

    # Generate service configuration
    service = {
        "name": machine.id,
        "loadBalancer": {
            "servers": [
                {
                    "url": f"http://{config.GOCKY_HOST}:{config.GOCKY_PORT}"
                }
            ]
        },
        "headers": {
            "customRequestHeaders": {
                "X-Gocky-Tag-Resource-Id": machine.id,
                "X-Gocky-Tag-Org-Id": machine.cloud.owner.id,
                "X-Gocky-Tag-Cloud-Id": machine.cloud.id,
                "X-Gocky-Tag-Machine-Id": machine.id,
                "X-Gocky-Tag-Machine-External-Id": machine.external_id,
                "X-Gocky-Tag-Source-Type": machine.os_type,
            }
        }
    }

    return router, middleware, service


def _gen_config():
    """Generate traefik config from scratch for all machines"""
    routers = {}
    middlewares = {}
    services = {}

    for machine in Machine.objects(monitoring__hasmonitoring=True):
        router, middleware, service = _gen_machine_config(machine)
        routers[machine.id] = router
        middlewares[machine.id] = middleware
        services[machine.id] = service

    return {"routers": routers, "middlewares": middlewares, "services": services}


def _get_config():
    """Get current traefik config"""
    routers_resp = requests.get(f"{TRAEFIK_API_URL}/http/routers")
    middlewares_resp = requests.get(f"{TRAEFIK_API_URL}/http/middlewares")
    services_resp = requests.get(f"{TRAEFIK_API_URL}/http/services")

    if not all(resp.ok for resp in [routers_resp, middlewares_resp, services_resp]):
        raise Exception(
            "Bad traefik response: %s %s" % (
                routers_resp.status_code, routers_resp.text
            )
        )

    return {
        "routers": routers_resp.json(),
        "middlewares": middlewares_resp.json(),
        "services": services_resp.json()
    }


def _set_config(cfg):
    """Set traefik config"""
    # Delete existing configuration
    requests.delete(f"{TRAEFIK_API_URL}/http/routers")
    requests.delete(f"{TRAEFIK_API_URL}/http/middlewares")
    requests.delete(f"{TRAEFIK_API_URL}/http/services")

    # Add new configuration
    for router in cfg["routers"].values():
        resp = requests.put(f"{TRAEFIK_API_URL}/http/routers/{router['name']}", json=router)
        if not resp.ok:
            raise Exception(f"Failed to add router: {resp.status_code} {resp.text}")

    for middleware in cfg["middlewares"].values():
        resp = requests.put(f"{TRAEFIK_API_URL}/http/middlewares/{middleware['name']}", json=middleware)
        if not resp.ok:
            raise Exception(f"Failed to add middleware: {resp.status_code} {resp.text}")

    for service in cfg["services"].values():
        resp = requests.put(f"{TRAEFIK_API_URL}/http/services/{service['name']}", json=service)
        if not resp.ok:
            raise Exception(f"Failed to add service: {resp.status_code} {resp.text}")

    return _get_config()


def reset_config():
    """Reset traefik config by regenerating from scratch"""
    return _set_config(_gen_config())


def add_machine_to_config(machine):
    """Add frontend rule for machine monitoring"""
    cfg = _get_config()
    router, middleware, service = _gen_machine_config(machine)
    cfg["routers"][machine.id] = router
    cfg["middlewares"][machine.id] = middleware
    cfg["services"][machine.id] = service
    return _set_config(cfg)


def remove_machine_from_config(machine):
    """Remove frontend rule for machine monitoring"""
    cfg = _get_config()
    cfg["routers"].pop(machine.id, None)
    cfg["middlewares"].pop(machine.id, None)
    cfg["services"].pop(machine.id, None)
    return _set_config(cfg)
