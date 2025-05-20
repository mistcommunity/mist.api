"""Definition of Container mongoengine models"""

import uuid
import logging

import mongoengine as me

from mist.api.containers.controllers import ClusterController
from mist.api.containers.controllers import GoogleClusterController
from mist.api.tag.models import Tag
from mist.api.clouds.models import Cloud
from mist.api.ownership.mixins import OwnershipMixin
from mist.api.mongoengine_extras import MistDictField
from mist.api.common.models import Cost
from mist.api.tag.mixins import TagMixin
from mist.api import config as api_config

__all__ = [
    "Cluster",
    "GoogleCluster",
    "AmazonCluster",
]
# This is a map from provider name to provider class, eg:
# 'google': GoogleCluster
# It is autofilled by _populate_clusters which is run on the end of this file.
CLUSTERS = {}


log = logging.getLogger(__name__)


def _populate_clusters():
    """Populates CLUSTERS variable with mappings from providers to clusters"""
    for key, value in list(globals().items()):
        if not key.startswith('_') and key.endswith(
                'Cluster') and key != 'Cluster':
            if issubclass(value, Cluster) and value is not Cluster:
                CLUSTERS[value.provider] = value
                for provider_alias in api_config.PROVIDERS[value.provider][
                        'aliases']:
                    CLUSTERS[provider_alias] = value


class NodePool(me.EmbeddedDocument):
    name = me.StringField(required=True)
    node_count = me.IntField(required=True, min_value=0)
    min_nodes = me.IntField()
    max_nodes = me.IntField()
    state = me.StringField()
    sizes = me.ListField(me.StringField())
    locations = me.ListField(me.StringField())

    def __repr__(self):
        return "%s Nodepool: %s State: %s Nodes: %s" % (
            type(self), self.name, self.state, self.node_count)

    def as_dict(self):
        return {
            "name": self.name,
            "node_count": self.node_count,
            "min_nodes": self.min_nodes,
            "max_nodes": self.max_nodes,
            "state": self.state,
            "sizes": self.sizes,
            "locations": self.locations,
            "autoscaling": self.autoscaling,
        }

    @property
    def autoscaling(self):
        """Determine if the nodepool has autoscaling enabled
        """
        # Use OR instead of AND because the GKE API does not return
        # min_nodes when its value is 0.
        return (self.min_nodes is not None or
                self.max_nodes is not None)


class Cluster(OwnershipMixin, me.Document, TagMixin):
    """Abstract base class for every cluster mongoengine model

    This class defines the fields common to all clusters of all types. For each
    different cluster type, a subclass should be created adding any
    cluster-specific fields and methods.

    Documents of all Cluster subclasses will be stored on the same mongo
    collection.

    One can perform a query directly on Cluster to fetch all cluster types,
    like this:

        Cluster.objects(owner=owner).count()

    This will return an iterable of clusters for that owner. Each cluster will
    be an instance of its respective Cluster subclass, like GoogleCluster
    instances.

    Clusters of a specific type can be queried like this:

        GoogleCluster.objects(owner=owner).count()

    This will return an iterable of GoogleCluster instances.

    To create a new cluster, one should initialize a Cluster subclass like
    GoogleCluster. Initializing directly a Cluster instance won't have any
    credential fields or associated handler to work with.
    """

    id = me.StringField(primary_key=True, default=lambda: uuid.uuid4().hex)
    cloud = me.ReferenceField(Cloud, required=True,
                              reverse_delete_rule=me.CASCADE)
    owner = me.ReferenceField('Organization', required=True,
                              reverse_delete_rule=me.CASCADE)
    location = me.ReferenceField('CloudLocation', required=False,
                                 reverse_delete_rule=me.DENY)
    name = me.StringField(required=True)
    external_id = me.StringField(required=True)
    name = me.StringField()
    nodepools = me.EmbeddedDocumentListField(NodePool, default=list)
    total_nodes = me.IntField()
    total_cpus = me.IntField()
    total_memory = me.IntField()
    credentials = MistDictField()
    config = MistDictField()
    extra = MistDictField()
    state = "unknown"
    last_seen = me.DateTimeField()
    missing_since = me.DateTimeField()
    created = me.DateTimeField()
    cost = me.EmbeddedDocumentField(Cost, default=lambda: Cost())
    total_cost = me.EmbeddedDocumentField(Cost, default=lambda: Cost())
    first_seen = me.DateTimeField()
    include_pods = me.BooleanField(default=False)

    meta = {
        'strict': False,
        'allow_inheritance': True,
        'collection': 'clusters',
        'indexes': [
            'owner', 'last_seen', 'missing_since',
            'name', 'cloud', 'external_id',
            {
                'fields': [
                    'cloud',
                    'external_id'
                ],
                'sparse': False,
                'unique': True,
                'cls': False,
            }, {
                'fields': ['$tags'],
                'default_language': 'english',
                'sparse': True,
                'unique': False
            }
        ],
    }

    _private_fields = ()

    def __init__(self, *args, ctl=ClusterController, **kwargs):
        super(Cluster, self).__init__(*args, **kwargs)
        self.ctl = ctl(self)

    def clean(self):
        # Populate owner field based on self.cloud.owner
        self.owner = self.cloud.owner

    @property
    def provider(self):
        return self.cloud.provider

    def delete(self):
        super(Cluster, self).delete()
        Tag.objects(resource_id=self.id, resource_type='cluster').delete()
        try:
            self.owner.mapper.remove(self)
        except Exception as exc:
            log.error("Got error %r while removing cluster %s", exc, self.id)
        try:
            if self.owned_by:
                self.owned_by.get_ownership_mapper(self.owner).remove(self)
        except Exception as exc:
            log.error("Got error %r while removing cluster %s", exc, self.id)

    def as_dict(self):
        cdict = {
            'id': self.id,
            'name': self.name,
            'external_id': self.external_id,
            'owner': self.owner.id,
            'cloud': self.cloud.id,
            'provider': self.provider,
            'total_nodes': self.total_nodes,
            'total_cpus': self.total_cpus,
            'total_memory': self.total_memory,
            'location': self.location.id if self.location else '',
            'credentials': self.credentials,
            'config': self.config,
            'cost': self.cost.as_dict(),
            'total_cost': self.total_cost.as_dict(),
            'extra': self.extra,
            'state': self.state,
            'last_seen': str(self.last_seen),
            'missing_since': str(self.missing_since),
            'created': str(self.created),
            'tags': {
                tag.key: tag.value for tag in Tag.objects(
                    owner=self.owner,
                    resource_id=self.id,
                    resource_type='cluster').only('key', 'value')
            },
            'owned_by': self.owned_by.email if self.owned_by else '',
            'created_by': self.created_by.email if self.created_by else '',
            'nodepools': [nodepool.as_dict()
                          for nodepool in self.nodepools],
            'include_pods': self.include_pods,
        }
        return cdict

    def as_dict_v2(self, deref='auto', only=''):
        from mist.api.helpers import prepare_dereferenced_dict
        standard_fields = [
            'id',
            'name',
            'external_id',
            'provider',
            'total_nodes',
            'total_cpus',
            'total_memory',
            'location',
            'credentials',
            'config',
            'extra',
            'state',
            'last_seen',
            'missing_since',
            'created',
            'tags',
            'include_pods',
        ]
        deref_map = {
            'cloud': 'id',
            'owner': 'id',
            'location': 'id',
            'owned_by': 'email',
            'created_by': 'email'
        }
        ret = prepare_dereferenced_dict(standard_fields, deref_map, self,
                                        deref, only)
        if 'cost' in only or not only:
            ret['cost'] = self.cost.as_dict()

        if 'total_cost' in only or not only:
            ret['total_cost'] = self.total_cost.as_dict()

        if "nodepools" in only or not only:
            ret["nodepools"] = [nodepool.as_dict()
                                for nodepool in self.nodepools]
        if 'last_seen' in ret:
            ret['last_seen'] = str(ret['last_seen'])
        if 'missing_since' in ret:
            ret['missing_since'] = str(ret['missing_since'])
        if 'created' in ret:
            ret['created'] = str(ret['created'])

        if 'tags' in only or not only:
            ret['tags'] = {
                tag.key: tag.value
                for tag in Tag.objects(
                    owner=self.owner,
                    resource_id=self.id,
                    resource_type='cluster').only('key', 'value')
            }

        return ret

    def __str__(self):
        return '%s cluster %s (%s) of %s' % (type(self), self.name,
                                             self.id, self.owner)


class GoogleCluster(Cluster):
    provider = 'google'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, ctl=GoogleClusterController, **kwargs)


class AmazonCluster(Cluster):
    provider = 'amazon'


_populate_clusters()
