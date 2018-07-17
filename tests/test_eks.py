from stacker.context import Context, Config
from stacker.variables import Variable
from stacker_blueprints.eks import (
    Cluster,
    Workers
)
from stacker.blueprints.testutil import BlueprintTestCase


class TestCluster(BlueprintTestCase):
    def setUp(self):
        self.common_variables = {
           "Name": "k8s",
           "SecurityGroupIds": "sg-abc1234",
           "SubnetIds": "net-123456,net-123457",
        }
        self.ctx = Context(config=Config({'namespace': 'test'}))

    def generate_variables(self, variable_dict=None):
        variable_dict = variable_dict or {}
        self.common_variables.update(variable_dict)
        return [Variable(k, v) for k, v in self.common_variables.items()]

    def test_eks_cluster(self):
        bp = Cluster("eks_cluster", self.ctx)
        bp.resolve_variables(self.generate_variables())
        bp.create_template()
        self.assertRenderedBlueprint(bp)


class TestWorkers(BlueprintTestCase):
    def setUp(self):
        self.common_variables = {
           "ClusterName": "test-k8s",
           "SecurityGroupId": "sg-def5678",
           "MinInstanceCount": 1,
           "MaxInstanceCount": 3,
           "Subnets": "net-123456,net-123457",
           "ImageId": "ami-73a6e20b",
           "InstanceType": "t2.small",
           "KeyName": "id_rsa_aws",
        }
        self.ctx = Context(config=Config({'namespace': 'test'}))

    def generate_variables(self, variable_dict=None):
        variable_dict = variable_dict or {}
        self.common_variables.update(variable_dict)
        return [Variable(k, v) for k, v in self.common_variables.items()]

    def test_eks_workers(self):
        bp = Workers("eks_workers", self.ctx)
        bp.resolve_variables(self.generate_variables())
        bp.create_template()
        self.assertRenderedBlueprint(bp)
