from stacker.context import Context
from stacker.variables import Variable
from stacker_blueprints.ec2 import (
    Instances,
    SecurityGroups,
)
from stacker.blueprints.testutil import BlueprintTestCase


class TestEC2Blueprint(BlueprintTestCase):
    def setUp(self):
        self.common_variables = [
            Variable(
                "Instances", {
                    "MyInstance": {
                        "ImageId": "ami-abc12345",
                        }
                }
            )
        ]

        self.ctx = Context({'namespace': 'test', 'environment': 'test'})

    def test_ec2_instances(self):
        blueprint = Instances("ec2_instances", self.ctx)
        blueprint.resolve_variables(self.common_variables)
        blueprint.create_template()
        self.assertRenderedBlueprint(blueprint)

    def test_ec2_instances_with_public_ip(self):
        blueprint = Instances("ec2_instances_with_public_ip", self.ctx)
        my_instance = self.common_variables[0]._value["MyInstance"]
        my_instance["NetworkInterfaces"] = [
            {
                "DeviceIndex": 1,
                "NetworkInterfaceId": "net-dafdafadf1",
            },
            {
                "DeviceIndex": 0,
                "NetworkInterfaceId": "net-dafdafadf0",
                "AssociatePublicIpAddress": True,
            }
        ]
        blueprint.resolve_variables(self.common_variables)
        blueprint.create_template()
        self.assertRenderedBlueprint(blueprint)

    def test_ec2_instances_with_interfaces_no_public_ip(self):
        blueprint = Instances(
            "ec2_instances_with_interfaces_no_public_ip",
            self.ctx
        )
        my_instance = self.common_variables[0]._value["MyInstance"]
        my_instance["NetworkInterfaces"] = [
            {
                "DeviceIndex": 1,
                "NetworkInterfaceId": "net-dafdafadf1",
            },
            {
                "DeviceIndex": 0,
                "NetworkInterfaceId": "net-dafdafadf0",
            }
        ]
        blueprint.resolve_variables(self.common_variables)
        blueprint.create_template()
        self.assertRenderedBlueprint(blueprint)


class TestSecurityGroupsBlueprint(BlueprintTestCase):
    def setUp(self):
        self.common_variables = [
            Variable(
                "SecurityGroups", {
                    "MySG1": {
                        "GroupDescription": "My first SecurityGroup",
                        }
                }
            )
        ]

        self.ctx = Context({'namespace': 'test', 'environment': 'test'})

    def test_ec2_security_groups(self):
        blueprint = SecurityGroups("ec2_security_groups", self.ctx)
        blueprint.resolve_variables(self.common_variables)
        blueprint.create_template()
        self.assertRenderedBlueprint(blueprint)
