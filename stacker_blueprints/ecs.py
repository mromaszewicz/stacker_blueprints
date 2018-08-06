from awacs.helpers.trust import get_ecs_task_assumerole_policy

from troposphere import (
    ecs,
    iam,
)

from troposphere import (
    NoValue,
    Output,
    Region,
    Sub,
)

from stacker.blueprints.base import Blueprint
from stacker.blueprints.variables.types import TroposphereType

from .policies import ecs_task_execution_policy


class Cluster(Blueprint):
    def create_template(self):
        t = self.template

        cluster = t.add_resource(ecs.Cluster("Cluster"))

        t.add_output(Output("ClusterId", Value=cluster.Ref()))
        t.add_output(Output("ClusterArn", Value=cluster.GetAtt("Arn")))


class SimpleFargateService(Blueprint):
    VARIABLES = {
        "ServiceName": {
            "type": str,
            "description": "A simple name for the service.",
        },
        "Image": {
            "type": str,
            "description": "The docker image to use for the task.",
        },
        "Command": {
            "type": list,
            "description": "A list of the command and it's arguments to run "
                           "inside the container. If not provided, will "
                           "default to the default command defined in the "
                           "image.",
            "default": [],
        },
        "Cluster": {
            "type": str,
            "description": "The name or Amazon Resource Name (ARN) of the "
                           "ECS cluster that you want to run your tasks on.",
        },
        "CPU": {
            "type": int,
            "description": "The relative CPU shares used by each instance of "
                           "the task.",
        },
        "Memory": {
            "type": int,
            "description": "The amount of memory (in megabytes) to reserve "
                           "for each instance of the task.",
        },
        "Count": {
            "type": int,
            "description": "The number of instances of the task to create.",
            "default": 1,
        },
        "TaskRoleArn": {
            "type": str,
            "description": "An optional role to run the task as.",
            "default": "",
        },
        "TaskExecutionRoleArn": {
            "type": str,
            "description": "An optional task execution role arn. If not "
                           "provided, one will be attempted to be created.",
            "default": "",
        },
        "Subnets": {
            "type": list,
            "description": "The list of VPC subnets to deploy the task in.",
        },
        "SecurityGroup": {
            "type": str,
            "description": "The SecurityGroup to attach to the task.",
        },
        "Environment": {
            "type": dict,
            "description": "A dictionary representing the environment of the "
                           "task.",
            "default": {},
        },
        "LogGroup": {
            "type": str,
            "description": "An optional CloudWatch LogGroup name to send logs "
                           "to.",
            "default": "",
        },
    }

    @property
    def service_name(self):
        return self.get_variables()["ServiceName"]

    @property
    def image(self):
        return self.get_variables()["Image"]

    @property
    def command(self):
        return self.get_variables()["Command"] or NoValue

    @property
    def cluster(self):
        return self.get_variables()["Cluster"]

    @property
    def cpu(self):
        return self.get_variables()["CPU"]

    @property
    def memory(self):
        return self.get_variables()["Memory"]

    @property
    def count(self):
        return self.get_variables()["Count"]

    @property
    def task_role_arn(self):
        return self.get_variables()["TaskRoleArn"] or NoValue

    @property
    def subnets(self):
        return self.get_variables()["Subnets"]

    @property
    def security_group(self):
        return self.get_variables()["SecurityGroup"]

    @property
    def log_group(self):
        return self.get_variables()["LogGroup"]

    @property
    def log_configuration(self):
        if not self.log_group:
            return NoValue

        return ecs.LogConfiguration(
            LogDriver="awslogs",
            Options={
                "awslogs-group": self.log_group,
                "awslogs-region": Region,
                "awslogs-stream-prefix": self.service_name,
            }
        )

    @property
    def environment(self):
        env_dict = self.get_variables()["Environment"]
        if not env_dict:
            return NoValue

        env_list = []
        for k, v in env_dict.items():
            env_list.append(ecs.Environment(Name=str(k), Value=str(v)))

        return env_list

    def generate_container_definition(self):
        return ecs.ContainerDefinition(
            Command=self.command,
            Cpu=self.cpu,
            Environment=self.environment,
            Essential=True,
            Image=self.image,
            LogConfiguration=self.log_configuration,
            Memory=self.memory,
            Name=self.service_name,
        )

    def create_task_execution_role(self):
        t = self.template

        self.task_execution_role = t.add_resource(
            iam.Role(
                "TaskExecutionRole",
                AssumeRolePolicyDocument=get_ecs_task_assumerole_policy(),
            )
        )

        t.add_output(
            Output(
                "TaskExecutionRoleName",
                Value=self.task_execution_role.Ref()
            )
        )

        t.add_output(
            Output(
                "TaskExecutionRoleArn",
                Value=self.task_execution_role.GetAtt("Arn")
            )
        )

    def create_task_execution_role_policy(self):
        t = self.template

        policy_name = Sub("${AWS::StackName}-task-exeuction-role-policy")

        self.task_execution_role_policy = t.add_resource(
            iam.PolicyType(
                "TaskExecutionRolePolicy",
                PolicyName=policy_name,
                PolicyDocument=ecs_task_execution_policy(
                    log_group=self.log_group
                ),
                Roles=[self.task_execution_role.Ref()],
            )
        )

    def create_task_definition(self):
        t = self.template

        self.task_definition = t.add_resource(
            ecs.TaskDefinition(
                "TaskDefinition",
                Cpu=str(self.cpu),
                ExecutionRoleArn=self.task_execution_role.GetAtt("Arn"),
                Family=self.service_name,
                Memory=str(self.memory),
                NetworkMode="awsvpc",
                TaskRoleArn=self.task_role_arn,
                ContainerDefinitions=[self.generate_container_definition()]
            )
        )

        t.add_output(
            Output(
                "TaskDefinitionArn",
                Value=self.task_definition.Ref()
            )
        )

    def create_service(self):
        t = self.template
        self.service = t.add_resource(
            ecs.Service(
                "Service",
                Cluster=self.cluster,
                DesiredCount=self.count,
                LaunchType="FARGATE",
                NetworkConfiguration=ecs.NetworkConfiguration(
                    AwsvpcConfiguration=ecs.AwsvpcConfiguration(
                        SecurityGroups=[self.security_group],
                        Subnets=self.subnets,
                    )
                ),
                ServiceName=self.service_name,
                TaskDefinition=self.task_definition.Ref(),
            )
        )

        t.add_output(
            Output(
                "ServiceArn",
                Value=self.service.Ref()
            )
        )

        t.add_output(
            Output(
                "ServiceName",
                Value=self.service.GetAtt("Name")
            )
        )

    def create_template(self):
        self.create_task_execution_role()
        self.create_task_execution_role_policy()
        self.create_task_definition()
        self.create_service()


class SimpleECSService(Blueprint):
    VARIABLES = {
        "ServiceName": {
            "type": str,
            "description": "A simple name for the service.",
        },
        "Image": {
            "type": str,
            "description": "The docker image to use for the task.",
        },
        "Command": {
            "type": list,
            "description": "A list of the command and it's arguments to run "
                           "inside the container. If not provided, will "
                           "default to the default command defined in the "
                           "image.",
            "default": [],
        },
        "Cluster": {
            "type": str,
            "description": "The name or Amazon Resource Name (ARN) of the "
                           "ECS cluster that you want to run your tasks on.",
        },
        "CPU": {
            "type": int,
            "description": "The relative CPU shares used by each instance of "
                           "the task.",
        },
        "Memory": {
            "type": int,
            "description": "The amount of memory (in megabytes) to reserve "
                           "for each instance of the task.",
        },
        "Count": {
            "type": int,
            "description": "The number of instances of the task to create.",
            "default": 1,
        },
        "Environment": {
            "type": dict,
            "description": "A dictionary representing the environment of the "
                           "task.",
            "default": {},
        },
        "LogConfiguration": {
            "type": TroposphereType(ecs.LogConfiguration, optional=True),
            "description": "An optional log configuration object.",
            "default": None,
        },
    }

    @property
    def service_name(self):
        return self.get_variables()["ServiceName"]

    @property
    def image(self):
        return self.get_variables()["Image"]

    @property
    def command(self):
        return self.get_variables()["Command"] or NoValue

    @property
    def cluster(self):
        return self.get_variables()["Cluster"]

    @property
    def cpu(self):
        return self.get_variables()["CPU"]

    @property
    def memory(self):
        return self.get_variables()["Memory"]

    @property
    def count(self):
        return self.get_variables()["Count"]

    @property
    def environment(self):
        env_dict = self.get_variables()["Environment"]
        if not env_dict:
            return NoValue

        env_list = []
        for k, v in env_dict.items():
            env_list.append(ecs.Environment(Name=str(k), Value=str(v)))

        return env_list

    @property
    def log_configuration(self):
        log_config = self.get_variables()["LogConfiguration"]
        return log_config or NoValue

    def add_output(self, key, value):
        self.template.add_output(Output(key, Value=value))

    def create_role(self):
        t = self.template

        self.role = t.add_resource(
            iam.Role(
                "Role",
                AssumeRolePolicyDocument=get_ecs_task_assumerole_policy(),
                Path="/",
            )
        )

        self.add_output("RoleName", self.role.Ref())
        self.add_output("RoleArn", self.role.GetAtt("Arn"))
        self.add_output("RoleId", self.role.GetAtt("RoleId"))

    def generate_policy_document(self):
        return None

    def create_policy(self):
        t = self.template

        policy_doc = self.generate_policy_document()
        if not policy_doc:
            return

        self.policy = t.add_resource(
            iam.ManagedPolicy(
                "ManagedPolicy",
                PolicyDocument=policy_doc,
                Roles=[self.role.Ref()],
            )
        )

        self.add_output("ManagedPolicyArn", self.policy.Ref())

    def generate_container_definition(self):
        return ecs.ContainerDefinition(
            Command=self.command,
            Cpu=self.cpu,
            Environment=self.environment,
            Essential=True,
            Image=self.image,
            LogConfiguration=self.log_configuration,
            Memory=self.memory,
            Name=self.service_name,
        )

    def create_task_definition(self):
        t = self.template

        self.task_definition = t.add_resource(
            ecs.TaskDefinition(
                "TaskDefinition",
                Cpu=str(self.cpu),
                Family=self.service_name,
                Memory=str(self.memory),
                TaskRoleArn=self.role.GetAtt("Arn"),
                ContainerDefinitions=[self.generate_container_definition()]
            )
        )

        self.add_output("TaskDefinitionArn", self.task_definition.Ref())

    def create_service(self):
        t = self.template
        self.service = t.add_resource(
            ecs.Service(
                "Service",
                Cluster=self.cluster,
                DesiredCount=self.count,
                LaunchType="EC2",
                ServiceName=self.service_name,
                TaskDefinition=self.task_definition.Ref(),
            )
        )

        self.add_output("ServiceArn", self.service.Ref())
        self.add_output("ServiceName", self.service.GetAtt("Name"))

    def create_template(self):
        self.create_role()
        self.create_policy()
        self.create_task_definition()
        self.create_service()
