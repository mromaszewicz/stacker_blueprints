from awacs.aws import (
    Allow,
    Statement,
    Principal,
    Policy
)
from awacs.sts import (
    AssumeRole
)

from troposphere import (
    Base64,
    FindInMap,
    GetAtt,
    Join,
    Ref,
    Output
)

from troposphere.autoscaling import (
    AutoScalingGroup,
    LaunchConfiguration,
    Tag
)

from troposphere.ec2 import (
    BlockDeviceMapping,
    EBSBlockDevice
)

from troposphere.iam import (
    InstanceProfile,
    Role
)

from troposphere.policies import (
    AutoScalingReplacingUpdate,
    AutoScalingRollingUpdate,
    UpdatePolicy
)

from troposphere import eks
from stacker.blueprints.base import Blueprint


class Cluster(Blueprint):
    VARIABLES = {
        "Name": {
            "type": str,
            "description": "The name of the cluster to create.",
        },
        "ExistingRoleArn": {
            "type": str,
            "description": "IAM Role ARN with EKS assume role policies. One "
                           "will be created if it's not provided.",
            "default": ""
        },
        "Version": {
            "type": str,
            "description": "Kubernetes version",
            "default": "",
        },
        "SecurityGroupIds": {
            "type": str,
            "description": "A comma separated list of security group ids for "
                           "controlling ENI access from EKS to workers",
        },
        "SubnetIds": {
            "type": str,
            "description": "A comma separated list of subnet ids where you "
                           "will launch your worker nodes",
        }
    }

    # This creates an IAM role which EKS requires, as described here:
    # https://docs.aws.amazon.com/eks/latest/userguide/getting-started.html#eks-create-cluster
    def create_iam_role(self):
        eks_service_role_id = "EksServiceRole"
        t = self.template
        role = t.add_resource(
            Role(
                eks_service_role_id,
                AssumeRolePolicyDocument=Policy(
                    Statement=[
                        Statement(
                            Effect=Allow,
                            Action=[AssumeRole],
                            Principal=Principal("Service",
                                                ["eks.amazonaws.com"])
                        )
                    ]
                ),
                Path="/",
                ManagedPolicyArns=[
                    "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy",
                    "arn:aws:iam::aws:policy/AmazonEKSServicePolicy",
                ]
            )
        )
        return role.GetAtt("Arn")

    def get_iam_role(self):
        role_arn = self.get_variables()["ExistingRoleArn"]
        if role_arn:
            return role_arn
        return self.create_iam_role()

    def create_template(self):
        t = self.template
        role_arn = self.get_iam_role()
        variables = self.get_variables()

        args = {}
        version = variables["Version"]
        if version:
            args["Version"] = version

        # This is a fully qualified stacker name, prefixed with the namespace.
        eks_name_tag = self.context.get_fqn(variables["Name"])

        t.add_resource(
            eks.Cluster(
                "EksCluster",
                Name=eks_name_tag,
                RoleArn=role_arn,
                ResourcesVpcConfig=eks.ResourcesVpcConfig(
                    SecurityGroupIds=variables["SecurityGroupIds"].split(","),
                    SubnetIds=variables["SubnetIds"].split(","),
                ),
                **args
            )
        )

        # Output the ClusterName and RoleArn, which are useful as inputs for
        # EKS worker nodes.
        t.add_output(Output("ClusterName", Value=eks_name_tag))
        t.add_output(Output("RoleArn", Value=role_arn))


# This is a stacker re-implementation of Amazon's template defined here:
# https://amazon-eks.s3-us-west-2.amazonaws.com/1.10.3/2018-06-05/amazon-eks-nodegroup.yaml
# More docs can be found here:
# https://docs.aws.amazon.com/eks/latest/userguide/launch-workers.html

# This comes straight from that template above, just formatted for Python
max_pods_per_instance = {
    "c4.large": 29,
    "c4.xlarge": 58,
    "c4.2xlarge": 58,
    "c4.4xlarge": 234,
    "c4.8xlarge": 234,
    "c5.large": 29,
    "c5.xlarge": 58,
    "c5.2xlarge": 58,
    "c5.4xlarge": 234,
    "c5.9xlarge": 234,
    "c5.18xlarge": 737,
    "i3.large": 29,
    "i3.xlarge": 58,
    "i3.2xlarge": 58,
    "i3.4xlarge": 234,
    "i3.8xlarge": 234,
    "i3.16xlarge": 737,
    "m3.medium": 12,
    "m3.large": 29,
    "m3.xlarge": 58,
    "m3.2xlarge": 118,
    "m4.large": 20,
    "m4.xlarge": 58,
    "m4.2xlarge": 58,
    "m4.4xlarge": 234,
    "m4.10xlarge": 234,
    "m5.large": 29,
    "m5.xlarge": 58,
    "m5.2xlarge": 58,
    "m5.4xlarge": 234,
    "m5.12xlarge": 234,
    "m5.24xlarge": 737,
    "p2.xlarge": 58,
    "p2.8xlarge": 234,
    "p2.16xlarge": 234,
    "p3.2xlarge": 58,
    "p3.8xlarge": 234,
    "p3.16xlarge": 234,
    "r3.xlarge": 58,
    "r3.2xlarge": 58,
    "r3.4xlarge": 234,
    "r3.8xlarge": 234,
    "r4.large": 29,
    "r4.xlarge": 58,
    "r4.2xlarge": 58,
    "r4.4xlarge": 234,
    "r4.8xlarge": 234,
    "r4.16xlarge": 737,
    "t2.small": 8,
    "t2.medium": 17,
    "t2.large": 35,
    "t2.xlarge": 44,
    "t2.2xlarge": 44,
    "x1.16xlarge": 234,
    "x1.32xlarge": 234,
}


def create_max_pods_per_node_mapping(t):
    mapping = {}
    for instance, max_pods in max_pods_per_instance.items():
        mapping[instance] = {"MaxPods": max_pods}
    t.add_mapping("MaxPodsPerNode", mapping)


# This is copy/pasted from
# https://amazon-eks.s3-us-west-2.amazonaws.com/1.10.3/2018-06-05/amazon-eks-nodegroup.yaml
# and updated to call troposphere functions instead of EC2 CFN placeholders
def get_launch_config_userdata(cluster_name, instance_type):
    if instance_type not in max_pods_per_instance:
        raise ValueError("%s is not supported by EKS" % instance_type)

    launch_config_userdata = [
        "#!/bin/bash -xe\n",
        "CA_CERTIFICATE_DIRECTORY=/etc/kubernetes/pki", "\n",
        "CA_CERTIFICATE_FILE_PATH=$CA_CERTIFICATE_DIRECTORY/ca.crt", "\n",
        "MODEL_DIRECTORY_PATH=~/.aws/eks", "\n",
        "MODEL_FILE_PATH=$MODEL_DIRECTORY_PATH/eks-2017-11-01.normal.json", "\n",
        "mkdir -p $CA_CERTIFICATE_DIRECTORY", "\n",
        "mkdir -p $MODEL_DIRECTORY_PATH", "\n",
        "curl -o $MODEL_FILE_PATH https://s3-us-west-2.amazonaws.com/amazon-eks/1.10.3/2018-06-05/eks-2017-11-01.normal.json",
        "\n",
        "aws configure add-model --service-model file://$MODEL_FILE_PATH --service-name eks", "\n",
        "aws eks describe-cluster --region=", Ref("AWS::Region"), " --name=", cluster_name,
        " --query 'cluster.{certificateAuthorityData: certificateAuthority.data, endpoint: endpoint}' > /tmp/describe_cluster_result.json",
        "\n",
        "cat /tmp/describe_cluster_result.json | grep certificateAuthorityData | awk '{print $2}' | sed 's/[,\"]//g' | base64 -d >  $CA_CERTIFICATE_FILE_PATH",
        "\n",
        "MASTER_ENDPOINT=$(cat /tmp/describe_cluster_result.json | grep endpoint | awk '{print $2}' | sed 's/[,\"]//g')",
        "\n",
        "INTERNAL_IP=$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)", "\n",
        "sed -i s,MASTER_ENDPOINT,$MASTER_ENDPOINT,g /var/lib/kubelet/kubeconfig", "\n",
        "sed -i s,CLUSTER_NAME,", cluster_name, ",g /var/lib/kubelet/kubeconfig", "\n",
        "sed -i s,REGION,", Ref("AWS::Region"), ",g /etc/systemd/system/kubelet.service", "\n",
        "sed -i s,MAX_PODS,", FindInMap("MaxPodsPerNode", instance_type, "MaxPods"),
        ",g /etc/systemd/system/kubelet.service", "\n",
        "sed -i s,MASTER_ENDPOINT,$MASTER_ENDPOINT,g /etc/systemd/system/kubelet.service", "\n",
        "sed -i s,INTERNAL_IP,$INTERNAL_IP,g /etc/systemd/system/kubelet.service", "\n",
        "DNS_CLUSTER_IP=10.100.0.10", "\n",
        "if [[ $INTERNAL_IP == 10.* ]] ; then DNS_CLUSTER_IP=172.20.0.10; fi", "\n",
        "sed -i s,DNS_CLUSTER_IP,$DNS_CLUSTER_IP,g  /etc/systemd/system/kubelet.service", "\n",
        "sed -i s,CERTIFICATE_AUTHORITY_FILE,$CA_CERTIFICATE_FILE_PATH,g /var/lib/kubelet/kubeconfig", "\n",
        "sed -i s,CLIENT_CA_FILE,$CA_CERTIFICATE_FILE_PATH,g  /etc/systemd/system/kubelet.service", "\n",
        "systemctl daemon-reload", "\n",
        "systemctl restart kubelet", "\n",
        "/opt/aws/bin/cfn-signal -e $? ",
        "         --stack ", Ref("AWS::StackName"),
        "         --resource NodeGroup ",
        "         --region ", Ref("AWS::Region"), "\n"
    ]
    return Base64(Join("", launch_config_userdata))


class Workers(Blueprint):
    VARIABLES = {
        "ClusterName": {
            "type": str,
            "description": "The name of the cluster for workers to join."
        },
        "SecurityGroupId": {
            "type": str,
            "description": "The security group ID which will contain worker "
                           "nodes."
        },
        "MinInstanceCount": {
            "type": int,
            "description": "The minimum number of worker nodes for the worker "
                           "AutoScalingGroup.",
            "default": 1,
        },
        "MaxInstanceCount": {
            "type": int,
            "description": "The maximum number of worker nodes for the worker "
                           "AutoScalingGroup.",
            "default": 3,
        },
        "DesiredInstanceCount": {
            "type": int,
            "description": "The desired number of worker nodes for the worker "
                           "AutoScalingGroup. Defaults to minimum.",
            "default": -1,
        },
        "Subnets": {
            "type": str,
            "description": "A list of subnet ID's where workers will be "
                           "launched."
        },
        "ImageId": {
            "type": str,
            "description": "Worker node AMI. You need to use one of the AWS "
                           "provided EKS worker AMI's."
        },
        "InstanceType": {
            "type": str,
            "description": "Instance type for workers.",
            "default": "t2.small",
        },
        "KeyName": {
            "type": str,
            "description": "Existing SSH key name for worker access."
        },
        "RootVolumeSize": {
            "type": int,
            "description": "Root volume size in GB.",
            "default": 20,
        },
        "RootVolumeDevice": {
            "type": str,
            "description": "The block device name for the root volume. This "
                           "will depend on instance type and AMI",
            "default": "/dev/sda1"
        }
    }

    def create_node_instance_role(self):
        t = self.template

        # The user data below relies on this map being present.
        create_max_pods_per_node_mapping(t)

        # This re-creates NodeInstanceRole from Amazon's CFN template
        role = t.add_resource(
            Role(
                "NodeInstanceRole",
                AssumeRolePolicyDocument=Policy(
                    Statement=[
                        Statement(
                            Effect=Allow,
                            Action=[AssumeRole],
                            Principal=Principal("Service", ["ec2.amazonaws.com"])
                        )
                    ]
                ),
                Path="/",
                ManagedPolicyArns=[
                    "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
                    "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
                    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
                ]
            )
        )
        t.add_output(Output("NodeInstanceRole", Value=role.ref()))
        return role

    def create_template(self):
        t = self.template
        variables = self.get_variables()

        # Create the node instance profile which allows nodes to join the
        # EKS Cluster
        role = self.create_node_instance_role()
        profile = t.add_resource(
            InstanceProfile(
                "NodeInstanceProfile",
                Roles=[role.ref()]
            )
        )

        cluster_name = variables["ClusterName"]
        instance_type = variables["InstanceType"]
        user_data = get_launch_config_userdata(cluster_name, instance_type)

        # Create the launch configuration with a userdata payload that
        # configures each node to connect to
        launch_config = t.add_resource(
            LaunchConfiguration(
                "NodeLaunchConfig",
                AssociatePublicIpAddress=False,
                IamInstanceProfile=profile.ref(),
                ImageId=variables["ImageId"],
                InstanceType=variables["InstanceType"],
                KeyName=variables["KeyName"],
                SecurityGroups=[variables["SecurityGroupId"]],
                UserData=user_data,
                BlockDeviceMappings=[
                    BlockDeviceMapping(
                        DeviceName=variables["RootVolumeDevice"],
                        Ebs=EBSBlockDevice(
                            VolumeSize=variables["RootVolumeSize"],
                            DeleteOnTermination=True
                        )
                    ),
                ],
            )
        )

        min_instances = variables["MinInstanceCount"]
        max_instances = variables["MaxInstanceCount"]
        desired_instances = variables["DesiredInstanceCount"]
        if desired_instances < 0:
            desired_instances = min_instances

        # Create the AutoScalingGroup which will manage our instances. It's
        # easy to change the worker count by tweaking the limits in here once
        # everything is up and running.
        t.add_resource(
            AutoScalingGroup(
                "NodeGroup",
                MinSize=min_instances,
                MaxSize=max_instances,
                DesiredCapacity=desired_instances,
                LaunchConfigurationName=launch_config.ref(),
                VPCZoneIdentifier=variables["Subnets"].split(","),
                Tags=[
                    Tag("Name", "%s-eks-worker" % cluster_name, True),
                    Tag("kubernetes.io/cluster/%s" % cluster_name,
                        "owned", True)
                ],
                UpdatePolicy=UpdatePolicy(
                    AutoScalingReplacingUpdate=AutoScalingReplacingUpdate(
                        WillReplace=True,
                    ),
                    AutoScalingRollingUpdate=AutoScalingRollingUpdate(
                        PauseTime='PT5M',
                        MinInstancesInService="1",
                        MaxBatchSize='1',
                        WaitOnResourceSignals=True
                    )
                )
            )
        )
