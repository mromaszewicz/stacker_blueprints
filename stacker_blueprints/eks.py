from awacs.helpers.trust import (
    get_default_assumerole_policy,
    make_simple_assume_policy,
)

from troposphere import (
    Base64,
    NoValue,
    Output,
    Sub,
)

from troposphere.autoscaling import (
    AutoScalingGroup,
    LaunchConfiguration,
    Tag,
)

from troposphere.ec2 import (
    BlockDeviceMapping,
    EBSBlockDevice,
)

from troposphere.iam import (
    InstanceProfile,
    Role,
)

from troposphere.policies import (
    AutoScalingReplacingUpdate,
    AutoScalingRollingUpdate,
    UpdatePolicy,
)

from troposphere import eks

from stacker.blueprints.base import Blueprint


class Cluster(Blueprint):
    VARIABLES = {
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

    @property
    def existing_role_arn(self):
        return self.get_variables()["ExistingRoleArn"]

    @property
    def version(self):
        return self.get_variables()["Version"]

    @property
    def security_group_ids(self):
        return self.get_variables()["SecurityGroupIds"]

    @property
    def subnet_ids(self):
        return self.get_variables()["SubnetIds"]

    # This creates an IAM role which EKS requires, as described here:
    # https://docs.aws.amazon.com/eks/latest/userguide/getting-started.html#eks-create-cluster
    def create_iam_role(self):
        t = self.template

        policy = make_simple_assume_policy("eks.amazonaws.com")
        self.role = t.add_resource(
            Role(
                "Role",
                AssumeRolePolicyDocument=policy,
                Path="/",
                ManagedPolicyArns=[
                    "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy",
                    "arn:aws:iam::aws:policy/AmazonEKSServicePolicy",
                ]
            )
        )
        return self.role.GetAtt("Arn")

    def get_iam_role(self):
        return self.existing_role_arn or self.create_iam_role()

    def create_template(self):
        t = self.template
        role_arn = self.get_iam_role()

        version = self.version or NoValue

        self.cluster = t.add_resource(
            eks.Cluster(
                "Cluster",
                RoleArn=role_arn,
                ResourcesVpcConfig=eks.ResourcesVpcConfig(
                    SecurityGroupIds=self.security_group_ids.split(","),
                    SubnetIds=self.subnet_ids.split(","),
                ),
                Version=version,
            )
        )

        t.add_output(Output("ClusterName", Value=self.cluster.Ref()))
        t.add_output(Output("ClusterArn", Value=self.cluster.GetAtt("Arn")))
        t.add_output(
            Output("ClusterEndpoint", Value=self.cluster.GetAtt("Endpoint"))
        )
        t.add_output(Output("RoleArn", Value=role_arn))


# This is a stacker re-implementation of Amazon's template defined here:
# https://amazon-eks.s3-us-west-2.amazonaws.com/1.10.3/2018-06-05/amazon-eks-nodegroup.yaml
# More docs can be found here:
# https://docs.aws.amazon.com/eks/latest/userguide/launch-workers.html

# This comes straight from that template above, just formatted for Python
MAX_PODS_PER_INSTANCE = {
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


LAUNCH_CONFIG_USERDATA = """
#!/bin/bash -xe
CA_CERTIFICATE_DIRECTORY=/etc/kubernetes/pki
CA_CERTIFICATE_FILE_PATH=$CA_CERTIFICATE_DIRECTORY/ca.crt
MODEL_DIRECTORY_PATH=~/.aws/eks
MODEL_FILE_PATH=$MODEL_DIRECTORY_PATH/eks-2017-11-01.normal.json
mkdir -p $CA_CERTIFICATE_DIRECTORY
mkdir -p $MODEL_DIRECTORY_PATH
curl -o $MODEL_FILE_PATH \
    https://s3-us-west-2.amazonaws.com/amazon-eks/1.10.3/2018-06-05/eks-2017-11-01.normal.json
aws configure add-model --service-model file://$MODEL_FILE_PATH \
    --service-name eks
aws eks describe-cluster --region=${"AWS::Region"} --name=${ClusterName} \
    --query 'cluster.{certificateAuthorityData: certificateAuthority.data, endpoint: endpoint}' > /tmp/describe_cluster_result.json
cat /tmp/describe_cluster_result.json | grep certificateAuthorityData | \
    awk '{print $2}' | sed 's/[,\"]//g' | \
    base64 -d >  $CA_CERTIFICATE_FILE_PATH
MASTER_ENDPOINT=$(cat /tmp/describe_cluster_result.json | grep endpoint | \
    awk '{print $2}' | sed 's/[,\"]//g')
INTERNAL_IP=$(curl -s http://169.254.169.254/latest/meta-data/local-ipv4)
sed -i s,MASTER_ENDPOINT,$MASTER_ENDPOINT,g /var/lib/kubelet/kubeconfig
sed -i s,CLUSTER_NAME,", cluster_name, ",g /var/lib/kubelet/kubeconfig
sed -i s,REGION,${AWS::Region},g /etc/systemd/system/kubelet.service
sed -i s,MAX_PODS,${MaxPods}
,g /etc/systemd/system/kubelet.service
sed -i s,MASTER_ENDPOINT,$MASTER_ENDPOINT,g /etc/systemd/system/kubelet.service
sed -i s,INTERNAL_IP,$INTERNAL_IP,g /etc/systemd/system/kubelet.service
DNS_CLUSTER_IP=10.100.0.10
if [[ $INTERNAL_IP == 10.* ]] ; then DNS_CLUSTER_IP=172.20.0.10; fi
sed -i s,DNS_CLUSTER_IP,$DNS_CLUSTER_IP,g  /etc/systemd/system/kubelet.service
sed -i s,CERTIFICATE_AUTHORITY_FILE,$CA_CERTIFICATE_FILE_PATH,g \
    /var/lib/kubelet/kubeconfig
sed -i s,CLIENT_CA_FILE,$CA_CERTIFICATE_FILE_PATH,g \
    /etc/systemd/system/kubelet.service
systemctl daemon-reload
systemctl restart kubelet
/opt/aws/bin/cfn-signal -e $? \
    --stack ${AWS::StackName} \
    --resource NodeGroup \
    --region ${AWS::Region}
"""


# This is copy/pasted from
# https://amazon-eks.s3-us-west-2.amazonaws.com/1.10.3/2018-06-05/amazon-eks-nodegroup.yaml
# and updated to call troposphere functions instead of EC2 CFN placeholders
def get_launch_config_userdata(cluster_name, instance_type):
    try:
        max_pods = MAX_PODS_PER_INSTANCE[instance_type]
    except KeyError:
        raise ValueError("%s is not supported by EKS" % instance_type)

    launch_config_userdata = Sub(
        LAUNCH_CONFIG_USERDATA,
        ClusterName=cluster_name,
        MaxPods=max_pods
    )

    return Base64(launch_config_userdata)


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

    @property
    def cluster_name(self):
        return self.get_variables()["ClusterName"]

    @property
    def security_group_id(self):
        return self.get_variables()["SecurityGroupId"]

    @property
    def min_instance_count(self):
        return self.get_variables()["MinInstanceCount"]

    @property
    def max_instance_count(self):
        return self.get_variables()["MaxInstanceCount"]

    @property
    def desired_instance_count(self):
        return self.get_variables()["DesiredInstanceCount"]

    @property
    def subnets(self):
        return self.get_variables()["Subnets"]

    @property
    def image_id(self):
        return self.get_variables()["ImageId"]

    @property
    def instance_type(self):
        return self.get_variables()["InstanceType"]

    @property
    def key_name(self):
        return self.get_variables()["KeyName"]

    @property
    def root_volume_size(self):
        return self.get_variables()["RootVolumeSize"]

    @property
    def root_volume_device(self):
        return self.get_variables()["RootVolumeDevice"]

    def create_node_instance_role(self):
        t = self.template

        policy_arns = [
            "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
            "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
            "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
        ]

        # This re-creates NodeInstanceRole from Amazon's CFN template
        self.role = t.add_resource(
            Role(
                "Role",
                AssumeRolePolicyDocument=get_default_assumerole_policy(),
                Path="/",
                ManagedPolicyArns=policy_arns,
            )
        )
        t.add_output(Output("Role", Value=self.role.ref()))

    def create_instance_profile(self):
        t = self.template

        self.instance_profile = t.add_resource(
            InstanceProfile(
                "InstanceProfile",
                Roles=[self.role.Ref()]
            )
        )

        t.add_output(
            Output("InstanceProfile", Value=self.instance_profile.Ref())
        )
        t.add_output(
            Output(
                "InstanceProfileArn",
                Value=self.instance_profile.GetAtt("Arn")
            )
        )

    def create_launch_config(self):
        t = self.template

        user_data = get_launch_config_userdata(
            self.cluster_name,
            self.instance_type
        )

        # Create the launch configuration with a userdata payload that
        # configures each node to connect to
        self.launch_config = t.add_resource(
            LaunchConfiguration(
                "LaunchConfiguration",
                AssociatePublicIpAddress=False,
                IamInstanceProfile=self.instance_profile.Ref(),
                ImageId=self.image_id,
                InstanceType=self.instance_type,
                KeyName=self.key_name,
                SecurityGroups=[self.security_group_id],
                UserData=user_data,
                BlockDeviceMappings=[
                    BlockDeviceMapping(
                        DeviceName=self.root_volume_device,
                        Ebs=EBSBlockDevice(
                            VolumeSize=self.root_volume_size,
                            DeleteOnTermination=True
                        )
                    ),
                ],
            )
        )

        t.add_output(
            Output("LaunchConfiguration", Value=self.launch_config.Ref())
        )

    def create_auto_scaling_group(self):
        t = self.template

        desired_instances = self.desired_instance_count
        if desired_instances < 0:
            desired_instances = self.min_instance_count

        # Create the AutoScalingGroup which will manage our instances. It's
        # easy to change the worker count by tweaking the limits in here once
        # everything is up and running.
        self.auto_scaling_group = t.add_resource(
            AutoScalingGroup(
                "AutoScalingGroup",
                MinSize=self.min_instance_count,
                MaxSize=self.max_instance_count,
                DesiredCapacity=desired_instances,
                LaunchConfigurationName=self.launch_config.Ref(),
                VPCZoneIdentifier=self.subnets.split(","),
                Tags=[
                    Tag("Name", "%s-eks-worker" % self.cluster_name, True),
                    Tag("kubernetes.io/cluster/%s" % self.cluster_name,
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

        t.add_output(
            Output("AutoScalingGroup", Value=self.auto_scaling_group.Ref())
        )

    def create_template(self):
        self.create_node_instance_role()
        self.create_instance_profile()
        self.create_launch_config()
        self.create_auto_scaling_group()
