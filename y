version = 0.1
[default]
[default.deploy]
[default.deploy.parameters]
stack_name = "sam-app-subnets"
s3_bucket = "aws-sam-cli-managed-default-samclisourcebucket-1omsti5xow7b0"
s3_prefix = "sam-app-subnets"
region = "ap-southeast-2"
confirm_changeset = true
capabilities = "CAPABILITY_IAM"
parameter_overrides = "AppName=\"SnackVotingPoll\" EnvType=\"dev\" DBClusterName=\"SnackRDSCluster\" DatabaseName=\"SnackRDS\" DBMasterUserName=\"admin_user\" DBSubnetList=\"subnet-065f71bbcfb1f7314, subnet-00ede7f62b0faccb0\""
