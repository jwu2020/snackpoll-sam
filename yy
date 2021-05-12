version = 0.1
[y]
[y.deploy]
[y.deploy.parameters]
stack_name = "sam-app"
s3_bucket = "aws-sam-cli-managed-default-samclisourcebucket-1omsti5xow7b0"
s3_prefix = "sam-app"
region = "ap-southeast-2"
confirm_changeset = true
capabilities = "CAPABILITY_IAM"
parameter_overrides = "AppName=\"SnackVotingPoll\" EnvType=\"dev\" DBClusterName=\"SnackRDSCluster\" DatabaseName=\"SnackRDS\" DBMasterUserName=\"admin_user\" DBSubnetList=\"y\""
