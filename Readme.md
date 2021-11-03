# Life Signals (Hawkeye) Environment (for AWS)

This repo contains a poc effort up on AWS EKS. Ideally, it is to help create the environment on AWS with EKS and deploy the application on it.

### Prerequisites
--------------------------------------------
* yq - *(CLI processor for yaml files)*
    * [Github page](https://github.com/mikefarah/yq)
        * `curl --silent --location "https://github.com/mikefarah/yq/releases/download/v4.2.0/yq_linux_amd64.tar.gz" | tar xz && sudo mv yq_linux_amd64 /usr/local/bin/yq`
* kubectl - *(official CLI for generic Kubernetes)*
    * [Install kubectl - OSX/Linux/Windows](https://docs.aws.amazon.com/eks/latest/userguide/install-kubectl.html)
* AWS CLI - *(official CLI for AWS)*
    * [Install/Upgrade AWS CLI - OSX](https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2-mac.html#cliv2-mac-install-cmd-all-users)
    * [Install AWS CLI - Linux](https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2-linux.html#cliv2-linux-install)
    * [Upgrade AWS CLI - Linux](https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2-linux.html#cliv2-linux-upgrade)
* AWS IAM Authenticator - *(helper tool to provide authentication to Kube cluster)*
    * Linux Installation - v1.19.6
        * `curl -o /tmp/aws-iam-authenticator "https://amazon-eks.s3.us-west-2.amazonaws.com/1.19.6/2021-01-05/bin/linux/amd64/aws-iam-authenticator"`
        * `sudo mv /tmp/aws-iam-authenticator /usr/local/bin`
        * `sudo chmod +x /usr/local/bin/aws-iam-authenticator`
        * `aws-iam-authenticator help`
    * OSX and Windows Installation 
        * [Install AWS IAM Authenticator](https://docs.aws.amazon.com/eks/latest/userguide/install-aws-iam-authenticator.html)
* eksctl - *(official CLI for Amazon EKS)*
    * [Install/Upgrade eksctl - OSX/Linux/Windows](https://docs.aws.amazon.com/eks/latest/userguide/eksctl.html)
* Helm - *(helpful Package Manager for Kubernetes)*
    * [Install](https://docs.aws.amazon.com/eks/latest/userguide/helm.html)
* kustomize - *(Customize kubernetes YML configurations)*
    * You will need 4.0.5 for use with ArgoFlow for AWS
    * `curl --silent --location "https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize%2Fv4.0.5/kustomize_v4.0.5_linux_amd64.tar.gz" | tar xz -C /tmp`
    * `sudo mv /tmp/kustomize /usr/local/bin`
    * `kustomize version`

### Install Instructions
--------------------------------------------
Before you deploy, you must have a cluster up and running with AWS EKS.  
Use the `eksctl` tool to create a specific cluster up on AWS for your needs.  
## Step 1 - Configure `awscli`
Define your key and secret in `~/.aws/credentials`
```
[default]
aws_access_key_id = SOMETHING
aws_secret_access_key = SOMETHINGLONGER
```
Define your profile information (AWS Organization) in `~/.aws/config`.
```
[default]
region = us-west-2
output = json

[profile bl-lifesignals]
region = us-west-2
output = json
role_arn = arn:aws:iam::113151489485:role/admin-lifesignals-subaccount
source_profile = bl-paloul
```
***A sysadmin should have already given your AWS IAM (i.e. paloul, mshirdel) the appropriate  
policy to be able to assume the Life Signals sub-account role, `admin-lifesignals-subaccount`.***

You must execute `awscli` or `eksctl` commands while assuming the correct role in order  
to deploy the cluster under the right account. This is done with either the `--profile`  
option or the use of an environment variable `AWS_PROFILE`, i.e. `export AWS_PROFILE=bl-profile1`,  
before executing any commands. Visit [here](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-profiles.html#using-profiles) for information.

Execute the following command to verify you configured `awscli` and `eksctl` correctly:
```
╰─❯ eksctl get cluster --verbose 4 --profile bl-lifesignals
[▶]  role ARN for the current session is "arn:aws:sts::113151489485:assumed-role/admin-lifesignals-subaccount/1618011239640991900"
[ℹ]  eksctl version 0.44.0
[ℹ]  using region us-west-2
No clusters found
```
You will see any existing EKS clusters in that account you have access to.
----
## Step 2 - Create EKS Cluster - [Additional Info](https://docs.aws.amazon.com/eks/latest/userguide/create-cluster.html)
Execute the following `eksctl` command to create a cluster under the AWS Babylon account. You  
should be in the same directory as the file `aws-eks-cluster.yaml`. 
```
eksctl create cluster -f aws-eks-cluster-spec.yaml --profile bl-lifesignals
```
This command will take several minutes as `eksctl` creates the entire stack with  
supporting services inside AWS, i.e. VPC, Subnets, Security Groups, Route Tables,  
in addition to the cluster itself. Once completed you should see the following:
```
[✓]  EKS cluster "hawkeye-1" in "us-west-2" region is ready
```
With nothing else running on the cluster you can check `kubectl` and see similar output:  
```
╰─❯ kubectl get nodes
NAME                                           STATUS   ROLES    AGE   VERSION
ip-192-168-2-226.us-west-2.compute.internal    Ready    <none>   17m   v1.19.6-eks-49a6c0
ip-192-168-26-228.us-west-2.compute.internal   Ready    <none>   17m   v1.19.6-eks-49a6c0

╰─❯ kubectl get pods -n kube-system
NAME                       READY   STATUS    RESTARTS   AGE
aws-node-2ssm5             1/1     Running   0          19m
aws-node-xj5sb             1/1     Running   0          19m
coredns-6548845887-fg74h   1/1     Running   0          25m
coredns-6548845887-vlzff   1/1     Running   0          25m
kube-proxy-hjgd5           1/1     Running   0          19m
kube-proxy-jm2m9           1/1     Running   0          19m
```
### <u>Delete the EKS Cluster When Not Needed</u>
One node group starts up a min 2 EC2 machines that charge by the hour. The other node groups  
are setup to scale down to 0 and only ramp up when pods are needed. In order to avoid being  
charged while not in use please use the following command to delete your cluster:
```
eksctl delete cluster -f aws-eks-cluster-spec.yaml --profile bl-lifesignals
```

## Step 3 - Create the policies and roles
We need to create policies and roles for each respective piece that needs it inside our cluster.  
Make sure you are using the right AWS Profile. Set the following to make sure you use bl-lifesignals profile:  
```
# !! IMPORTANT !!
export AWS_PROFILE=bl-lifesignals
```

### <u>Kubernetes Cluster Autoscaler</u> - [Additional Info](https://docs.aws.amazon.com/eks/latest/userguide/cluster-autoscaler.html)
We need to create the appropriate policy and role for the Cluster Autoscaler.

Create the Policy and Role for the Cluster Autoscaler to work properly:
```
# The policy file is already included as part of this repo
aws iam create-policy \
    --policy-name AmazonEKSClusterAutoscalerPolicy \
    --policy-document file://cluster-autoscaler-policy.json
# Note the ARN returned in the output for use in a later step.
```
You can now make a new role with the policy attached. You can create an IAM role and attach an IAM policy  
to it using eksctl. 
```
# Replace the attach-policy-arn field with the arn of the policy created above. 
# Put your cluster name in the cluster field.
eksctl create iamserviceaccount \
  --cluster=hawkeye \
  --namespace=kube-system \
  --name=cluster-autoscaler \
  --attach-policy-arn=arn:aws:iam::113151489485:policy/AmazonEKSClusterAutoscalerPolicy \
  --override-existing-serviceaccounts \
  --approve
```
### <u>External-DNS</u> - [Additional Info](https://github.com/kubernetes-sigs/external-dns/blob/master/docs/tutorials/aws.md)
External-DNS is a supporting feature controller for Kubernetes that automatically assigns DNS A records  
for load balancers when a service/ingress is defined. The correct permissions need to be assigned to the  
`kube-system` namespace'd pods in order for this to function.

You will first have to create the Policy and Role for the external-dns system to work properly.  
**Important: Update hosted zone in the external-dns-policy.json to match the domain you want the policy to grant access to.**
```
# The policy file is already included as part of this repo
aws iam create-policy \
    --policy-name AmazonEKSClusterExternalDnsPolicy \
    --policy-document file://external-dns-policy.json
# Note the ARN returned in the output for use in a later step.
```
You can now make a new role with the policy attached. You can create an IAM role and attach an IAM policy  
to it using eksctl. 
```
# Replace the attach-policy-arn field with the arn of the policy created above. 
# Put your cluster name in the cluster field.
eksctl create iamserviceaccount \
  --cluster=hawkeye \
  --namespace=kube-system \
  --name=external-dns \
  --attach-policy-arn=arn:aws:iam::113151489485:policy/AmazonEKSClusterExternalDnsPolicy \
  --override-existing-serviceaccounts \
  --approve
```
### <u>AWS Load Balancer Controller</u> - [Additional Info](https://docs.aws.amazon.com/eks/latest/userguide/aws-load-balancer-controller.html)
The AWS Load Balancer Controller is in charge of creating the load balancer when ingresses are defined  
in Kubernetes yaml files for services. It needs policies that allows it to schedule a NLB in specific subnets. 
The policy version for the LB Controller should match the actual version of the LB that gets deployed in cluster.
The one contained within this repo is marked lb-controller-v2_2_0 that matches version 2.2.0 of the LB Controller.
The AWS Load Balancer Controller is installed with a Helm chart via ArgoCD deployment. The Helm Chart link is:  
https://artifacthub.io/packages/helm/aws/aws-load-balancer-controller/1.2.0. This Helm Chart is versioned 1.2.0,  
but the underlying LB Controller is marked as version 2.2.0. If the Helm Chart is updated and a newer LB Controller  
version is used, then make sure to update the IAM Policy for the LB Controller here as well.
```
# Create an IAM policy from the json already downloaded, lb-controller-iam_policy.json
# This mightve already been done, you will see an error if the Policy already exists, ignore.
aws iam create-policy \
    --policy-name AWSLoadBalancerControllerIAMPolicy \
    --policy-document file://lb-controller-v2_2_0-iam_policy.json
# Note the ARN returned in the output for use in a later step.
```
You can now make a new role with policy attached. You can create an IAM role and attach an IAM policy  
to it using eksctl.
```
# Create an IAM role and annotate the Kubernetes service account named 
# aws-load-balancer-controller in the kube-system namespace
# Get the policy ARN from the AWS IAM Policy Console
eksctl create iamserviceaccount \
  --cluster=hawkeye \
  --namespace=kube-system \
  --name=aws-load-balancer-controller \
  --attach-policy-arn=arn:aws:iam::113151489485:policy/AWSLoadBalancerControllerIAMPolicy \
  --override-existing-serviceaccounts \
  --approve
```
### <u>External Secrets</u> - [Additional Info](https://github.com/external-secrets/kubernetes-external-secrets) 
Kubernetes External Secrets allows you to use external secret management systems, like AWS Secrets Manager or HashiCorp Vault, to securely add secrets in Kubernetes.  
Create the policy and the role to access the Secret stoe in AWS Secret Manager.
```
# Create an IAM policy from the json already downloaded, external-secrets-iam-policy.json
# This mightve already been done, you will see an error if the Policy already exists, ignore.
aws iam create-policy \
    --policy-name AWSExternalSecretsDevHawkeyeIAMPolicy \
    --policy-document file://external-secrets-iam-policy.json
# Note the ARN returned in the output for use in a later step.
```
You can now make a new role with policy attached. You can create an IAM role and attach an IAM policy  
to it using eksctl.
```
# Create an IAM role and annotate the Kubernetes service account named 
# external-secrets in the kube-system namespace
# Get the policy ARN from the AWS IAM Policy Console
# Update the cluster name if different
eksctl create iamserviceaccount \
  --cluster=hawkeye \
  --namespace=kube-system \
  --name=external-secrets \
  --attach-policy-arn=arn:aws:iam::113151489485:policy/AWSExternalSecretsDevHawkeyeIAMPolicy \
  --override-existing-serviceaccounts \
  --approve
```
### <u>Cert Manager</u> - [Additional Info](https://cert-manager.io/docs/)
`cert-manager` is a native Kubernetes certificate management controller. It can help with issuing  
certificates from a variety of sources, in our case, AWS' ACM. `cert-manager` needs to be able to add  
records to Route53 in order to solve the DNS01 challenge. To enable this, create a IAM policy.
```
# Create an IAM policy from the json already downloaded, cert-manager-iam_policy.json
# This mightve already been done, you will see an error if the Policy already exists, ignore.
aws iam create-policy \
    --policy-name AWSCertManagerIAMPolicy \
    --policy-document file://cert-manager-iam_policy.json
# Note the ARN returned in the output for use in a later step.
```
You can now make a new role with policy attached. You can create an IAM role and attach an IAM policy  
to it using eksctl.
```
# Create an IAM role and annotate the Kubernetes service account named 
# cert-manager in the cert-manager namespace.
# Update the cluster value
# Update the attach-policy-arn value with the arn of the policy created above
eksctl create iamserviceaccount \
  --cluster=hawkeye \
  --namespace=cert-manager \
  --name=cert-manager \
  --attach-policy-arn=arn:aws:iam::113151489485:policy/AWSCertManagerIAMPolicy \
  --override-existing-serviceaccounts \
  --approve
```

## Step 4 - Create and Configure the supporting managed resources/services/properties
### <u>Elasticache - Redis</u> - General cache service for cluster
The Authentication piece requires a Redis server. Create one with AWS Elasticache.
Record the hostname and update the setup_repo.conf file with the Redis host for the 
field `<<__oidc.redis.connection_url__>>`. 

### <u>AWS Cognito and Azure AD Enterprise App</u> - User Id Provider and SAML SSO
Fill this in

### <u>Update Role ARNs in setup_repo.sh</u> - Role Permissions
Fill this in

### <u>Define secrets in Secret Manager</u> - Define secrets with keys defined in setup_repo.sh
Fill this in

## Step 5 - Deploy the pieces with ArgoCD
Once the environment is setup proceed to deploy the application with ArgoCD. 
1. Run the `setup_repo.sh` script to populate files with config values from `setup_repo.conf`
2. Commit and push changes to target repo branch defined by `git_repo.url` and `git_repo.target_revision` in `setup_repo.conf`
3. Start up externa-secret and argocd separately first:
  - `kustomize build distribution/external-secrets/ | kubectl apply -f -`
  - `kustomize build distribution/argocd/ | kubectl apply -f -`
4. Get the admin password to the ArgoCD Dashboard and login. The ArgoCD Dashboard is only accessible via port forward:
  - `kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d`
  - `kubectl port-forward svc/argocd-server -n argocd 8888:80`
5. Finally roll out the main argocd hawkeye application that will instruct argocd to deploy all pieces
  - `kubectl apply -f distribution/hawkeye.yaml`