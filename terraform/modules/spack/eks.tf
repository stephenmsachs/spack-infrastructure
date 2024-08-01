locals {
  cluster_name = "spack-${var.deployment_name}"
}

module "eks" {
  # https://registry.terraform.io/modules/terraform-aws-modules/eks/aws/latest
  source  = "terraform-aws-modules/eks/aws"
  version = "20.17.2"

  cluster_name    = local.cluster_name
  cluster_version = var.kubernetes_version

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  # Enables OIDC provider for cluster; required for Karpenter
  enable_irsa = true

  create_kms_key            = false
  cluster_encryption_config = {}

  cluster_endpoint_public_access = true

  node_security_group_additional_rules = {
    ingress_self_all = {
      description = "Node to node all ports/protocols"
      protocol    = "-1"
      from_port   = 0
      to_port     = 0
      type        = "ingress"
      self        = true # Only apply this rule to other nodes in this security group
    }
  }

  node_security_group_tags = {
    # NOTE - if creating multiple security groups with this module, only tag the
    # security group that Karpenter should utilize with the following tag
    # (i.e. - at most, only one security group should have this tag in your account)
    "karpenter.sh/discovery" = local.cluster_name
  }

  # Only need one node to get Karpenter up and running.
  # This ensures core services such as VPC CNI, CoreDNS, etc. are up and running
  # so that Karpenter can be deployed and start managing compute capacity as required
  eks_managed_node_groups = {
    initial = {
      instance_types = ["m5.large"]
      # Not required nor used - avoid tagging two security groups with same tag as well
      create_security_group = false

      # Ensure enough capacity to run 2 Karpenter pods
      min_size     = 2
      max_size     = 3
      desired_size = 2

      # Use same role as Karpenter nodes
      create_iam_role = false
      iam_role_arn    = module.karpenter.node_iam_role_arn

      taints = {
        critical-addons-only = {
          key    = "CriticalAddonsOnly"
          effect = "NO_SCHEDULE"
        }
      }
    }
  }

  cluster_addons = {
    aws-ebs-csi-driver = {
      addon_version            = "v1.20.0-eksbuild.1"
      service_account_role_arn = aws_iam_role.ebs_efs_csi_driver.arn
    }
    coredns = {
      addon_version = "v1.11.1-eksbuild.9"
    }
  }

  authentication_mode = "API_AND_CONFIG_MAP"
}

resource "aws_iam_role" "eks_cluster_access" {
  name = "SpackEKSClusterAccess-${var.deployment_name}"
  assume_role_policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Principal" : {
          "AWS" : [
            "arn:aws:iam::588562868276:user/scott",
            "arn:aws:iam::588562868276:user/jacob",
            "arn:aws:iam::588562868276:user/krattiger1",
            "arn:aws:iam::588562868276:user/mike",
            "arn:aws:iam::588562868276:user/zack",
            "arn:aws:iam::588562868276:user/dan",
            "arn:aws:iam::588562868276:user/william",
          ]
        },
        "Action" : "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role" "readonly_clusterrole" {
  name = "SpackEKSReadOnlyClusterAccess-${var.deployment_name}"
  assume_role_policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Principal" : {
          "AWS" : [
            "arn:aws:iam::588562868276:user/joesnyder",
            "arn:aws:iam::588562868276:user/alecscott",
            "arn:aws:iam::588562868276:user/tgamblin",
            "arn:aws:iam::588562868276:user/vsoch",
            "arn:aws:iam::588562868276:user/caetanomelone",
          ]
        },
        "Action" : "sts:AssumeRole"
      }
    ]
  })
}


resource "aws_iam_role" "ebs_efs_csi_driver" {
  name = "EbsEfsDriverRole-${var.deployment_name}"
  assume_role_policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Principal" : {
          "Federated" : module.eks.oidc_provider_arn
        },
        "Action" : "sts:AssumeRoleWithWebIdentity",
        "Condition" : {
          "StringEquals" : {
            "${module.eks.oidc_provider}:sub" : "system:serviceaccount:kube-system:ebs-csi-controller-sa",
            "${module.eks.oidc_provider}:aud" : "sts.amazonaws.com"
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "ebs_efs_csi_driver" {
  name = "EbsEfsDriverPolicy-${var.deployment_name}"
  role = aws_iam_role.ebs_efs_csi_driver.id
  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Action" : [
          "ec2:CreateSnapshot",
          "ec2:AttachVolume",
          "ec2:DetachVolume",
          "ec2:ModifyVolume",
          "ec2:DescribeAvailabilityZones",
          "ec2:DescribeInstances",
          "ec2:DescribeSnapshots",
          "ec2:DescribeTags",
          "ec2:DescribeVolumes",
          "ec2:DescribeVolumesModifications"
        ],
        "Resource" : "*"
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "ec2:CreateTags"
        ],
        "Resource" : [
          "arn:aws:ec2:*:*:volume/*",
          "arn:aws:ec2:*:*:snapshot/*"
        ],
        "Condition" : {
          "StringEquals" : {
            "ec2:CreateAction" : [
              "CreateVolume",
              "CreateSnapshot"
            ]
          }
        }
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "ec2:DeleteTags"
        ],
        "Resource" : [
          "arn:aws:ec2:*:*:volume/*",
          "arn:aws:ec2:*:*:snapshot/*"
        ]
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "ec2:CreateVolume"
        ],
        "Resource" : "*",
        "Condition" : {
          "StringLike" : {
            "aws:RequestTag/ebs.csi.aws.com/cluster" : "true"
          }
        }
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "ec2:CreateVolume"
        ],
        "Resource" : "*",
        "Condition" : {
          "StringLike" : {
            "aws:RequestTag/CSIVolumeName" : "*"
          }
        }
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "ec2:DeleteVolume"
        ],
        "Resource" : "*",
        "Condition" : {
          "StringLike" : {
            "ec2:ResourceTag/ebs.csi.aws.com/cluster" : "true"
          }
        }
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "ec2:DeleteVolume"
        ],
        "Resource" : "*",
        "Condition" : {
          "StringLike" : {
            "ec2:ResourceTag/CSIVolumeName" : "*"
          }
        }
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "ec2:DeleteVolume"
        ],
        "Resource" : "*",
        "Condition" : {
          "StringLike" : {
            "ec2:ResourceTag/kubernetes.io/created-for/pvc/name" : "*"
          }
        }
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "ec2:DeleteSnapshot"
        ],
        "Resource" : "*",
        "Condition" : {
          "StringLike" : {
            "ec2:ResourceTag/CSIVolumeSnapshotName" : "*"
          }
        }
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "ec2:DeleteSnapshot"
        ],
        "Resource" : "*",
        "Condition" : {
          "StringLike" : {
            "ec2:ResourceTag/ebs.csi.aws.com/cluster" : "true"
          }
        }
      }
    ]
  })
}

# Define a configmap that provides the EKS Cluster name
resource "kubectl_manifest" "cluster_name_config_map" {
  yaml_body = <<-YAML
    apiVersion: v1
    kind: ConfigMap
    metadata:
        name: cluster-info
        namespace: kube-system
    data:
        cluster-name: ${module.eks.cluster_name}
  YAML
}

# This ClusterRole and ClusterRoleBinding allow for read-only access to the
# Kubernetes cluster.
resource "kubectl_manifest" "readonly_clusterrole" {
  yaml_body = <<YAML
    apiVersion: rbac.authorization.k8s.io/v1
    kind: ClusterRole
    metadata:
      name: readonly-access
    rules:
    - apiGroups: ["*"]
      resources: ["*"]
      verbs: ["get", "list", "watch"]
  YAML
}

resource "kubectl_manifest" "readonly_clusterrolebinding" {
  yaml_body = <<YAML
    apiVersion: rbac.authorization.k8s.io/v1
    kind: ClusterRoleBinding
    metadata:
      name: readonly-access
    subjects:
    - kind: Group
      name: readonly-access
      apiGroup: rbac.authorization.k8s.io
    roleRef:
      kind: ClusterRole
      name: ${kubectl_manifest.readonly_clusterrole.name}
      apiGroup: rbac.authorization.k8s.io
    YAML
}

module "eks_aws_auth" {
  source  = "terraform-aws-modules/eks/aws//modules/aws-auth"
  version = "20.17.2"

  manage_aws_auth_configmap = true
  aws_auth_roles = [
    {
      rolearn  = module.eks.eks_managed_node_groups["initial"].iam_role_arn,
      username = "system:node:{{EC2PrivateDNSName}}",
      groups   = ["system:bootstrappers", "system:nodes"]
    },
    {
      # Admin/superuser access to the cluster
      rolearn  = aws_iam_role.eks_cluster_access.arn
      username = "admin"
      groups   = ["system:masters"]
    },
    {
      # Read-only access to the cluster (for users)
      rolearn  = aws_iam_role.readonly_clusterrole.arn,
      username = "readonly-access",
      # See the ClusterRole/ClusterRoleBinding at the bottom of
      # this file for the permissions given to this group
      groups = ["readonly-access"],
    },
    {
      # Read-only access to the cluster (for github actions)
      rolearn  = aws_iam_role.github_actions.arn,
      username = "github-actions",
      # See the ClusterRole/ClusterRoleBinding at the bottom of
      # this file for the permissions given to this group
      groups = ["readonly-access"],
    },
    # This is required for DNS resolution to work on Windows nodes.
    # See info about aws-auth configmap here - https://docs.aws.amazon.com/eks/latest/userguide/windows-support.html#enable-windows-support
    {
      rolearn  = module.eks.eks_managed_node_groups["windows"].iam_role_arn,
      username = "system:node:{{EC2PrivateDNSName}}",
      groups   = ["eks:kube-proxy-windows", "system:bootstrappers", "system:nodes"]
    }
  ]
}


resource "aws_iam_role" "vpc_cni" {
  name = "VpcCniPluginRole-${var.deployment_name}"
  assume_role_policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Principal" : {
          "Federated" : module.eks.oidc_provider_arn
        },
        "Action" : "sts:AssumeRoleWithWebIdentity",
        "Condition" : {
          "StringEquals" : {
            "${module.eks.oidc_provider}:sub" : "system:serviceaccount:kube-system:aws-node",
            "${module.eks.oidc_provider}:aud" : "sts.amazonaws.com"
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "vpc_cni" {
  role       = aws_iam_role.vpc_cni.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
}
