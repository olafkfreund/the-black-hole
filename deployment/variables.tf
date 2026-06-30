variable "aws_region" {
  type        = string
  description = "The AWS region to deploy resources to"
  default     = "us-west-2"
}

variable "aws_profile" {
  type        = string
  description = "The AWS CLI profile to use (leave null to use default/environment-defined credentials)"
  default     = null
}

variable "environment" {
  type        = string
  description = "The deployment environment (e.g. dev, staging, prod)"
  default     = "dev"
}

variable "vpc_cidr" {
  type        = string
  description = "CIDR block for the custom VPC"
  default     = "10.0.0.0/16"
}

variable "public_subnets" {
  type        = list(string)
  description = "CIDR blocks for the VPC public subnets"
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "private_subnets" {
  type        = list(string)
  description = "CIDR blocks for the VPC private subnets"
  default     = ["10.0.10.0/24", "10.0.11.0/24"]
}

variable "cluster_name" {
  type        = string
  description = "Name of the EKS cluster"
  default     = "mcp-gateway-cluster"
}

variable "cluster_version" {
  type        = string
  description = "Target Kubernetes version for EKS"
  default     = "1.29"
}

variable "node_instance_types" {
  type        = list(string)
  description = "EC2 instance types for EKS managed node group"
  default     = ["t3.medium"]
}

variable "node_desired_size" {
  type        = number
  description = "Desired number of worker nodes in EKS cluster"
  default     = 2
}

variable "node_max_size" {
  type        = number
  description = "Maximum number of worker nodes in EKS cluster"
  default     = 3
}

variable "node_min_size" {
  type        = number
  description = "Minimum number of worker nodes in EKS cluster"
  default     = 1
}

variable "cluster_endpoint_public_access" {
  type        = bool
  description = "Whether the EKS public API endpoint is enabled. Prefer false and access via VPN/bastion."
  default     = false
}

variable "cluster_endpoint_public_access_cidrs" {
  type        = list(string)
  description = "CIDR blocks allowed to reach the public EKS API endpoint (when enabled). Do not use 0.0.0.0/0."
  default     = []
}
