variable "DataSetName" {
    type = string
    description = "Your  Dataset Name, this name will be used to distinguish the task uniquey."
}

variable "vpcID" {
    type = string
    description = "Which VPC do you deploy ECS Task into?"
}

variable "subnetIDs" {
    type = list(string)
    description = "Which VPC do you deploy ECS Task into?"
}


variable "dataset-s3-bucket" {
    type = string
    description = "The dataset s3 bucket name."
}

variable "securityGroups" {
    type = list
    description = "The security group will be attached with lambda,ecs task"
}

variable "DatabaseName" {
    type = string
    description = "Please generate the  DatabaseName as per  naming specification"
}