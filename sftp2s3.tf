provider "aws" {
  region = "cn-north-1"
}

#- Step 0: Upload the sftp2s3 configuration file to the buckets
resource "aws_s3_bucket" "confBucket" {
  bucket = join("-", [replace(lower(var.DataSetName), "_", "-"), "conf"])
}


resource "aws_s3_bucket_object" "sftp2s3-conf" {
  bucket = aws_s3_bucket.confBucket.bucket
  key    = "sftp2s3.conf"
  source = "./sftp2s3.conf"
  etag   = filemd5("./sftp2s3.conf")
}

#- Step 1: Create the Elastic Container Registry and Cluster
data "aws_caller_identity" "current" {}

resource "aws_ecr_repository" "sftp2s3" {
  name = "${var.DataSetName}-sftp2s3"

  provisioner "local-exec" {
    command = "cd .terraform/modules/sftp2s3/sftp2s3-Docker && aws ecr get-login-password --region cn-north-1 | docker login --username AWS --password-stdin ${data.aws_caller_identity.current.account_id}.dkr.ecr.cn-north-1.amazonaws.com.cn"
  }

  provisioner "local-exec" {
    command = "cd .terraform/modules/sftp2s3/sftp2s3-Docker && docker build -t ${var.DataSetName}-sftp2s3 ."
  }

  provisioner "local-exec" {
    command = "cd .terraform/modules/sftp2s3/sftp2s3-Docker && docker tag ${var.DataSetName}-sftp2s3:latest ${data.aws_caller_identity.current.account_id}.dkr.ecr.cn-north-1.amazonaws.com.cn/${var.DataSetName}-sftp2s3:latest"
  }

  provisioner "local-exec" {
    command = "cd .terraform/modules/sftp2s3/sftp2s3-Docker && docker push ${data.aws_caller_identity.current.account_id}.dkr.ecr.cn-north-1.amazonaws.com.cn/${var.DataSetName}-sftp2s3:latest"
  }
}


resource "aws_ecs_cluster" "ECS-DT-Clu" {
  name = "${var.DataSetName}-clu"
}


resource "aws_cloudwatch_log_group" "loggroup" {
  name = "${var.DataSetName}-loggroup"
}


data "aws_ecr_image" "sftp2s3-image" {
  repository_name = aws_ecr_repository.sftp2s3.name
  image_tag       = "latest"
}


data "aws_region" "current" {}


resource "aws_iam_role" "role_for_ecs_task" {
  name = "${var.DataSetName}-role-for-ecs-task"
  assume_role_policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Principal" : {
          "Service" : "ecs-tasks.amazonaws.com"
        },
        "Action" : "sts:AssumeRole"
      }
    ]
  })

}


resource "aws_iam_policy" "policy_for_ecs_task" {
  name        = "${var.DataSetName}-policy-for-ecs-task"
  path        = "/"
  description = "${var.DataSetName}-policy-for-ecs-task"
  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Action" : "s3:*",
        "Resource" : "*"
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "ecr:GetAuthorizationToken",
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        "Resource" : "*"
      },
      {
        "Action" : [
          "secretsmanager:*",
          "cloudformation:CreateChangeSet",
          "cloudformation:DescribeChangeSet",
          "cloudformation:DescribeStackResource",
          "cloudformation:DescribeStacks",
          "cloudformation:ExecuteChangeSet",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSubnets",
          "ec2:DescribeVpcs",
          "kms:DescribeKey",
          "kms:ListAliases",
          "kms:ListKeys",
          "lambda:ListFunctions",
          "tag:GetResources"
        ],
        "Effect" : "Allow",
        "Resource" : "*"
      }
    ]
  })
}


resource "aws_iam_policy_attachment" "ecs-task-policy-role-attach" {
  name       = "${var.DataSetName}-ecs-task-policy-role-attachment"
  roles      = [aws_iam_role.role_for_ecs_task.name]
  policy_arn = aws_iam_policy.policy_for_ecs_task.arn
}


resource "aws_ecs_task_definition" "sftp2s3" {
  family                   = "${var.DataSetName}-sftp2s3"
  task_role_arn            = aws_iam_role.role_for_ecs_task.arn
  execution_role_arn       = aws_iam_role.role_for_ecs_task.arn
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = "256"
  memory                   = "512"
  container_definitions = jsonencode([
    {
      name      = "${var.DataSetName}-sftp2s3-c1"
      image     = join(":", [aws_ecr_repository.sftp2s3.repository_url, "latest"])
      essential = true
      "environment" : [
        {
          "name" : "SecretName",
          "value" : aws_secretsmanager_secret.Secret-sftp2s3.name
        },
        {
          "name" : "JobConf",
          "value" : "${aws_s3_bucket.confBucket.bucket}/${aws_s3_bucket_object.sftp2s3-conf.key}"
        },
        {
          "name" : "Region",
          "value" : data.aws_region.current.name
        }
      ],
      "logConfiguration" : {
        "logDriver" : "awslogs",
        "options" : {
          "awslogs-region" : data.aws_region.current.name,
          "awslogs-group" : aws_cloudwatch_log_group.loggroup.name,
          "awslogs-stream-prefix" : "${var.DataSetName}-sftp2s3"
        }
      }
    }
  ])
}


#- Step 2: Create the secrets to save the senstive informatioon
resource "aws_secretsmanager_secret" "Secret-sftp2s3" {
  name = "${var.DataSetName}-secret-sftp2s3"
}


variable "sftp2s3_keys" {
  default = {
    sftp_password     = "Replace Me using your sftp password"
    sftp_private_key  = "Replace Me using your sftp private key"
    access_key_id     = "Replace Me using your aws access key"
    secret_access_key = "Replace Me using your aws access secret key"
  }
  type = map(string)
}


resource "aws_secretsmanager_secret_version" "sftp2s3-secret-version" {
  secret_id     = aws_secretsmanager_secret.Secret-sftp2s3.id
  secret_string = jsonencode(var.sftp2s3_keys)
}

#- Step 3: Create the bucket to save the Glue and Lambda scripts
resource "aws_s3_bucket" "GlueLambdaBucket" {
  bucket = join("-", [replace(lower(var.DataSetName), "_", "-"), "scripts"])
}


#- Step 4: Create the lambda to invoke the Glue crawler and ETL job
resource "aws_iam_role" "role_for_lambda" {
  name = "${var.DataSetName}-role-for-lambda"
  assume_role_policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Principal" : {
          "Service" : "lambda.amazonaws.com"
        },
        "Action" : "sts:AssumeRole"
      }
    ]
  })
}


resource "aws_iam_policy" "policy_for_lambda" {
  name        = "${var.DataSetName}-policy-for-lambda"
  path        = "/"
  description = "${var.DataSetName}-policy-for-lambda"
  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Action" : [
          "ec2:CreateNetworkInterface",
          "ec2:DeleteNetworkInterface",
          "ec2:DescribeNetworkInterfaces",
          "glue:StartJobRun",
          "glue:StartCrawler"
        ],
        "Resource" : "*"
      }
    ]
  })
}


resource "aws_iam_policy_attachment" "lambda_policy_role_attach" {
  name       = "lambda_policy_role_attachment"
  policy_arn = aws_iam_policy.policy_for_lambda.arn
  roles      = [aws_iam_role.role_for_lambda.name]
}

# Upload the lambda function files to bucket.
resource "aws_s3_bucket_object" "CrawlerLambdaFunctionFile" {
  bucket = aws_s3_bucket.GlueLambdaBucket.bucket
  key    = "${aws_s3_bucket.GlueLambdaBucket.bucket}/CallCrawler.zip"
  source = "./.terraform/modules/sftp2s3/code/CallCrawler.zip"
  etag   = filemd5("./.terraform/modules/sftp2s3/code/CallCrawler.zip")
}


resource "aws_lambda_function" "CallCrawler" {
  function_name    = "${var.DataSetName}-CallCrawler"
  runtime          = "python3.8"
  publish          = true
  role             = aws_iam_role.role_for_lambda.arn
  s3_bucket        = aws_s3_bucket.GlueLambdaBucket.bucket
  s3_key           = "${aws_s3_bucket.GlueLambdaBucket.bucket}/CallCrawler.zip"
  source_code_hash = filebase64sha256("./.terraform/modules/sftp2s3/code/CallCrawler.zip")
  handler          = "CallCrawler.lambda_handler"
  vpc_config {
    subnet_ids         = var.subnetIDs
    security_group_ids = var.securityGroups
  }
}


resource "aws_s3_bucket_object" "ETLLambdaFunctionFile" {
  bucket = aws_s3_bucket.GlueLambdaBucket.bucket
  key    = "${aws_s3_bucket.GlueLambdaBucket.bucket}/CallETL.zip"
  source = "./.terraform/modules/sftp2s3/code/CallETL.zip"
  etag   = filemd5("./.terraform/modules/sftp2s3/code/CallCrawler.zip")
}


resource "aws_lambda_function" "CallETL" {
  function_name    = "${var.DataSetName}-CallETL"
  runtime          = "python3.8"
  publish          = true
  role             = aws_iam_role.role_for_lambda.arn
  s3_bucket        = aws_s3_bucket.GlueLambdaBucket.bucket
  s3_key           = "${aws_s3_bucket.GlueLambdaBucket.bucket}/CallETL.zip"
  source_code_hash = filebase64sha256("./.terraform/modules/sftp2s3/code/CallETL.zip")
  handler          = "CallETL.lambda_handler"
  vpc_config {
    subnet_ids         = var.subnetIDs
    security_group_ids = var.securityGroups
  }
}


#- Step 5: Create the Glue crawler and ETL job
resource "aws_glue_crawler" "CrawlerS3" {
  database_name = var.DatabaseName
  name          = "${var.DataSetName}-crawler"
  role          = aws_iam_role.sftp2s3-glue-role.name
  s3_target {
    path = var.-dataset-s3-bucket
  }
  configuration = jsonencode({
    "Version" : 1.0,
    "Grouping" : {
      "TableGroupingPolicy" : "CombineCompatibleSchemas"
    }
  })
  schema_change_policy {
    delete_behavior = "DELETE_FROM_DATABASE"
    update_behavior = "UPDATE_IN_DATABASE"
  }
}


resource "aws_s3_bucket_object" "object" {
  bucket = aws_s3_bucket.GlueLambdaBucket.bucket
  key    = "etl.py"
  source = "./.terraform/modules/sftp2s3/code/etl.py"
  etag   = filemd5("./.terraform/modules/sftp2s3/code/etl.py")
}

resource "aws_iam_role" "sftp2s3-glue-role" {
  name = "${var.DataSetName}-sftp2s3-glue-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "glue.amazonaws.com"
        }
      },
    ]
  })
}

resource "aws_iam_policy" "sftp2s3-glue-policy" {
  name        = "${var.DataSetName}-sftp2s3-glue-policy"
  path        = "/"
  description = "${var.DataSetName}-sftp2s3-glue-policy"
  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Action" : [
          "glue:*",
          "s3:GetBucketLocation",
          "s3:ListBucket",
          "s3:ListAllMyBuckets",
          "s3:GetBucketAcl",
          "ec2:DescribeVpcEndpoints",
          "ec2:DescribeRouteTables",
          "ec2:CreateNetworkInterface",
          "ec2:DeleteNetworkInterface",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSubnets",
          "ec2:DescribeVpcAttribute",
          "iam:ListRolePolicies",
          "iam:GetRole",
          "iam:GetRolePolicy",
          "cloudwatch:PutMetricData"
        ],
        "Resource" : [
          "*"
        ]
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "s3:CreateBucket"
        ],
        "Resource" : [
          "arn:aws-cn:s3:::aws-glue-*"
        ]
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ],
        "Resource" : [
          "arn:aws-cn:s3:::aws-glue-*/*",
          "arn:aws-cn:s3:::*/*aws-glue-*/*"
        ]
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "s3:GetObject"
        ],
        "Resource" : [
          "arn:aws-cn:s3:::crawler-public*",
          "arn:aws-cn:s3:::aws-glue-*"
        ]
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        "Resource" : [
          "arn:aws-cn:logs:*:*:/aws-glue/*"
        ]
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "ec2:CreateTags",
          "ec2:DeleteTags"
        ],
        "Condition" : {
          "ForAllValues:StringEquals" : {
            "aws:TagKeys" : [
              "aws-glue-service-resource"
            ]
          }
        },
        "Resource" : [
          "arn:aws-cn:ec2:*:*:network-interface/*",
          "arn:aws-cn:ec2:*:*:security-group/*",
          "arn:aws-cn:ec2:*:*:instance/*"
        ]
      }
    ]
  })
}

resource "aws_iam_policy_attachment" "sftp2s3-glue-role-policy-attach" {
  name       = "${var.DataSetName}-sftp2s3-glue-role-policy-attach"
  roles      = [aws_iam_role.sftp2s3-glue-role.name]
  policy_arn = aws_iam_policy.sftp2s3-glue-policy.arn
}


data "aws_availability_zones" "azs" {
  all_availability_zones = true
}


data "aws_subnet" "subneta" {
  id = var.subnetIDs[0]
}


resource "aws_glue_connection" "ETLConn" {
  name            = "${var.DataSetName}-Connection"
  connection_type = "NETWORK"
  connection_properties = {
    "JDBC_ENFORCE_SSL" : "false"
  }
  physical_connection_requirements {
    security_group_id_list = var.securityGroups
    availability_zone      = data.aws_availability_zones.azs.names[0]
    subnet_id              = data.aws_subnet.subneta.id
  }
}


resource "aws_glue_job" "ProcessS3Data" {
  name     = "${var.DataSetName}-GlueETLJob"
  role_arn = aws_iam_role.sftp2s3-glue-role.arn
  command {
    script_location = "s3://${aws_s3_bucket.GlueLambdaBucket.bucket}/etl.py"
  }
  connections = [aws_glue_connection.ETLConn.name]
}


#- Step 6: Create the Cloudwatch Event rule to trigger the lambda and ECS task.
data "aws_ecs_cluster" "ECS-DT-Clu" {
  cluster_name = aws_ecs_cluster.ECS-DT-Clu.name
}


data "aws_ecs_task_definition" "sftp2s3" {
  task_definition = aws_ecs_task_definition.sftp2s3.family
}


resource "aws_iam_role" "CW-Invoke-ECS-Role" {
  name = "${var.DataSetName}-CW-Invoke-ECS-Role"
  assume_role_policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Principal" : {
          "Service" : "events.amazonaws.com"
        },
        "Action" : "sts:AssumeRole"
      }
    ]
  })
}


resource "aws_iam_policy" "CW-Invoke-ECS-Role-Policy" {
  name        = "${var.DataSetName}-CW-Invoke-ECS-Role-Policy"
  path        = "/"
  description = "${var.DataSetName}-CW-Invoke-ECS-Role-Policy"
  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Action" : [
          "ecs:RunTask"
        ],
        "Resource" : "*"
      },
      {
        "Effect" : "Allow",
        "Action" : [
          "ecr:GetAuthorizationToken",
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        "Resource" : "*"
      },
      {
        "Effect" : "Allow",
        "Action" : "iam:PassRole",
        "Resource" : "*",
        "Condition" : {
          "StringLike" : {
            "iam:PassedToService" : "ecs-tasks.amazonaws.com"
          }
        }
      }
    ]
  })
}


resource "aws_iam_policy_attachment" "cw-invoke-ecs-policy-role-attach" {
  name       = "${var.DataSetName}-cw-invoke-ecs-policy-role-attachment"
  roles      = [aws_iam_role.CW-Invoke-ECS-Role.name]
  policy_arn = aws_iam_policy.CW-Invoke-ECS-Role-Policy.arn
}


# Trigger the ECS task: sftp2s3 
resource "aws_cloudwatch_event_rule" "TiggerSFTP2S3-Rule" {
  name                = "${var.DataSetName}-Trigger-SFTP2S3-Rule"
  description         = "${var.DataSetName}-Trigger-SFTP2S3-Rule"
  schedule_expression = "cron(0 0 * * ? *)"
}

resource "aws_cloudwatch_event_target" "TiggerSFTP2S3-Rule-Target" {
  target_id = "${var.DataSetName}-cloudwatch-sftp2s3-target"
  arn       = aws_ecs_cluster.ECS-DT-Clu.arn
  role_arn  = aws_iam_role.CW-Invoke-ECS-Role.arn
  rule      = aws_cloudwatch_event_rule.TiggerSFTP2S3-Rule.name
  ecs_target {
    task_count          = 1
    task_definition_arn = aws_ecs_task_definition.sftp2s3.arn
    launch_type         = "FARGATE"
    network_configuration {
      subnets          = var.subnetIDs
      security_groups  = var.securityGroups
      assign_public_ip = true
    }
  }
}


# Trigger lambda to invoke the ETL job when the sftp2s3 ecs task was done
resource "aws_cloudwatch_event_rule" "TriggerLambdaInvokeETL-Rule" {
  name          = "${var.DataSetName}-LmdInvokeETL-Rule"
  description   = "${var.DataSetName}-LmdInvokeETL-Rule"
  event_pattern = <<EOF
{
  "source": [
    "aws.ecs"
  ],
  "detail-type": [
    "ECS Task State Change"
  ],
  "detail": {
    "clusterArn": [
      "${data.aws_ecs_cluster.ECS-DT-Clu.arn}"
    ],
    "taskDefinitionArn": [
      "${aws_ecs_task_definition.sftp2s3.arn}"
    ],
    "lastStatus": [
      "STOPPED"
    ],
    "launchType": [
      "FARGATE"
    ]
  }
}
EOF
}


resource "aws_lambda_permission" "allow_cloudwatch_calletl" {
  statement_id  = "${var.DataSetName}-AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.CallETL.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.TriggerLambdaInvokeETL-Rule.arn
}


resource "aws_cloudwatch_event_target" "TriggerLambdaInvokeETL-Rule-Target" {
  target_id = "${var.DataSetName}-cloudwatch-ETL-target"
  rule      = aws_cloudwatch_event_rule.TriggerLambdaInvokeETL-Rule.name
  arn       = aws_lambda_function.CallETL.arn
  input = jsonencode({
    "JOB" : aws_glue_job.ProcessS3Data.name
  })
}


# Trigger the lambda to invoke the crawler when the etl job was done
resource "aws_cloudwatch_event_rule" "TriggerLambdaInvokeCrawler-Rule" {
  name          = "${var.DataSetName}-LmdInvokeCrawler-Rule"
  description   = "${var.DataSetName}-LmdInvokeCrawler-Rule"
  event_pattern = <<EOF
{
  "source": [
    "aws.glue"
  ],
  "detail-type": [
    "Glue Job State Change"
  ],
  "detail": {
    "jobName": [
      "${aws_glue_job.ProcessS3Data.name}"
    ],
    "state": [
      "SUCCEEDED"
    ]
  }
}
EOF

}


resource "aws_lambda_permission" "allow_cloudwatch_callcrawler" {
  statement_id  = "${var.DataSetName}-AllowExecutionFromCloudWatch"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.CallCrawler.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.TriggerLambdaInvokeCrawler-Rule.arn
}


resource "aws_cloudwatch_event_target" "TriggerCrawler-Rule-Target" {
  target_id = "${var.DataSetName}-cloudwatch-Crawler-target"
  rule      = aws_cloudwatch_event_rule.TriggerLambdaInvokeCrawler-Rule.name
  arn       = aws_lambda_function.CallCrawler.arn
  input = jsonencode({
    "JOB" : aws_glue_crawler.CrawlerS3.name
  })
}