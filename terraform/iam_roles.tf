# IAM role for Lambda functions
resource "aws_iam_role" "lambda_execution_role" {
  name = "${var.project_name}-lambda-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name = "${var.project_name}-lambda-execution-role"
  }
}

# IAM policy for Lambda execution
resource "aws_iam_role_policy" "lambda_basic_execution" {
  name = "${var.project_name}-lambda-basic-execution"
  role = aws_iam_role.lambda_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

# IAM policy for GuardDuty access
resource "aws_iam_role_policy" "lambda_guardduty_access" {
  name = "${var.project_name}-lambda-guardduty-access"
  role = aws_iam_role.lambda_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "guardduty:GetFindings",
          "guardduty:ListFindings",
          "guardduty:GetDetector"
        ]
        Resource = "*"
      }
    ]
  })
}

# IAM policy for CloudTrail access
resource "aws_iam_role_policy" "lambda_cloudtrail_access" {
  name = "${var.project_name}-lambda-cloudtrail-access"
  role = aws_iam_role.lambda_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "cloudtrail:LookupEvents",
          "cloudtrail:GetEventSelectors"
        ]
        Resource = "*"
      }
    ]
  })
}

# IAM policy for VPC Flow Logs access
resource "aws_iam_role_policy" "lambda_flowlogs_access" {
  name = "${var.project_name}-lambda-flowlogs-access"
  role = aws_iam_role.lambda_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:FilterLogEvents",
          "logs:DescribeLogStreams"
        ]
        Resource = "*"
      }
    ]
  })
}

# IAM policy for DynamoDB access
resource "aws_iam_role_policy" "lambda_dynamodb_access" {
  name = "${var.project_name}-lambda-dynamodb-access"
  role = aws_iam_role.lambda_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "dynamodb:PutItem",
          "dynamodb:GetItem",
          "dynamodb:UpdateItem",
          "dynamodb:Query",
          "dynamodb:Scan"
        ]
        Resource = [
          aws_dynamodb_table.incident_reports.arn,
          "${aws_dynamodb_table.incident_reports.arn}/index/*"
        ]
      }
    ]
  })
}

# IAM policy for S3 access (for log storage)
resource "aws_iam_role_policy" "lambda_s3_access" {
  name = "${var.project_name}-lambda-s3-access"
  role = aws_iam_role.lambda_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.log_storage.arn,
          "${aws_s3_bucket.log_storage.arn}/*"
        ]
      }
    ]
  })
}

# IAM role for Step Functions
resource "aws_iam_role" "stepfunctions_execution_role" {
  name = "${var.project_name}-stepfunctions-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "states.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name = "${var.project_name}-stepfunctions-execution-role"
  }
}

# IAM policy for Step Functions to invoke Lambda
resource "aws_iam_role_policy" "stepfunctions_lambda_invoke" {
  name = "${var.project_name}-stepfunctions-lambda-invoke"
  role = aws_iam_role.stepfunctions_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "lambda:InvokeFunction"
        ]
        Resource = [
          aws_lambda_function.log_forensics_agent.arn,
          aws_lambda_function.threat_attribution_agent.arn,
          aws_lambda_function.knowledge_retrieval_agent.arn,
          aws_lambda_function.remediation_agent.arn
        ]
      }
    ]
  })
}

