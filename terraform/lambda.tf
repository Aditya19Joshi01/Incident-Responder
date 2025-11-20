# Lambda layer for dependencies
resource "aws_lambda_layer_version" "python_dependencies" {
  filename   = "${path.module}/../lambda_layer.zip"
  layer_name = "${var.project_name}-python-dependencies"

  compatible_runtimes = [var.lambda_runtime]

  source_code_hash = filebase64sha256("${path.module}/../lambda_layer.zip")
}

# Log Forensics Agent Lambda
resource "aws_lambda_function" "log_forensics_agent" {
  filename         = "${path.module}/../lambda_functions/log_forensics_agent.zip"
  function_name    = "${var.project_name}-log-forensics-agent"
  role             = aws_iam_role.lambda_execution_role.arn
  handler          = "log_forensics_agent.handler"
  runtime          = var.lambda_runtime
  timeout          = var.lambda_timeout
  memory_size      = var.lambda_memory_size
  layers           = [aws_lambda_layer_version.python_dependencies.arn]

  source_code_hash = filebase64sha256("${path.module}/../lambda_functions/log_forensics_agent.zip")

  environment {
    variables = {
      LOGS_BUCKET = aws_s3_bucket.log_storage.bucket
    }
  }

  tracing_config {
    mode = var.enable_xray ? "Active" : "PassThrough"
  }

  tags = {
    Name        = "${var.project_name}-log-forensics-agent"
    Agent       = "LogForensics"
  }
}

# Threat Attribution Agent Lambda
resource "aws_lambda_function" "threat_attribution_agent" {
  filename         = "${path.module}/../lambda_functions/threat_attribution_agent.zip"
  function_name    = "${var.project_name}-threat-attribution-agent"
  role             = aws_iam_role.lambda_execution_role.arn
  handler          = "threat_attribution_agent.handler"
  runtime          = var.lambda_runtime
  timeout          = var.lambda_timeout
  memory_size      = var.lambda_memory_size
  layers           = [aws_lambda_layer_version.python_dependencies.arn]

  source_code_hash = filebase64sha256("${path.module}/../lambda_functions/threat_attribution_agent.zip")

  tracing_config {
    mode = var.enable_xray ? "Active" : "PassThrough"
  }

  tags = {
    Name        = "${var.project_name}-threat-attribution-agent"
    Agent       = "ThreatAttribution"
  }
}

# Knowledge Retrieval Agent Lambda
resource "aws_lambda_function" "knowledge_retrieval_agent" {
  filename         = "${path.module}/../lambda_functions/knowledge_retrieval_agent.zip"
  function_name    = "${var.project_name}-knowledge-retrieval-agent"
  role             = aws_iam_role.lambda_execution_role.arn
  handler          = "knowledge_retrieval_agent.handler"
  runtime          = var.lambda_runtime
  timeout          = var.lambda_timeout
  memory_size      = var.lambda_memory_size
  layers           = [aws_lambda_layer_version.python_dependencies.arn]

  source_code_hash = filebase64sha256("${path.module}/../lambda_functions/knowledge_retrieval_agent.zip")

  environment {
    variables = {
      MITRE_EMBEDDINGS_BUCKET = aws_s3_bucket.log_storage.bucket
      OPENAI_API_KEY          = "" # Set via AWS Secrets Manager in production
    }
  }

  tracing_config {
    mode = var.enable_xray ? "Active" : "PassThrough"
  }

  tags = {
    Name        = "${var.project_name}-knowledge-retrieval-agent"
    Agent       = "KnowledgeRetrieval"
  }
}

# Remediation Agent Lambda
resource "aws_lambda_function" "remediation_agent" {
  filename         = "${path.module}/../lambda_functions/remediation_agent.zip"
  function_name    = "${var.project_name}-remediation-agent"
  role             = aws_iam_role.lambda_execution_role.arn
  handler          = "remediation_agent.handler"
  runtime          = var.lambda_runtime
  timeout          = var.lambda_timeout
  memory_size      = var.lambda_memory_size
  layers           = [aws_lambda_layer_version.python_dependencies.arn]

  source_code_hash = filebase64sha256("${path.module}/../lambda_functions/remediation_agent.zip")

  tracing_config {
    mode = var.enable_xray ? "Active" : "PassThrough"
  }

  tags = {
    Name        = "${var.project_name}-remediation-agent"
    Agent       = "Remediation"
  }
}

# CloudWatch Log Groups
resource "aws_cloudwatch_log_group" "log_forensics_agent" {
  name              = "/aws/lambda/${aws_lambda_function.log_forensics_agent.function_name}"
  retention_in_days = 14
}

resource "aws_cloudwatch_log_group" "threat_attribution_agent" {
  name              = "/aws/lambda/${aws_lambda_function.threat_attribution_agent.function_name}"
  retention_in_days = 14
}

resource "aws_cloudwatch_log_group" "knowledge_retrieval_agent" {
  name              = "/aws/lambda/${aws_lambda_function.knowledge_retrieval_agent.function_name}"
  retention_in_days = 14
}

resource "aws_cloudwatch_log_group" "remediation_agent" {
  name              = "/aws/lambda/${aws_lambda_function.remediation_agent.function_name}"
  retention_in_days = 14
}

