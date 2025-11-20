output "lambda_functions" {
  description = "Lambda function ARNs"
  value = {
    log_forensics_agent      = aws_lambda_function.log_forensics_agent.arn
    threat_attribution_agent = aws_lambda_function.threat_attribution_agent.arn
    knowledge_retrieval_agent = aws_lambda_function.knowledge_retrieval_agent.arn
    remediation_agent        = aws_lambda_function.remediation_agent.arn
  }
}

output "stepfunctions_state_machine_arn" {
  description = "Step Functions state machine ARN"
  value       = aws_sfn_state_machine.incident_responder_workflow.arn
}

output "dynamodb_table_name" {
  description = "DynamoDB table name for incident reports"
  value       = aws_dynamodb_table.incident_reports.name
}

output "dynamodb_table_arn" {
  description = "DynamoDB table ARN"
  value       = aws_dynamodb_table.incident_reports.arn
}

output "s3_log_bucket" {
  description = "S3 bucket for log storage"
  value       = aws_s3_bucket.log_storage.bucket
}

output "s3_reports_bucket" {
  description = "S3 bucket for reports storage"
  value       = aws_s3_bucket.reports_storage.bucket
}

output "iam_role_arn" {
  description = "IAM role ARN for Lambda execution"
  value       = aws_iam_role.lambda_execution_role.arn
}

