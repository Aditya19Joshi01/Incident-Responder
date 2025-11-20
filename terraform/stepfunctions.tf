# Step Functions state machine definition
locals {
  state_machine_definition = jsonencode({
    Comment = "Incident Responder AI - Multi-Agent Workflow"
    StartAt = "LogForensicsAgent"
    States = {
      LogForensicsAgent = {
        Type     = "Task"
        Resource = aws_lambda_function.log_forensics_agent.arn
        Next     = "ThreatAttributionAgent"
        Retry = [
          {
            ErrorEquals     = ["States.TaskFailed"]
            IntervalSeconds = 2
            MaxAttempts     = 3
            BackoffRate     = 2.0
          }
        ]
      }
      ThreatAttributionAgent = {
        Type     = "Task"
        Resource = aws_lambda_function.threat_attribution_agent.arn
        InputPath = "$"
        ResultPath = "$.attribution"
        Next     = "KnowledgeRetrievalAgent"
        Retry = [
          {
            ErrorEquals     = ["States.TaskFailed"]
            IntervalSeconds = 2
            MaxAttempts     = 3
            BackoffRate     = 2.0
          }
        ]
      }
      KnowledgeRetrievalAgent = {
        Type     = "Task"
        Resource = aws_lambda_function.knowledge_retrieval_agent.arn
        InputPath = "$"
        ResultPath = "$.knowledge"
        Next     = "RemediationAgent"
        Retry = [
          {
            ErrorEquals     = ["States.TaskFailed"]
            IntervalSeconds = 2
            MaxAttempts     = 3
            BackoffRate     = 2.0
          }
        ]
      }
      RemediationAgent = {
        Type     = "Task"
        Resource = aws_lambda_function.remediation_agent.arn
        InputPath = "$"
        ResultPath = "$.remediation"
        End      = true
        Retry = [
          {
            ErrorEquals     = ["States.TaskFailed"]
            IntervalSeconds = 2
            MaxAttempts     = 3
            BackoffRate     = 2.0
          }
        ]
      }
    }
  })
}

# Step Functions state machine
resource "aws_sfn_state_machine" "incident_responder_workflow" {
  name     = "${var.project_name}-workflow"
  role_arn = aws_iam_role.stepfunctions_execution_role.arn

  definition = local.state_machine_definition

  logging_configuration {
    log_destination        = "${aws_cloudwatch_log_group.stepfunctions.arn}:*"
    include_execution_data = true
    level                  = "ALL"
  }

  tags = {
    Name = "${var.project_name}-workflow"
  }
}

# CloudWatch Log Group for Step Functions
resource "aws_cloudwatch_log_group" "stepfunctions" {
  name              = "/aws/vendedlogs/states/${var.project_name}-workflow"
  retention_in_days = 14
}

