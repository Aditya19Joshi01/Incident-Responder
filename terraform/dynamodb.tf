# DynamoDB table for incident reports
resource "aws_dynamodb_table" "incident_reports" {
  name           = "${var.project_name}-incident-reports"
  billing_mode   = "PAY_PER_REQUEST" # On-demand pricing (free tier eligible)
  hash_key       = "id"

  attribute {
    name = "id"
    type = "S"
  }

  attribute {
    name = "timestamp"
    type = "S"
  }

  global_secondary_index {
    name     = "timestamp-index"
    hash_key = "timestamp"
  }

  tags = {
    Name = "${var.project_name}-incident-reports"
  }
}

