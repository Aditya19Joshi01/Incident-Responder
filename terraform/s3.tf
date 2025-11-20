# S3 bucket for log storage
resource "aws_s3_bucket" "log_storage" {
  bucket = "${var.project_name}-logs-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name = "${var.project_name}-log-storage"
  }
}

# S3 bucket versioning
resource "aws_s3_bucket_versioning" "log_storage" {
  bucket = aws_s3_bucket.log_storage.id

  versioning_configuration {
    status = "Enabled"
  }
}

# S3 bucket encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "log_storage" {
  bucket = aws_s3_bucket.log_storage.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# S3 bucket public access block
resource "aws_s3_bucket_public_access_block" "log_storage" {
  bucket = aws_s3_bucket.log_storage.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# S3 bucket for reports
resource "aws_s3_bucket" "reports_storage" {
  bucket = "${var.project_name}-reports-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name = "${var.project_name}-reports-storage"
  }
}

# S3 bucket versioning for reports
resource "aws_s3_bucket_versioning" "reports_storage" {
  bucket = aws_s3_bucket.reports_storage.id

  versioning_configuration {
    status = "Enabled"
  }
}

# S3 bucket encryption for reports
resource "aws_s3_bucket_server_side_encryption_configuration" "reports_storage" {
  bucket = aws_s3_bucket.reports_storage.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# S3 bucket public access block for reports
resource "aws_s3_bucket_public_access_block" "reports_storage" {
  bucket = aws_s3_bucket.reports_storage.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

