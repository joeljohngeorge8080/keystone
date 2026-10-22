output "bucket_name" {
  value = aws_s3_bucket.anchors.id
}

output "bucket_arn" {
  value = aws_s3_bucket.anchors.arn
}
