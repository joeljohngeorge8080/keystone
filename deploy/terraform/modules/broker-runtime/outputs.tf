output "role_arn" {
  value = aws_iam_role.broker.arn
}

output "role_name" {
  value = aws_iam_role.broker.name
}

output "instance_profile_name" {
  value = try(aws_iam_instance_profile.broker[0].name, null)
}
