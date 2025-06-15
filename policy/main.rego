package terraform.policy



deny[msg] {
  resource := input.resource_changes[_]
  required_tags := ["Name", "Environment", "Owner"]

  tag := required_tags[_]
  not resource.change.after.tags[tag]

  msg = sprintf("Missing required tag '%s' on resource %s", [tag, resource.address])
}

/*
deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_instance"

  not resource.change.after.tags["Name"]
  msg = sprintf("Missing 'Name' tag for resource: %s", [resource.address])
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_instance"

  not resource.change.after.tags["Environment"]
  msg = sprintf("Missing 'Environment' tag for resource: %s", [resource.address])
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_instance"

  not resource.change.after.tags["Owner"]
  msg = sprintf("Missing 'Owner' tag for resource: %s", [resource.address])
}
*/