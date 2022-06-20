# CF-Centralized-Logging-TF Notes 📝 

```
terraform init
```

```
terraform plan 
```

```
terraform apply --auto-approve
```

```
terraform apply -var "region=us-east-1" --auto-approve
```
- to apply changes while passing in vars in the cli

```
terraform destroy
```

```
terraform apply -target
```
- to apply a specific resource

```
terraform destroy -target
```
- to delete a specific resource

```
terraform refresh
```
- for printing the output values without deploying anything.

```
terraform output
```
- to see the outputs if any.

