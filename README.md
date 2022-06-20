# CF-Centralized-Logging-TF Notes 📝 

---
```
terraform init
```
- to initialize the template
---

```
terraform plan 
```
- to run the planner, see the changes before deploying
---

```
terraform apply --auto-approve
```
- to deploy the resources to the cloud
---

```
terraform apply -var "region=us-east-1" --auto-approve
```
- to apply changes while passing in vars in the cli
---

```
terraform destroy
```
- to delete/terminate the resources in the cloud
---

```
terraform apply -target
```
- to apply a specific resource
---

```
terraform destroy -target
```
- to delete a specific resource
---

```
terraform refresh
```
- for printing the output values without deploying the resources.
---

```
terraform output
```
- to see the outputs if any.

