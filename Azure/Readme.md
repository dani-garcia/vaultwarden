# Creates a Vaultwarden Container App within Azurefile external storage

[![Deploy To Azure](https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/1-CONTRIBUTION-GUIDE/images/deploytoazure.svg?sanitize=true)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fadamhnat%2Fvaultwarden%2Fmain%2FAzure%2Fmain.json)
[![Visualize](https://raw.githubusercontent.com/Azure/azure-quickstart-templates/master/1-CONTRIBUTION-GUIDE/images/visualizebutton.svg?sanitize=true)](http://armviz.io/#/?load=https%3A%2F%2Fraw.githubusercontent.com%2Fadamhnat%2Fvaultwarden%2Fmain%2FAzure%2Fmain.json)

This template provides a way to deploy a **Vaultwarden** in a **Azure Container App** with external **file share** storage that can be used to backup restore data easly.

Deploy:
1. Click above button and select 
- Resource Group - all resources will be created in that group, you can choose also to create new one
- Storage Account Type - in case that you you like to be more resistant for failure you may choose Standard_GRS or any other storage with redundancy.
- AdminAPI Key - it will be generated automaticly or you can specify your own one. It will be used to access /admin page
- Choose memory and cpu sizing - I recommend to start with 0.25 cpu and 0.5 Memory 
    The total CPU and memory allocations requested for all the containers in a container app must add up to one of the following combinations.
    vCPUs (cores) 	Memory
    0.25 	0.5Gi
    0.5 	1.0Gi
    0.75 	1.5Gi
    1.0 	2.0Gi
    1.25 	2.5Gi
    1.5 	3.0Gi
    1.75 	3.5Gi
    2.0 	4.0Gi
- **Deploy**
- copy db.sqlite3 (empty database, with WAL off) into fileshare (deployment bug - vaultwarden cannot create new database in SMB share)

2. Resource vaultwarden Microsoft.App/containerApps failed - if in some case you will notice failed message, just click **redeploy** and reenter same data as before - it may happen when Azure provision resources and link to storage isn't created at time.

Updating to new version:
in Azure Portal:
- Open Resource Group -> vaultwarden -> Revision management -> **Create revision** -> type name/suffix -> check vaultwarden in Container image section -> **create**
  This will update your vaultwarden container app into most recent version, keeping data in place, in no downtime.

Get Admin key:
- Resource Group -> vaultwarden -> Containers -> Environment Variables -> double click on ADMIN_TOKEN **value**

Restore your backup into Azure Contaier App:
- The storage is accesible via SMB in contaner it means that sqlite WAL needs to be turned off, make sure before put database in fileshare that you turned off WAL [Running without WAL enabled](https://github.com/dani-garcia/vaultwarden/wiki/Running-without-WAL-enabled)