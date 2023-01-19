@description('Storage Account type')
@allowed([
  'Premium_LRS'
  'Premium_ZRS'
  'Standard_GRS'
  'Standard_GZRS'
  'Standard_LRS'
  'Standard_RAGRS'
  'Standard_RAGZRS'
  'Standard_ZRS'
])
param storageAccountSKU string = 'Standard_LRS'

@description('Vaultwarden Admin API key used to access /admin page - minLength is 20')
@minLength(20)
@secure()
param AdminAPIKEY string = base64(newGuid())

@description('Number of CPU cores the container can use. Can be with a maximum of two decimals.')
@allowed([
  '0.25'
  '0.5'
  '0.75'
  '1'
  '1.25'
  '1.5'
  '1.75'
  '2'
])
param cpuCore string = '0.25'

@description('Amount of memory (in gibibytes, GiB) allocated to the container up to 4GiB. Can be with a maximum of two decimals. Ratio with CPU cores must be equal to 2.')
@allowed([
  '0.5'
  '1'
  '1.5'
  '2'
  '3'
  '3.5'
  '4'
])
param memorySize string = '0.5'

var logWorkspaceName  = 'vw-logwks${uniqueString(resourceGroup().id)}'
var storageAccountName  = 'vwstorage${uniqueString(resourceGroup().id)}'
var location = resourceGroup().location

resource storageaccount 'Microsoft.Storage/storageAccounts@2021-02-01' = {
  name: storageAccountName
  location: location
  kind: 'StorageV2'
  sku: {
    name: storageAccountSKU
  }
  properties:{
    accessTier: 'Hot'
    allowSharedKeyAccess: true
    allowBlobPublicAccess: true
  }
  resource fileshare 'fileServices@2022-09-01'={
    name: 'default'
    resource vwardendata 'shares@2022-09-01'={
      name: 'vw-data'
      properties:{
        accessTier: 'Hot'
      }
    }
  }  
}

resource logAnalyticsWorkspace 'Microsoft.OperationalInsights/workspaces@2020-10-01' = {
  name: logWorkspaceName
  location: location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 30
  }
}


resource containerAppEnv 'Microsoft.App/managedEnvironments@2022-06-01-preview'= {
  name: 'appenv-vaultwarden${uniqueString(resourceGroup().id)}'
  location: location
  sku:{
    name: 'Consumption'
  }
  properties:{
    appLogsConfiguration:{
      destination: 'log-analytics'
      logAnalyticsConfiguration:{
        customerId: logAnalyticsWorkspace.properties.customerId
        sharedKey: logAnalyticsWorkspace.listKeys().primarySharedKey
      }
    }
  }
  resource storegeLink 'storages@2022-06-01-preview'={
    name:'vw-data-link'
    properties:{
      azureFile:{
        accessMode: 'ReadWrite'
        accountKey: storageaccount.listKeys().keys[0].value
        shareName: 'vw-data'
        accountName: storageaccount.name
    }
  }
  }
}

resource vwardenApp 'Microsoft.App/containerApps@2022-06-01-preview'= {
  name: 'vaultwarden'
  location: location
  properties:{
    environmentId: containerAppEnv.id
    configuration:{
      ingress:{
        external: true
        targetPort: 80
        allowInsecure: true
        traffic:[
          {
            latestRevision: true
            weight: 100
          }
        ]
      }
    }
    template:{
      containers:[
        {
          name: 'vaultwarden'
          image: 'docker.io/vaultwarden/server:latest'
          resources:{
            cpu: json(cpuCore)
            memory: '${memorySize}Gi'
          }
          
          volumeMounts:[
            {
              volumeName: 'vwdatashare'
              mountPath: '/data'
            }
          ]
          env: [
            {
              name: 'ADMIN_TOKEN'
              value: AdminAPIKEY
            }
            {
              name: 'ENABLE_DB_WAL'
              value: 'false'
            }
          ]
        }
      ]
      volumes:[
        {
          name:'vwdatashare'
          storageName: 'vw-data-link'
          storageType: 'AzureFile'
        }
      ]
      scale:{
        minReplicas: 1
        maxReplicas: 4
      }
    }
  }
}
