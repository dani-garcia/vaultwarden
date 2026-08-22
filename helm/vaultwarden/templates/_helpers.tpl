{{/*
Expand the name of the chart.
*/}}
{{- define "vaultwarden.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "vaultwarden.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "vaultwarden.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "vaultwarden.labels" -}}
helm.sh/chart: {{ include "vaultwarden.chart" . }}
{{ include "vaultwarden.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "vaultwarden.selectorLabels" -}}
app.kubernetes.io/name: {{ include "vaultwarden.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use.
*/}}
{{- define "vaultwarden.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "vaultwarden.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Return the appropriate image tag.
*/}}
{{- define "vaultwarden.imageTag" -}}
{{- default .Chart.AppVersion .Values.image.tag }}
{{- end }}

{{/*
Return the secret name for admin token.
*/}}
{{- define "vaultwarden.adminSecretName" -}}
{{- if .Values.vaultwarden.admin.existingSecret }}
{{- .Values.vaultwarden.admin.existingSecret }}
{{- else }}
{{- printf "%s-admin" (include "vaultwarden.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Return the secret name for SMTP credentials.
*/}}
{{- define "vaultwarden.smtpSecretName" -}}
{{- if .Values.vaultwarden.smtp.existingSecret }}
{{- .Values.vaultwarden.smtp.existingSecret }}
{{- else }}
{{- printf "%s-smtp" (include "vaultwarden.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Return the secret name for SSO credentials.
*/}}
{{- define "vaultwarden.ssoSecretName" -}}
{{- if .Values.vaultwarden.sso.existingSecret }}
{{- .Values.vaultwarden.sso.existingSecret }}
{{- else }}
{{- printf "%s-sso" (include "vaultwarden.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Return the secret name for push notification credentials.
*/}}
{{- define "vaultwarden.pushSecretName" -}}
{{- if .Values.vaultwarden.push.existingSecret }}
{{- .Values.vaultwarden.push.existingSecret }}
{{- else }}
{{- printf "%s-push" (include "vaultwarden.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Return the secret name for Yubico credentials.
*/}}
{{- define "vaultwarden.yubicoSecretName" -}}
{{- if .Values.vaultwarden.yubico.existingSecret }}
{{- .Values.vaultwarden.yubico.existingSecret }}
{{- else }}
{{- printf "%s-yubico" (include "vaultwarden.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Return the secret name for database URL.
*/}}
{{- define "vaultwarden.databaseSecretName" -}}
{{- if .Values.database.existingSecret }}
{{- .Values.database.existingSecret }}
{{- else }}
{{- printf "%s-database" (include "vaultwarden.fullname" .) }}
{{- end }}
{{- end }}
