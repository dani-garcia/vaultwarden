{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}
{{- define "bitwardenrs.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "bitwardenrs.fullname" -}}
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
{{- define "bitwardenrs.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "bitwardenrs.labels" -}}
helm.sh/chart: {{ include "bitwardenrs.chart" . }}
{{ include "bitwardenrs.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "bitwardenrs.selectorLabels" -}}
app.kubernetes.io/name: {{ include "bitwardenrs.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "bitwardenrs.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "bitwardenrs.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Ensure valid DB type is select, defaults to SQLite
*/}}
{{- define "bitwardenrs.image" -}}
{{- if eq .Values.database.type "postgresql" }}
{{- .Values.image.postgresqlRepository -}}
{{- else if eq .Values.database.type "mysql" }}
{{- .Values.image.mysqlRepository -}}
{{- else if eq .Values.database.type "sqlite" }}
{{- .Values.image.sqliteRepository -}}
{{- else }}
{{- required "Invalid database type" nil }}
{{- end -}}
{{- end -}}

{{/*
Ensure log type is valid
*/}}
{{- define "bitwardenrs.logLevelValid" -}}
{{- if not (or (eq .Values.bitwardenrs.log.level "trace") (eq .Values.bitwardenrs.log.level "debug") (eq .Values.bitwardenrs.log.level "info") (eq .Values.bitwardenrs.log.level "warn") (eq .Values.bitwardenrs.log.level "error") (eq .Values.bitwardenrs.log.level "off")) }}
{{- required "Invalid log level" nil }}
{{- end }}
{{- end }}