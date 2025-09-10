{{/*
Expand the name of the chart.
*/}}
{{- define "chm.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "chm.fullname" -}}
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
{{- define "chm.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "chm.labels" -}}
helm.sh/chart: {{ include "chm.chart" . }}
{{ include "chm.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "chm.selectorLabels" -}}
app.kubernetes.io/name: {{ include "chm.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "chm.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "chm.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Database URL
*/}}
{{- define "chm.databaseUrl" -}}
{{- if .Values.postgresql.enabled }}
{{- printf "postgresql://%s:%s@%s-postgresql:5432/%s" .Values.postgresql.auth.username .Values.postgresql.auth.password (include "chm.fullname" .) .Values.postgresql.auth.database }}
{{- else }}
{{- .Values.app.secretEnv.DATABASE_URL }}
{{- end }}
{{- end }}

{{/*
Redis URL
*/}}
{{- define "chm.redisUrl" -}}
{{- if .Values.redis.enabled }}
{{- printf "redis://%s-redis-master:6379/0" (include "chm.fullname" .) }}
{{- else }}
{{- .Values.app.env.REDIS_URL | default "redis://redis:6379/0" }}
{{- end }}
{{- end }}

{{/*
Celery Broker URL
*/}}
{{- define "chm.celeryBrokerUrl" -}}
{{- if .Values.redis.enabled }}
{{- printf "redis://%s-redis-master:6379/1" (include "chm.fullname" .) }}
{{- else }}
{{- .Values.app.env.CELERY_BROKER_URL | default "redis://redis:6379/1" }}
{{- end }}
{{- end }}

{{/*
Celery Result Backend
*/}}
{{- define "chm.celeryResultBackend" -}}
{{- if .Values.redis.enabled }}
{{- printf "redis://%s-redis-master:6379/2" (include "chm.fullname" .) }}
{{- else }}
{{- .Values.app.env.CELERY_RESULT_BACKEND | default "redis://redis:6379/2" }}
{{- end }}
{{- end }}