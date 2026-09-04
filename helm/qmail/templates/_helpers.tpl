{{/* qmail chart helpers */}}

{{- define "qmail.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "qmail.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "qmail.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{/* Render a values env dict as a ConfigMap data block */}}
{{- define "qmail.envdata" -}}
{{- range $k, $v := . -}}
  {{ $k }}: {{ $v | default "" | quote }}
{{- end -}}
{{- end -}}
