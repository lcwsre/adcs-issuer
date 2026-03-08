{{/*
Expand the name of the chart.
*/}}
{{- define "adcs-issuer.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "adcs-issuer.fullname" -}}
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
{{- define "adcs-issuer.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "adcs-issuer.labels" -}}
helm.sh/chart: {{ include "adcs-issuer.chart" . }}
{{ include "adcs-issuer.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "adcs-issuer.selectorLabels" -}}
app.kubernetes.io/name: {{ include "adcs-issuer.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
control-plane: controller-manager
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "adcs-issuer.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "adcs-issuer.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Webhook service name
*/}}
{{- define "adcs-issuer.webhookServiceName" -}}
{{- printf "%s-webhook" (include "adcs-issuer.fullname" .) }}
{{- end }}

{{/*
Return the full image reference including optional registry prefix.
Usage: {{ include "adcs-issuer.image" . }}
*/}}
{{- define "adcs-issuer.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- if .Values.image.registry -}}
{{- printf "%s/%s:%s" .Values.image.registry .Values.image.repository $tag -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}
{{- end }}

{{/*
Return the list of imagePullSecrets, combining existing secrets and the auto-created registry secret.
*/}}
{{- define "adcs-issuer.imagePullSecrets" -}}
{{- $secrets := list -}}
{{- range .Values.imagePullSecrets -}}
{{- $secrets = append $secrets . -}}
{{- end -}}
{{- if .Values.imageCredentials.create -}}
{{- $name := default (printf "%s-registry" (include "adcs-issuer.fullname" .)) .Values.imageCredentials.name -}}
{{- $secrets = append $secrets (dict "name" $name) -}}
{{- end -}}
{{- if $secrets -}}
imagePullSecrets:
{{- range $secrets }}
  - name: {{ .name }}
{{- end }}
{{- end -}}
{{- end }}
