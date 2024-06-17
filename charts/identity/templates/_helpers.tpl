{{/*
Expand the name of the chart.
*/}}
{{- define "unikorn.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "unikorn.fullname" -}}
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
{{- define "unikorn.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "unikorn.labels" -}}
helm.sh/chart: {{ include "unikorn.chart" . }}
{{ include "unikorn.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "unikorn.selectorLabels" -}}
app.kubernetes.io/name: {{ include "unikorn.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "unikorn.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "unikorn.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the container images
*/}}
{{- define "unikorn.defaultRepositoryPath" -}}
{{- if .Values.repository }}
{{- printf "%s/%s" .Values.repository .Values.organization }}
{{- else }}
{{- .Values.organization }}
{{- end }}
{{- end }}

{{- define "unikorn.image" -}}
{{- .Values.image | default (printf "%s/unikorn-identity:%s" (include "unikorn.defaultRepositoryPath" .) (.Values.tag | default .Chart.Version)) }}
{{- end }}

{{- define "unikorn.organizationControllerImage" -}}
{{- .Values.organizationController.image | default (printf "%s/unikorn-organization-controller:%s" (include "unikorn.defaultRepositoryPath" .) (.Values.tag | default .Chart.Version)) }}
{{- end }}

{{- define "unikorn.projectControllerImage" -}}
{{- .Values.projectController.image | default (printf "%s/unikorn-project-controller:%s" (include "unikorn.defaultRepositoryPath" .) (.Values.tag | default .Chart.Version)) }}
{{- end }}

{{/*
Create image pull secrets
*/}}
{{- define "unikorn.imagePullSecrets" -}}
{{- if .Values.imagePullSecret -}}
- name: {{ .Values.imagePullSecret }}
{{ end }}
{{- if .Values.dockerConfig -}}
- name: docker-config
{{- end }}
{{- end }}

{{/*
Creates predicatable Kubernetes name compatible UUIDs from name.
Note we always start with a letter (kubernetes DNS label requirement),
group 3 starts with "4" (UUIDv4 aka "random") and group 4 with "8"
(the variant aka RFC9562).
*/}}
{{ define "resource.id" -}}
{{- $sum := sha256sum . -}}
{{ printf "f%s-%s-4%s-8%s-%s" (substr 1 8 $sum) (substr 8 12 $sum) (substr 13 16 $sum) (substr 17 20 $sum) (substr 20 32 $sum) }}
{{- end }}

{{/*
Abstractions to allow an all-in-one chart
*/}}
{{- define "unikorn.identity.host" -}}
{{- if (and .Values.global .Values.global.identity .Values.global.identity.host) -}}
{{- .Values.global.identity.host }}
{{- else }}
{{- .Values.host }}
{{- end }}
{{- end }}

{{- define "unikorn.ingress.clusterIssuer" -}}
{{- if (and .Values.global .Values.global.ingress .Values.global.ingress.clusterIssuer) -}}
{{- .Values.global.ingress.clusterIssuer }}
{{- else }}
{{- .Values.ingress.clusterIssuer }}
{{- end }}
{{- end }}
