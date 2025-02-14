{{/*
Create the container images
*/}}
{{- define "unikorn.image" -}}
{{- .Values.image | default (printf "%s/unikorn-identity:%s" (include "unikorn.defaultRepositoryPath" .) (.Values.tag | default .Chart.Version)) }}
{{- end }}

{{- define "unikorn.organizationControllerImage" -}}
{{- .Values.organizationController.image | default (printf "%s/unikorn-organization-controller:%s" (include "unikorn.defaultRepositoryPath" .) (.Values.tag | default .Chart.Version)) }}
{{- end }}

{{- define "unikorn.oauth2clientControllerImage" -}}
{{- .Values.oauth2clientController.image | default (printf "%s/unikorn-oauth2client-controller:%s" (include "unikorn.defaultRepositoryPath" .) (.Values.tag | default .Chart.Version)) }}
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
Onboarding flags
*/}}
{{- define "unikorn.onboarding.flags" -}}
{{- if .Values.onboarding.authenticateUnknownUsers }}
- --authenticate-unknown-users={{ .Values.onboarding.authenticateUnknownUsers }}
{{- end }}
{{- end }}
