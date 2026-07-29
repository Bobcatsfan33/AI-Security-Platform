{{/* Common naming + label helpers. */}}

{{- define "aisp.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "aisp.fullname" -}}
{{- printf "%s" (include "aisp.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "aisp.labels" -}}
app.kubernetes.io/name: {{ include "aisp.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "aisp.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}
{{- end -}}

{{- define "aisp.secretName" -}}
{{- if .Values.secrets.existingSecret -}}{{ .Values.secrets.existingSecret }}{{- else -}}{{ include "aisp.fullname" . }}-secrets{{- end -}}
{{- end -}}

{{- define "aisp.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "aisp.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "aisp.secretProviderClassName" -}}
{{- default (include "aisp.fullname" .) .Values.secrets.secretProviderClass.name -}}
{{- end -}}

{{/*
Shared env block for every workload: non-secret config from the ConfigMap +
JWT_SECRET from the Secret. Usage: {{- include "aisp.env" . | nindent 12 }}
*/}}
{{- define "aisp.env" -}}
- name: ENVIRONMENT
  value: {{ .Values.environment | quote }}
- name: DATABASE_URL
  valueFrom:
    {{- if eq .Values.environment "production" }}
    secretKeyRef: { name: {{ include "aisp.secretName" . }}, key: database-url }
    {{- else }}
    configMapKeyRef: { name: {{ include "aisp.fullname" . }}-config, key: database-url }
    {{- end }}
- name: REDIS_URL
  valueFrom:
    {{- if eq .Values.environment "production" }}
    secretKeyRef: { name: {{ include "aisp.secretName" . }}, key: redis-url }
    {{- else }}
    configMapKeyRef: { name: {{ include "aisp.fullname" . }}-config, key: redis-url }
    {{- end }}
- name: CLICKHOUSE_URL
  valueFrom:
    {{- if eq .Values.environment "production" }}
    secretKeyRef: { name: {{ include "aisp.secretName" . }}, key: clickhouse-url }
    {{- else }}
    configMapKeyRef: { name: {{ include "aisp.fullname" . }}-config, key: clickhouse-url }
    {{- end }}
- name: REDPANDA_BROKERS
  valueFrom:
    {{- if eq .Values.environment "production" }}
    secretKeyRef: { name: {{ include "aisp.secretName" . }}, key: redpanda-brokers }
    {{- else }}
    configMapKeyRef: { name: {{ include "aisp.fullname" . }}-config, key: redpanda-brokers }
    {{- end }}
- name: STREAMING_ENABLED
  valueFrom: { configMapKeyRef: { name: {{ include "aisp.fullname" . }}-config, key: streaming-enabled } }
- name: JWT_SECRET
  valueFrom: { secretKeyRef: { name: {{ include "aisp.secretName" . }}, key: jwt-secret } }
{{- end -}}

{{/* Soft anti-affinity so replicas spread across nodes (HA). */}}
{{- define "aisp.affinity" -}}
{{- if .Values.affinity -}}
{{ toYaml .Values.affinity }}
{{- else -}}
podAntiAffinity:
  preferredDuringSchedulingIgnoredDuringExecution:
    - weight: 100
      podAffinityTerm:
        topologyKey: kubernetes.io/hostname
        labelSelector:
          matchLabels:
            app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
{{- end -}}
