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
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}

{{- define "aisp.secretName" -}}
{{- if .Values.secrets.existingSecret -}}{{ .Values.secrets.existingSecret }}{{- else -}}{{ include "aisp.fullname" . }}-secrets{{- end -}}
{{- end -}}

{{/*
Shared env block for every workload: non-secret config from the ConfigMap +
JWT_SECRET from the Secret. Usage: {{- include "aisp.env" . | nindent 12 }}
*/}}
{{- define "aisp.env" -}}
- name: ENVIRONMENT
  value: {{ .Values.environment | quote }}
- name: DATABASE_URL
  valueFrom: { configMapKeyRef: { name: {{ include "aisp.fullname" . }}-config, key: database-url } }
- name: REDIS_URL
  valueFrom: { configMapKeyRef: { name: {{ include "aisp.fullname" . }}-config, key: redis-url } }
- name: CLICKHOUSE_URL
  valueFrom: { configMapKeyRef: { name: {{ include "aisp.fullname" . }}-config, key: clickhouse-url } }
- name: REDPANDA_BROKERS
  valueFrom: { configMapKeyRef: { name: {{ include "aisp.fullname" . }}-config, key: redpanda-brokers } }
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
