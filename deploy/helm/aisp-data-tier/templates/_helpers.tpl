{{- define "aisp-dt.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "aisp-dt.fullname" -}}
{{- printf "%s" (include "aisp-dt.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "aisp-dt.labels" -}}
app.kubernetes.io/name: {{ include "aisp-dt.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: ai-security-platform
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
aisp.io/region: {{ .Values.deploymentRegion | quote }}
{{- end -}}

{{/*
Image reference. Digest ONLY — there is no tag branch to fall through to.
validate.yaml has already refused anything that is not a sha256 digest, so this
helper cannot emit a mutable reference even if someone edits values later.
*/}}
{{- define "aisp-dt.image" -}}
{{- printf "%s@%s" .repository .digest -}}
{{- end -}}

{{/*
HARD anti-affinity, not the soft "preferred" the control plane uses.

The control plane is stateless: two API replicas on one node is a capacity
problem. Two PostgreSQL replicas on one node is a DATA problem — the node is
the failure domain the standby exists to survive, so co-scheduling them makes
the standby decorative. requiredDuringScheduling means the second replica stays
Pending rather than landing somewhere that cannot help, which is a visible,
diagnosable failure instead of a silent loss of redundancy.
*/}}
{{- define "aisp-dt.antiAffinity" -}}
podAntiAffinity:
  requiredDuringSchedulingIgnoredDuringExecution:
    - topologyKey: kubernetes.io/hostname
      labelSelector:
        matchLabels:
          app.kubernetes.io/instance: {{ .instance }}
          app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "aisp-dt.storageClass" -}}
{{- if .Values.storageClassName }}
storageClassName: {{ .Values.storageClassName | quote }}
{{- end }}
{{- end -}}
