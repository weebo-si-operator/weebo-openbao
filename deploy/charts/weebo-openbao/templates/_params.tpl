{{/*
This operator's parameters for the kit's library chart (weebo-operator-lib,
see its README): everything templates/operator.yaml renders that is not a
value.
*/}}
{{- define "operator.params" -}}
group: openbao.weebo.io
versions: [v1alpha1]
# Every kind the operator watches (ClusterRole).
kinds:
  - openbaoinstances
  - openbaonamespaces
  - openbaoaccesslevels
  - openbaospacelayouts
  - openbaoorganizations
  - openbaoaccessgrants
# The namespaced kinds: none, every kind is cluster-scoped (RFC 0007 §6.6).
namespacedKinds: []
# Kinds the admission webhook checks: none until the operator serves
# `/validate` (a namespace allow-list).
admitted: []
# The operator's own environment variables.
env: []
egress:
  - comment: OpenBao.
    rules: {{ toJson .Values.networkPolicy.egress.openbao }}
# Alerts on the operator's own metrics, appended to the kit's.
alerts: []
{{- end -}}
