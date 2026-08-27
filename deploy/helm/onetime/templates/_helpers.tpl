{{/*
Name helpers.
*/}}
{{- define "onetime.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "onetime.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "onetime.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "onetime.labels" -}}
helm.sh/chart: {{ include "onetime.chart" . }}
{{ include "onetime.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: onetime
{{- end -}}

{{- define "onetime.selectorLabels" -}}
app.kubernetes.io/name: {{ include "onetime.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "onetime.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "onetime.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Image references. A digest always wins over a tag: it is the only reference
that cannot be repointed underneath a running release.
*/}}
{{- define "onetime.image" -}}
{{- $registry := .Values.image.registry | default "" -}}
{{- $repo := .Values.image.repository -}}
{{- $base := ternary $repo (printf "%s/%s" $registry $repo) (empty $registry) -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" $base .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" $base (.Values.image.tag | default .Chart.AppVersion) -}}
{{- end -}}
{{- end -}}

{{- define "onetime.initImage" -}}
{{- printf "%s:%s" .Values.initImage.repository .Values.initImage.tag -}}
{{- end -}}

{{- define "onetime.redisImage" -}}
{{- printf "%s:%s" .Values.redis.image.repository .Values.redis.image.tag -}}
{{- end -}}

{{/*
Storage names.
*/}}
{{- define "onetime.pvcName" -}}
{{- if .Values.persistence.existingClaim -}}
{{- .Values.persistence.existingClaim -}}
{{- else -}}
{{- printf "%s-data" (include "onetime.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
Deployment strategy — DERIVED, not a user knob.

The data volume is ReadWriteOnce. A RollingUpdate brings the new pod up before
the old one goes away, so the new pod tries to attach a volume that is still
attached to the old pod's node. On most CSI drivers that is a Multi-Attach
error and the rollout wedges until someone deletes the old pod by hand.
Recreate accepts a few seconds of downtime instead of an indefinite stall.

Without persistence (emptyDir, i.e. CI) there is no volume to fight over, so a
RollingUpdate is both safe and nicer.
*/}}
{{- define "onetime.strategy" -}}
{{- if .Values.persistence.enabled -}}
type: Recreate
{{- else -}}
type: RollingUpdate
rollingUpdate:
  maxUnavailable: 0
  maxSurge: 1
{{- end -}}
{{- end -}}

{{/*
Master keyring: which Secret, which key.
*/}}
{{- define "onetime.masterKeySecretName" -}}
{{- if .Values.masterKey.existingSecret -}}
{{- .Values.masterKey.existingSecret -}}
{{- else -}}
{{- printf "%s-masterkey" (include "onetime.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "onetime.masterKeySecretKey" -}}
{{- if .Values.masterKey.existingSecret -}}
{{- .Values.masterKey.existingSecretKey | default "master.keys" -}}
{{- else -}}
{{- .Values.masterKey.existingSecretKey | default "master.keys" -}}
{{- end -}}
{{- end -}}

{{/*
Absolute path the application reads the keyring from.
*/}}
{{- define "onetime.masterKeyPath" -}}
{{- printf "%s/%s" (.Values.masterKey.mountPath | trimSuffix "/") .Values.masterKey.fileName -}}
{{- end -}}

{{/*
Resolve the keyring material for the chart-managed Secret.

`lookup` returns the value already stored in the cluster so that an upgrade
does not rotate the key. It returns an EMPTY map during `helm template`, during
`--dry-run`, and therefore under ArgoCD — which is precisely why autoGenerate
defaults to false. See NOTES.txt.
*/}}
{{- define "onetime.masterKeyMaterial" -}}
{{- if .Values.masterKey.value -}}
{{- .Values.masterKey.value -}}
{{- else -}}
{{- $name := include "onetime.masterKeySecretName" . -}}
{{- $key := include "onetime.masterKeySecretKey" . -}}
{{- $found := lookup "v1" "Secret" .Release.Namespace $name -}}
{{- if and $found $found.data (hasKey $found.data $key) -}}
{{- index $found.data $key | b64dec -}}
{{- else -}}
{{- printf "v1:%s" (randAlphaNum 32 | b64enc) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Rendered redis.conf for the sidecar. Kept in a helper so the ConfigMap and the
pod-template checksum are always computed from the exact same bytes.
*/}}
{{- define "onetime.redisConf" -}}
# Managed by the onetime Helm chart. Do not edit in place.

# The sidecar shares the pod's network namespace with the app, so loopback is
# the entire reachable surface. Nothing outside the pod can open a connection,
# which is why there is no password: there is no one to authenticate.
bind 127.0.0.1
protected-mode yes
port 6379
tcp-keepalive 300
timeout 0

# RDB snapshots disabled. A snapshot is a point-in-time copy of live secret
# metadata; restoring one resurrects secrets that were already burned. The AOF
# gives crash recovery without that "roll the world back" failure mode.
save ""
appendonly yes
appendfsync everysec
aof-load-truncated yes
auto-aof-rewrite-percentage 100
auto-aof-rewrite-min-size 64mb

# Same PersistentVolume as the app, isolated by subPath.
dir /data/redis

maxmemory {{ .Values.redis.maxmemory }}

# CRITICAL — must stay noeviction.
#
# Every key is a live secret's metadata. Any *-lru or *-random policy would let
# memory pressure silently delete secrets whose links are still in someone's
# inbox: data loss with no error, no log line and no way to tell the user which
# ones went. noeviction makes the write fail loudly instead, and the app turns
# that into a 503 the caller can retry.
maxmemory-policy noeviction

loglevel notice
logfile ""

# Remove the commands that can wipe or reshape the dataset in one shot.
rename-command FLUSHALL ""
rename-command FLUSHDB ""
rename-command CONFIG ""
rename-command KEYS ""
{{- range .Values.redis.extraConfig }}
{{ . }}
{{- end }}
{{- end -}}

{{/*
Environment for the app container, rendered into the ConfigMap.

ONETIME_DATA_DIR and ONETIME_TMP_DIR are intentionally NOT exposed as values.
They must sit on the same filesystem — a blob write is "create in tmp, fsync,
rename into blobs", and rename() fails across mount points. Making them
configurable is an invitation to split them across two volumes and discover it
in production.
*/}}
{{- define "onetime.env" -}}
ONETIME_LISTEN_ADDR: {{ printf ":%d" (int .Values.config.listenPort) | quote }}
ONETIME_METRICS_ADDR: {{ printf ":%d" (int .Values.config.metricsPort) | quote }}
ONETIME_BASE_URL: {{ .Values.config.baseURL | quote }}

ONETIME_MASTER_KEYS_FILE: {{ include "onetime.masterKeyPath" . | quote }}

ONETIME_DATA_DIR: "/data/blobs"
ONETIME_TMP_DIR: "/data/tmp"

ONETIME_REDIS_MODE: {{ .Values.redis.mode | quote }}
{{- if eq .Values.redis.mode "sidecar" }}
ONETIME_REDIS_ADDR: "127.0.0.1:6379"
ONETIME_REDIS_DB: "0"
{{- else if eq .Values.redis.mode "external" }}
ONETIME_REDIS_URL: {{ .Values.redis.external.url | quote }}
ONETIME_REDIS_DB: {{ .Values.redis.external.db | int64 | quote }}
{{- if .Values.redis.external.existingPasswordSecret }}
{{/* Its own directory: nesting it under masterKey.mountPath would mean two
     volumes mounted inside one another, which kubelet orders unpredictably. */}}
ONETIME_REDIS_PASSWORD_FILE: "/run/secrets/onetime-redis/password"
{{- end }}
{{- end }}

{{/* `| int64` is load-bearing on every numeric value below.

     Helm decodes YAML numbers into float64, so `52428800 | quote` renders as
     "5.24288e+07". The app parses these with strconv.ParseInt, which rejects
     that outright - the pod crash-loops at startup with a config error, and the
     only clue is a value you never typed. int64 forces plain decimal. */}}
ONETIME_MAX_FILE_BYTES: {{ .Values.config.limits.maxFileBytes | int64 | quote }}
ONETIME_MAX_TEXT_INLINE_BYTES: {{ .Values.config.limits.maxTextInlineBytes | int64 | quote }}
ONETIME_MAX_TEXT_BYTES: {{ .Values.config.limits.maxTextBytes | int64 | quote }}
ONETIME_DAILY_BYTES_PER_IP: {{ .Values.config.limits.dailyBytesPerIP | int64 | quote }}
ONETIME_TOTAL_STORAGE_BYTES: {{ .Values.config.limits.totalStorageBytes | int64 | quote }}
ONETIME_DISK_HIGH_WATERMARK_PCT: {{ .Values.config.limits.diskHighWatermarkPct | int64 | quote }}

ONETIME_TTL_MIN_DAYS: {{ .Values.config.ttl.minDays | int64 | quote }}
ONETIME_TTL_MAX_DAYS: {{ .Values.config.ttl.maxDays | int64 | quote }}
ONETIME_TTL_DEFAULT_DAYS: {{ .Values.config.ttl.defaultDays | int64 | quote }}
ONETIME_RECEIPT_EXTRA_TTL: {{ .Values.config.ttl.receiptExtra | quote }}
ONETIME_TOMBSTONE_TTL: {{ .Values.config.ttl.tombstone | quote }}
ONETIME_DOWNLOAD_TICKET_TTL: {{ .Values.config.ttl.downloadTicket | quote }}
ONETIME_DOWNLOAD_ATTEMPTS: {{ .Values.config.ttl.downloadAttempts | int64 | quote }}

ONETIME_ARGON2_MEM_KIB: {{ .Values.config.argon2.memoryKiB | int64 | quote }}
ONETIME_ARGON2_TIME: {{ .Values.config.argon2.time | int64 | quote }}
ONETIME_ARGON2_PAR: {{ .Values.config.argon2.parallelism | int64 | quote }}
ONETIME_ARGON2_CONCURRENCY: {{ .Values.config.argon2.concurrency | int64 | quote }}

ONETIME_PASSPHRASE_WINDOW_FAILS: {{ .Values.config.passphrase.windowFails | int64 | quote }}
ONETIME_PASSPHRASE_WINDOW: {{ .Values.config.passphrase.window | quote }}
ONETIME_PASSPHRASE_TOTAL_FAILS: {{ .Values.config.passphrase.totalFails | int64 | quote }}

ONETIME_GC_INTERVAL: {{ .Values.config.jobs.gcInterval | quote }}
ONETIME_RECONCILE_INTERVAL: {{ .Values.config.jobs.reconcileInterval | quote }}
ONETIME_ORPHAN_GRACE: {{ .Values.config.jobs.orphanGrace | quote }}

ONETIME_ENABLE_FILES: {{ .Values.config.enableFiles | quote }}
ONETIME_READ_ONLY: {{ .Values.config.readOnly | quote }}
ONETIME_RATELIMIT_ENABLED: {{ .Values.config.rateLimitEnabled | quote }}
{{- with .Values.config.rateLimits }}
{{- if .createText }}
ONETIME_RATELIMIT_CREATE_TEXT: {{ .createText | quote }}
{{- end }}
{{- if .createFile }}
ONETIME_RATELIMIT_CREATE_FILE: {{ .createFile | quote }}
{{- end }}
{{- if .generate }}
ONETIME_RATELIMIT_GENERATE: {{ .generate | quote }}
{{- end }}
{{- if .peek }}
ONETIME_RATELIMIT_PEEK: {{ .peek | quote }}
{{- end }}
{{- if .reveal }}
ONETIME_RATELIMIT_REVEAL: {{ .reveal | quote }}
{{- end }}
{{- if .download }}
ONETIME_RATELIMIT_DOWNLOAD: {{ .download | quote }}
{{- end }}
{{- if .receipt }}
ONETIME_RATELIMIT_RECEIPT: {{ .receipt | quote }}
{{- end }}
{{- if .burn }}
ONETIME_RATELIMIT_BURN: {{ .burn | quote }}
{{- end }}
{{- if .page }}
ONETIME_RATELIMIT_PAGE: {{ .page | quote }}
{{- end }}
{{- end }}

ONETIME_DEFAULT_LANG: {{ .Values.config.defaultLang | quote }}
ONETIME_LOG_LEVEL: {{ .Values.config.logLevel | quote }}
ONETIME_LOG_FORMAT: {{ .Values.config.logFormat | quote }}

ONETIME_SHUTDOWN_TIMEOUT: {{ .Values.config.shutdownTimeout | quote }}
ONETIME_STRICT_STARTUP: {{ .Values.config.strictStartup | quote }}
{{- if .Values.config.trustedProxies }}
ONETIME_TRUSTED_PROXIES: {{ join "," .Values.config.trustedProxies | quote }}
{{- end }}
{{- range $k, $v := .Values.config.extraEnv }}
{{ $k }}: {{ $v | quote }}
{{- end }}
{{- end -}}

{{/*
Fail-fast validation. Every message names the value to change, because the
alternative is a rendered manifest that applies cleanly and then misbehaves at
runtime in a way that costs data.
*/}}
{{- define "onetime.validate" -}}

{{- if gt (int .Values.replicaCount) 1 -}}
{{- fail "\n\nonetime: replicaCount must be 1.\n\nThe blob store is a ReadWriteOnce volume and the GC/reconcile loops assume a single writer.\nA second replica does not give you HA - it gives you a pod stuck on a Multi-Attach error\nplus two GC loops racing over the same blobs.\n" -}}
{{- end -}}

{{- if not .Values.config.baseURL -}}
{{- fail "\n\nonetime: config.baseURL is required.\n\nIt is the origin used to build the one-time links themselves; there is no sane default.\nUse https:// in production - the secret id travels in the URL path.\n" -}}
{{- end -}}

{{- if and (not (hasPrefix "https://" .Values.config.baseURL)) (not (hasPrefix "http://" .Values.config.baseURL)) -}}
{{- fail (printf "\n\nonetime: config.baseURL must start with http:// or https://, got %q.\n" .Values.config.baseURL) -}}
{{- end -}}

{{- if not (or .Values.masterKey.existingSecret .Values.masterKey.value .Values.masterKey.autoGenerate) -}}
{{- fail "\n\nonetime: no master keyring configured.\n\nThe keyring encrypts every stored secret. Losing it destroys all of them, irreversibly,\nso the chart refuses to invent one behind your back. Pick exactly one:\n\n  1. masterKey.existingSecret=<name>   RECOMMENDED - you manage the Secret (SealedSecrets,\n                                       External Secrets, SOPS, vault-injector, kubectl).\n  2. masterKey.value=<keyring>         Chart creates the Secret. Fine for dev/CI/helm test;\n                                       in production the keyring ends up in your values file\n                                       and in Helm's release Secret in plaintext.\n  3. masterKey.autoGenerate=true       ONLY with real `helm install`. NEVER with ArgoCD or any\n                                       `helm template` pipeline - see NOTES.txt.\n\nKeyring format: \"v2:<base64 of 32 bytes>,v1:<base64 of 32 bytes>\", newest first.\nGenerate one with:  onetime keygen\n" -}}
{{- end -}}

{{- if and (eq .Values.redis.mode "external") (not .Values.redis.external.url) -}}
{{- fail "\n\nonetime: redis.mode=external requires redis.external.url (redis://host:6379/0).\n\nAlso remember to open egress: networkPolicy defaults to deny-all-but-DNS, so add the\nRedis endpoint under networkPolicy.extraEgress or the app will never become ready.\n" -}}
{{- end -}}

{{- if and .Values.config.strictStartup (not .Values.masterKey.hardenPermissions) -}}
{{- fail "\n\nonetime: config.strictStartup=true requires masterKey.hardenPermissions=true.\n\nKubernetes mounts Secret volumes as root:<fsGroup> and, when fsGroup is set, ORs group-read\ninto the file mode - so even defaultMode 0400 lands as 0440. The app's startup check rejects\nanything readable by group or other, so it would crash-loop.\n\nmasterKey.hardenPermissions=true adds an init container that copies the keyring as uid 65532\nand chmods it to 0400, which satisfies both. Only set hardenPermissions=false if you also set\nconfig.strictStartup=false, and understand you are accepting a group-readable keyring.\n" -}}
{{- end -}}

{{- if and .Values.ingress.enabled (not .Values.ingress.host) -}}
{{- fail "\n\nonetime: ingress.enabled=true requires ingress.host.\n" -}}
{{- end -}}

{{- if and .Values.persistence.enabled (not .Values.persistence.existingClaim) (not .Values.persistence.size) -}}
{{- fail "\n\nonetime: persistence.enabled=true requires persistence.size (or persistence.existingClaim).\n" -}}
{{- end -}}

{{- if gt (int .Values.config.ttl.minDays) (int .Values.config.ttl.maxDays) -}}
{{- fail "\n\nonetime: config.ttl.minDays must be <= config.ttl.maxDays.\n" -}}
{{- end -}}

{{- if or (lt (int .Values.config.ttl.defaultDays) (int .Values.config.ttl.minDays)) (gt (int .Values.config.ttl.defaultDays) (int .Values.config.ttl.maxDays)) -}}
{{- fail "\n\nonetime: config.ttl.defaultDays must sit inside [config.ttl.minDays, config.ttl.maxDays].\n" -}}
{{- end -}}

{{- if and .Values.podDisruptionBudget.enabled (eq (int .Values.replicaCount) 1) (hasKey .Values.podDisruptionBudget "minAvailable") -}}
{{- fail "\n\nonetime: podDisruptionBudget.minAvailable with replicaCount=1 permanently blocks `kubectl drain`.\n\nThe single pod can never be evicted, so node maintenance hangs until someone deletes the PDB\nby hand - usually at 3am, by someone who did not write this chart. Use maxUnavailable: 1\n(which is a no-op at one replica, which is the honest answer) or leave the PDB disabled.\n" -}}
{{- end -}}

{{- end -}}
