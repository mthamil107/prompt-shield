# prompt-shield Helm Chart

Deploy the prompt-shield REST API on Kubernetes.

## TL;DR

```bash
helm install my-shield ./deploy/helm/prompt-shield
```

## Configuration

The most common values you may want to override:

| Key | Description | Default |
|---|---|---|
| `replicaCount` | Number of replicas | `2` |
| `image.repository` | Container image | `ghcr.io/mthamil107/prompt-shield` |
| `image.tag` | Image tag (defaults to `Chart.appVersion`) | `""` |
| `config.mode` | `block` / `flag` / `log` | `block` |
| `config.threshold` | Risk score threshold for blocking | `0.7` |
| `service.type` | `ClusterIP` / `NodePort` / `LoadBalancer` | `ClusterIP` |
| `ingress.enabled` | Expose via Ingress | `false` |
| `autoscaling.enabled` | Enable HorizontalPodAutoscaler | `false` |
| `persistence.enabled` | Mount a PVC at `config.dataDir` (vault, history) | `false` |

See [`values.yaml`](values.yaml) for the complete list.

## Examples

### Production deployment with autoscaling and persistence

```yaml
# values-prod.yaml
replicaCount: 3
autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 20
  targetCPUUtilizationPercentage: 70
persistence:
  enabled: true
  size: 10Gi
  storageClass: gp3
ingress:
  enabled: true
  className: nginx
  hosts:
    - host: prompt-shield.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: prompt-shield-tls
      hosts:
        - prompt-shield.example.com
resources:
  limits:
    cpu: 2000m
    memory: 2Gi
  requests:
    cpu: 500m
    memory: 512Mi
```

```bash
helm install prompt-shield ./deploy/helm/prompt-shield -f values-prod.yaml
```

### Local development with port-forward

```bash
helm install dev ./deploy/helm/prompt-shield --set replicaCount=1
kubectl port-forward svc/dev-prompt-shield 8000:8000
curl http://localhost:8000/health
```

## Verify before installing

```bash
# Lint
helm lint ./deploy/helm/prompt-shield

# Render templates without applying
helm template my-shield ./deploy/helm/prompt-shield
```

## Uninstall

```bash
helm uninstall my-shield
```

If `persistence.enabled` was set, the PVC remains by design — delete it manually if you want to discard the vault and history databases.
