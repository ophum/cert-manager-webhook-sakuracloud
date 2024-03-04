# cert-manager ACME dns01 webhook solver for sakuracloud

※ 非公式です。

[cert-manager/webhook-example](https://github.com/cert-manager/webhook-example)をフォークしさくらのクラウド向けに実装しました。

## Usage

ここでは nemaspace 毎に issuer を設定する方法を記述します。

1. cert-manager をデプロイします。

[cert-manager: installation/helm](https://cert-manager.io/docs/installation/helm/)

```
helm repo add jetstack https://charts.jetstack.io --force-update
helm repo update
helm install \
  cert-manager jetstack/cert-manager \
  --namespace cert-manager \
  --create-namespace \
  --version v1.14.3 \
  --set installCRDs=true
```

2. cert-manager-webhook-sakuracloud をデプロイします。

```
git clone https://github.com/ophum/cert-manager-webhook-sakuracloud.git
cd cert-manager-webhook-sakuracloud
helm install --namespace cert-manager \
  cert-manager-webhook-sakuracloud \
  ./deploy/cert-manager-webhook-sakuracloud
```

3. issuer を設定します。

issuer で使うさくらのクラウドの API キーを作成します。

```
apiVersion: v1
data:
  accessToken: <アクセストークンのbase64>
  accessTokenSecret: <アクセストークンシークレットのbase64>
kind: Secret
metadata:
  name: sakuracloud-dns-credentials
  namespace: example-ns
type: Opaque
```

```
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: example-issuer
  namespace: example-ns
spec:
  acme:
    server: https://acme-staging-v02.api.letsencrypt.org/directory
    email: user@example.com
    privateKeySecretRef:
      name: example-issuer-account-key
    solvers:
    - dns01:
        webhook:
          groupName: acme.t-inagaki.net
          solverName: sakuracloud-dns-solver
          config:
            zoneID: <さくらのクラウドのDNSゾーンID>
            accessTokenRef:
              name: sakuracloud-dns-credentials
              key: accessToken
            accessTokenSecretRef:
              name: sakuracloud-dns-credentials
              key: accessTokenSecret
```

4. ingress の annotation で指定して証明書を作ります。

```
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  annotations:
    cert-manager.io/issuer: example-issuer
  name: example-ingress
  namespace: example-ns
spec:
  rules:
  - host: example.<さくらのクラウドで管理するゾーン名>
    http:
      paths:
      - pathType: Prefix
        path: /
        backend:
          service:
            name: myservice
            port:
              number: 80
  tls:
  - hosts:
    - example.<さくらのクラウドで管理するゾーン名>
    secretName: example-ingress-cert
```
