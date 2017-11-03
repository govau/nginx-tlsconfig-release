# Development

```bash
# To deploy quick update to bosh lite
go generate ./cmd/le-responder && \
    GOOS=linux GOARCH=amd64 go build ./cmd/le-responder && \
    bosh scp -d cf le-responder tls-credhub/0:/tmp/le-responder && \
    bosh ssh -d cf tls-credhub/0 'sudo bash -c "rm /var/vcap/packages/nginx-tls-config-go-tools/bin/le-responder && cp /tmp/le-responder /var/vcap/packages/nginx-tls-config-go-tools/bin && /var/vcap/bosh/bin/monit restart le-responder /var/vcap/packages/nginx-tls-config-go-tools/bin/"'
# To deploy quick update to bosh lite
GOOS=linux GOARCH=amd64 go build ./cmd/gen-nginx-config && \
    bosh scp -d cf gen-nginx-config router/0:/tmp/gen-nginx-config && \
    bosh ssh -d cf router/0 'sudo bash -c "rm /var/vcap/packages/nginx-tls-config-go-tools/bin/gen-nginx-config && cp /tmp/gen-nginx-config /var/vcap/packages/nginx-tls-config-go-tools/bin && /var/vcap/bosh/bin/monit restart gen-nginx-config /var/vcap/packages/nginx-tls-config-go-tools/bin/"'

# To get admin password:
credhub get -n /main/cf/cf_admin_password

# To deploy cf:


```bash
bosh -d cf deploy -n cf-deployment.yml \
 -o operations/bosh-lite.yml \
 -o operations/use-compiled-releases.yml    \
  -v system_domain=bosh-lite.com \
  -o ~/Documents/dta/ops/terraform/modules/opensourcecf/installer/files/wrap-go-router-with-nginx.yml \
  -v certs_le_contact_email=adam.eijdenberg@digital.gov.au \
  -v certs_le_external_domain=cm.le.bosh-lite.com \
  -o certs.yml
```

Local `certs.yml`:

```bash
- type: replace
  path: /instance_groups/name=tls-credhub/jobs/name=le-responder/properties/config/servers/admin_ui/external_url
  value: https://((certs_le_external_domain)):8452

- type: replace
  path: /instance_groups/name=uaa/jobs/name=uaa/properties/uaa/clients/le-responder-user-client/redirect-uri
  value: https://((certs_le_external_domain)):8452/oauth2callback
```

```bash
# Update glide
rm -rf ~/.glide/cache/src/https-github.com-govau-cf-common/ && \
    glide update && glide install
```
