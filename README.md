## BOSH-deployed nginx Server with multiple SSL certificates

This BOSH release is built as an add-on for the community [nginx-release](https://github.com/cloudfoundry-community/nginx-release).

1. Upload release to BOSH director

```
bosh upload-release https://github.com/govau/nginx-tlsconfig-release/releases/download/1.0/nginx-tlsconfig-release-v1.0.tgz
```

2. Create BOSH manifest to deploy nginx server using both [nginx-release](//github.com/cloudfoundry-community/nginx-release) and this release.


Check `nginx_manifest.yml` manifest from the `examples/` subdirectory as a template on how to use ssl-config in

This release add 1 additional job which populate multiple  certificates and configuration files for each server block in nginx.
Using this approach we can leverage credhub to store our cert and keys securely.

To build a tarball yourself and upload onto bosh, you can run the following command.

```
git clone https://github.com/govau/nginx-tlsconfig-release.git
bosh2 create-release --tarball=release.tgz
bosh2 -e vbox upload-release release.tgz
```

