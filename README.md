### Intro

This bosh release allows user to do multiple things. It can be used for various scenarios:

 - Running Nginx as reverse proxy and terminate multiple TLS connections.
 - Standalone errand to renew Letsencrypt certificate by trigger an errand (Only support HTTP acme challenge)
 - Standalone errand to import certificates and private keys to credhub
 - A combined errand to renew Letsencrypt certificate and import of new certs/keys to credhub db.

This BOSH release is built to be used together with the community [nginx-release](https://github.com/cloudfoundry-community/nginx-release).

1. Upload the release to BOSH director

```
bosh upload-release https://github.com/govau/nginx-tlsconfig-release/releases/download/1.0/nginx-tlsconfig-release-v2.0.tgz
```

2. Create BOSH manifest to deploy nginx server using both [nginx-release](https://github.com/cloudfoundry-community/nginx-release) and this release.

Check the manifest in `examples/` subdirectory as a template.

To build a release tarball yourself and upload onto bosh, you can run the following command.

```
git clone https://github.com/govau/nginx-tlsconfig-release.git
bosh2 create-release --tarball=release.tgz
bosh2 -e vbox upload-release release.tgz
```


#### Example with boshlite

Add `10.244.0.10` to the list of static ips for "default" network:

 - Execute `bosh2 -e vbox cloud-config > cloud-config.yml` to acquire latest cloud-config
 - Modify cloud-config file and add 10.244.0.10 to the list of static ip (or create a new entry) as shown below
 - Execute `bosh2 -e vbox update-cloud-config cloud-config.yml` to update the cloud-config

```
networks:
- name: default
  subnets:
  - azs:
    - z1
    - z2
    - z3
    cloud_properties:
      name: vboxnet2
    dns:
    - 8.8.8.8
    gateway: 10.244.0.1
    range: 10.244.0.0/16
    reserved:
    - 10.244.0.0-10.244.0.4
    static:
    - 10.244.0.10
```
Deploy the example deployment manifest with an operator file which specify information about the new cert (this.example.com)

```
bosh2 -e vbox -d nginx deploy ./example/nginx_manifest.yml -o ./example/this_example_com.yml
```

`bosh2 -e vbox -d nginx instances` should show nginx-ubuntu machine running and nothing happens for errand machine.

To execute the errand, we will need to run `bosh2 -e vbox -d nginx run-errand letsencrypt-errand`

Here is an example to add another domain, we will make a copy of the operator file for this.example.com and do a few `sed` commands to replace the variable name and domain. Example below will add a subdomain that.example.com config

```
cp ./example/this_example_com.yml ./example/that_example_com.yml
sed -i 's/this_example_com/that_example_com/g' ./example/that_example_com.yml
sed -i 's/this\.example\.com/that\.example\.com/g' ./example/that_example_com.yml
```

We can now redeploy the deployment and see if everything working as expected and errand job runs accordingly

```
bosh2 -e vbox -d nginx deploy ./example/nginx_manifest.yml -o ./example/this_example_com.yml -o ./example/that_example_com.yml
bosh2 -e vbox -d nginx run-errand letsencrypt-errand
```

This time we should see the Stdout of the errand job showing 2 attempts to renew certificate, one for this_example_com and another for that_example_com.

__NOTE:__ the operator file for each of these domains do not only have the configuration used for LetsEncrypt certificate signing request (CSR) but also include the virtual host configuration for nginx reverse proxy servers itself. This configuration allow administrators to add custom Headers, Security options , Blacklist URI etc...
