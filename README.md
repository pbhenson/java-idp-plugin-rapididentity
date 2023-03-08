# java-idp-plugin-rapididentity
An IdP plugin providing RapidIdentity authentication API MFA support

## Quick start

### Dependencies

```
gpg (GnuPG)
apache maven (latest stable)
java (developed with 11 LTS, 17 LTS is probably fine)
```

First, check out the repo and cd into the root of it. You will need a gpg key to sign the plugin package, so if you don't have one, create one:

```
gpg --generate-key
```

Update the repo public key file with the key you intend to use, for example:

```
gpg --armor --export rapid@test > rapididentity-dist/src/main/resources/bootstrap/keys.txt
```

At this point you are ready to compile (`mvn compile`) and assuming no errors package (`mvn package`) the plugin. Next, you need to sign the resultant package, for example:

```
gpg --local-user rapid@test --output rapididentity-dist/target/shibboleth-idp-plugin-rapididentity-1.0.0-SNAPSHOT.tar.gz.asc --detach-sig rapididentity-dist/target/shibboleth-idp-plugin-rapididentity-1.0.0-SNAPSHOT.tar.gz
```

As there is currently no binary distribution, you will need to make a local properties file to make the plugin installer happy. Create a file named for example `java-idp-plugin-rapididentity.properties` with the following content:

```
id.signet.idp.plugin.authn.rapididentity.versions = 1.0.0-SNAPSHOT

id.signet.idp.plugin.authn.rapididentity.downloadURL.%{version} = https://localhost/downloads/identity-provider/plugins/rapididentity/%{version}
id.signet.idp.plugin.authn.rapididentity..baseName.%{version} = idp-plugin-rapididentity-dist-%{version}

id.signet.idp.plugin.authn.rapididentity.idpVersionMax.1.0.0-SNAPSHOT = 5.0.0
id.signet.idp.plugin.authn.rapididentity.idpVersionMin.1.0.0-SNAPSHOT = 4.1.0
id.signet.idp.plugin.authn.rapididentity.supportLevel.1.0.0-SNAPSHOT = Current
```

Assuming you create that file in /tmp and copy the package/signature there as well, you can now install the plugin by running:

```
/opt/shibboleth-idp/bin/plugin.sh --updateURL file:///tmp/java-idp-plugin-rapididentity.properties -i /tmp/shibboleth-idp-plugin-rapididentity-1.0.0-SNAPSHOT.tar.gz
```
