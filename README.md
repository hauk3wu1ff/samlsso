## Configure a service provider-initiated SSO with identity propagation

This is an IBM Websphere Liberty SAML SSO example described in this [article](https://www.ibm.com/developerworks/library/mw-1703-maurip1-bluemix/index.html).

Also see the Websphere Liberty Knowledgebase: [Configuring SAML Web Browser SSO in Liberty](https://www.ibm.com/support/knowledgecenter/SSEQTP_liberty/com.ibm.websphere.wlp.doc/ae/twlp_config_saml_web_sso.html). Also see [SAML assertions across WebSphere Application Server security domains](https://www.ibm.com/developerworks/websphere/techjournal/1004_chao/1004_chao.html).

The tutorial uses the Liberty InstallUtility, which has options described in [Configuring repositories and proxy settings for the installUtility command](https://www.ibm.com/support/knowledgecenter/SSEQTP_liberty/com.ibm.websphere.wlp.doc/ae/twlp_config_installutility.html). It describes how to configure a proxy for networkaccess by the InstallUtility.

### Notes

* In **Step 2b** *"Apply the security configuration to the IdentityServer profile"* / *"1. Create a key in a new keystore"*
    * The IdentityServer needs to be started once to create the directory <WLP_SERVERS>\IdentityServer\resources\security\ **before** this step.
* In **Step 2c** *"Test the identity provider application by using a web browser"*, starting the IdentityServer generates the following console output:
```
Launching IdentityServer (WebSphere Application Server 18.0.0.1/wlp-1.0.20.cl180120180309-2209) on Java HotSpot(TM) 64-Bit Server VM, version 1.8.0_121-b13 (en_IE)
[AUDIT   ] CWWKE0001I: The server IdentityServer has been launched.
[AUDIT   ] CWWKE0100I: This product is licensed for development, and limited production use. The full license terms can be viewed here: https://public.dhe.ibm.com/ibmdl/export/pub/software/websphere/wasdev/license/base_ilan/ilan/18.0.0.1/lafiles/en.html
[AUDIT   ] CWWKZ0058I: Monitoring dropins for applications.
[AUDIT   ] CWWKI0001I: The CORBA name server is now available at corbaloc:iiop:localhost:2809/NameService.
[AUDIT   ] CWWKF0012I: The server installed the following features: [identityProvider-1.0].
[AUDIT   ] CWWKF0011I: The server IdentityServer is ready to run a smarter planet.
[AUDIT   ] CWWKT0016I: Web application available (default_host): http://192.168.1.23:80/idp/
```
* Authenticating at http://localhost/idp/SAMLResponse as "max" produces the following SAML assertion:
```xml
<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<saml2p:Response 
    xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" IssueInstant="2018-05-13T16:36:13.727Z" Version="2.0">
    <saml2:Issuer 
        xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">samlsso.sample.net
    </saml2:Issuer>
    <saml2p:Status>
        <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </saml2p:Status>
    <saml2:Assertion 
        xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="Assertion1526229373583" IssueInstant="2018-05-13T16:36:13.478Z" Version="2.0">
        <saml2:Issuer>samlsso.sample.net</saml2:Issuer>
        <ds:Signature 
            xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <ds:SignedInfo>
                <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                <ds:Reference URI="#Assertion1526229373583">
                    <ds:Transforms>
                        <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                        <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
                    </ds:Transforms>
                    <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                    <ds:DigestValue>+mSKS70UVR/lUKF5132CUPgg3mo=</ds:DigestValue>
                </ds:Reference>
            </ds:SignedInfo>
            <ds:SignatureValue>diLaI72ZXNra+EsenVgkOnbFvH4mcegF3pmRR4DYQ7dhwdu/Jic40QE2WeQXxQDC/9GXqmjIUI/jlR2SjPdEf7NfFYMlsRZrPBGrRZYCr2c08zl2UL/GZQgDZTI3VJ1oVYHN14E2hpamMVtWicz7lrrq2BfvOx3/LBhhRCYq433rWeIa1JeCyyn+2vjlf0BLFRWlKigFyMrZxmpL/53SYmKtobzS+/S9tFi4LNuVdtRvJCuHVjloe7uINvHFrGd3/zSrTgXg4UwJ5MLCp08HnxgrqX0bcp0JjNsQYRRgQWYwarINjCF3ZUG6eWsBX6DytEjUBG+L/o1Z8xKk8FB3sg==</ds:SignatureValue>
            <ds:KeyInfo>
                <ds:X509Data>
                    <ds:X509Certificate>
MIIDRzCCAi+gAwIBAgIEGaZ71jANBgkqhkiG9w0BAQsFADBUMRMwEQYKCZImiZPyLGQBGRYDbmV0
MRYwFAYKCZImiZPyLGQBGRYGc2FtcGxlMRcwFQYKCZImiZPyLGQBGRYHc2FtbHNzbzEMMAoGA1UE
AxMDaWRwMB4XDTE4MDUxMzE2MDA0MloXDTMyMDEyMDE2MDA0MlowVDETMBEGCgmSJomT8ixkARkW
A25ldDEWMBQGCgmSJomT8ixkARkWBnNhbXBsZTEXMBUGCgmSJomT8ixkARkWB3NhbWxzc28xDDAK
BgNVBAMTA2lkcDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ5ovSrOLomGGAoUNbHG
bCUIO3JWrZ2k+exQGMIaet7/J2oIUWRVDFlAUN563T8KbbSeRZnBlOd+1eXPSeG+a1SB1Qv0OR3V
eRYaBZoQLOU+cLSpqxsNsYuCGACztaUE6iRlX0SmUKRrG+OGNxQL3+WqWCh+9t44jpEY6JYCMEJ6
T/1QV0oftC7fUI+0kzzEkbQfE7Ssv+lR+ZAYNzjoODOXLuz2yn/GuwRHEd7n7dQCSWiJx3O5j/vp
fVUAPytrlEBX2y+SYheBPHYIYF5/sKP02cOL2du//OkEJT6R3sLLX6vR/4FSfIL6nzvN+44rvGmZ
AYVlnjD2hz/HNjj0HF8CAwEAAaMhMB8wHQYDVR0OBBYEFEAZU7QprPeC52Dkun+neYzVxlQqMA0G
CSqGSIb3DQEBCwUAA4IBAQByldqVu1itZvx49zM1/6yj3bqTfbhyJ0QZ/EWMQjnyqrTVxOv3MPiA
vReQ/WiBahFwWqi32S0+APKNzPis4NJ+VEwSibONnIMSsCFhzyRZUo1wWtsLGqjJbvPDxlPcDqYn
s9/s6ZOO3PFoaTcUpLwgV3ge3d03dQInt4PtOsMyCsZaw1g6Y6GHKso12vh/K7Q9NieK4naBb78r
sUqwl0VRtwYbUHlAwcT02ZbNLya33EFv8qgUQnyi9H/+b2exVRXPXKHvyzFDg85/I0k+DigBNbO0
gnEXou2NHSSTwZC4LW2QTR0rLjFKDTZKjwgYqMh2rhA3ZnWAyJQVO5hBH07+</ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>
        </ds:Signature>
        <saml2:Subject>
            <saml2:NameID>max</saml2:NameID>
            <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml2:SubjectConfirmationData NotOnOrAfter="2018-05-13T17:36:13.478Z" Recipient="https://localhost:9444/ibm/saml20/defaultSP"/>
            </saml2:SubjectConfirmation>
        </saml2:Subject>
        <saml2:Conditions NotBefore="2018-05-13T16:06:13.478Z" NotOnOrAfter="2018-05-13T17:06:13.478Z">
            <saml2:AudienceRestriction>
                <saml2:Audience/>
            </saml2:AudienceRestriction>
        </saml2:Conditions>
        <saml2:AttributeStatement>
            <saml2:Attribute Name="Membership">
                <saml2:AttributeValue>CN=IdentityRequestors,DC=samlsso,DC=sample,DC=net</saml2:AttributeValue>
                <saml2:AttributeValue>CN=FrontendServiceUsers,DC=samlsso,DC=sample,DC=net</saml2:AttributeValue>
            </saml2:Attribute>
        </saml2:AttributeStatement>
        <saml2:AuthnStatement AuthnInstant="2018-05-13T16:36:13.478Z">
            <saml2:AuthnContext>
                <saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml2:AuthnContextClassRef>
            </saml2:AuthnContext>
        </saml2:AuthnStatement>
    </saml2:Assertion>
</saml2p:Response>
```
* Using https also works (tested in Chrome), but triggers an "Not secure"-warning from the browser
* IdP meta-data generated by https://localhost/idp/SAMLResource
```xml
<?xml version="1.0"?>
<md:EntityDescriptor id="samlsso.sample.net" xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"  validUntil="2022-10-29T22:57:55Z" cacheDuration="PT1478213875S" entityID="samlsso.sample.net" >
  <md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>
MIIDRzCCAi+gAwIBAgIEGaZ71jANBgkqhkiG9w0BAQsFADBUMRMwEQYKCZImiZPyLGQBGRYDbmV0
MRYwFAYKCZImiZPyLGQBGRYGc2FtcGxlMRcwFQYKCZImiZPyLGQBGRYHc2FtbHNzbzEMMAoGA1UE
AxMDaWRwMB4XDTE4MDUxMzE2MDA0MloXDTMyMDEyMDE2MDA0MlowVDETMBEGCgmSJomT8ixkARkW
A25ldDEWMBQGCgmSJomT8ixkARkWBnNhbXBsZTEXMBUGCgmSJomT8ixkARkWB3NhbWxzc28xDDAK
BgNVBAMTA2lkcDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ5ovSrOLomGGAoUNbHG
bCUIO3JWrZ2k+exQGMIaet7/J2oIUWRVDFlAUN563T8KbbSeRZnBlOd+1eXPSeG+a1SB1Qv0OR3V
eRYaBZoQLOU+cLSpqxsNsYuCGACztaUE6iRlX0SmUKRrG+OGNxQL3+WqWCh+9t44jpEY6JYCMEJ6
T/1QV0oftC7fUI+0kzzEkbQfE7Ssv+lR+ZAYNzjoODOXLuz2yn/GuwRHEd7n7dQCSWiJx3O5j/vp
fVUAPytrlEBX2y+SYheBPHYIYF5/sKP02cOL2du//OkEJT6R3sLLX6vR/4FSfIL6nzvN+44rvGmZ
AYVlnjD2hz/HNjj0HF8CAwEAAaMhMB8wHQYDVR0OBBYEFEAZU7QprPeC52Dkun+neYzVxlQqMA0G
CSqGSIb3DQEBCwUAA4IBAQByldqVu1itZvx49zM1/6yj3bqTfbhyJ0QZ/EWMQjnyqrTVxOv3MPiA
vReQ/WiBahFwWqi32S0+APKNzPis4NJ+VEwSibONnIMSsCFhzyRZUo1wWtsLGqjJbvPDxlPcDqYn
s9/s6ZOO3PFoaTcUpLwgV3ge3d03dQInt4PtOsMyCsZaw1g6Y6GHKso12vh/K7Q9NieK4naBb78r
sUqwl0VRtwYbUHlAwcT02ZbNLya33EFv8qgUQnyi9H/+b2exVRXPXKHvyzFDg85/I0k+DigBNbO0
gnEXou2NHSSTwZC4LW2QTR0rLjFKDTZKjwgYqMh2rhA3ZnWAyJQVO5hBH07+

</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:KeyDescriptor use="encryption">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
        <ds:X509Certificate>
MIIDRzCCAi+gAwIBAgIEGaZ71jANBgkqhkiG9w0BAQsFADBUMRMwEQYKCZImiZPyLGQBGRYDbmV0
MRYwFAYKCZImiZPyLGQBGRYGc2FtcGxlMRcwFQYKCZImiZPyLGQBGRYHc2FtbHNzbzEMMAoGA1UE
AxMDaWRwMB4XDTE4MDUxMzE2MDA0MloXDTMyMDEyMDE2MDA0MlowVDETMBEGCgmSJomT8ixkARkW
A25ldDEWMBQGCgmSJomT8ixkARkWBnNhbXBsZTEXMBUGCgmSJomT8ixkARkWB3NhbWxzc28xDDAK
BgNVBAMTA2lkcDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ5ovSrOLomGGAoUNbHG
bCUIO3JWrZ2k+exQGMIaet7/J2oIUWRVDFlAUN563T8KbbSeRZnBlOd+1eXPSeG+a1SB1Qv0OR3V
eRYaBZoQLOU+cLSpqxsNsYuCGACztaUE6iRlX0SmUKRrG+OGNxQL3+WqWCh+9t44jpEY6JYCMEJ6
T/1QV0oftC7fUI+0kzzEkbQfE7Ssv+lR+ZAYNzjoODOXLuz2yn/GuwRHEd7n7dQCSWiJx3O5j/vp
fVUAPytrlEBX2y+SYheBPHYIYF5/sKP02cOL2du//OkEJT6R3sLLX6vR/4FSfIL6nzvN+44rvGmZ
AYVlnjD2hz/HNjj0HF8CAwEAAaMhMB8wHQYDVR0OBBYEFEAZU7QprPeC52Dkun+neYzVxlQqMA0G
CSqGSIb3DQEBCwUAA4IBAQByldqVu1itZvx49zM1/6yj3bqTfbhyJ0QZ/EWMQjnyqrTVxOv3MPiA
vReQ/WiBahFwWqi32S0+APKNzPis4NJ+VEwSibONnIMSsCFhzyRZUo1wWtsLGqjJbvPDxlPcDqYn
s9/s6ZOO3PFoaTcUpLwgV3ge3d03dQInt4PtOsMyCsZaw1g6Y6GHKso12vh/K7Q9NieK4naBb78r
sUqwl0VRtwYbUHlAwcT02ZbNLya33EFv8qgUQnyi9H/+b2exVRXPXKHvyzFDg85/I0k+DigBNbO0
gnEXou2NHSSTwZC4LW2QTR0rLjFKDTZKjwgYqMh2rhA3ZnWAyJQVO5hBH07+

</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>
    
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://localhost/idp/SAMLResponse"/>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST-SimpleSign" Location="https://localhost/idp/SAMLResponse"/>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://localhost/idp/SAMLResponse"/>
 
   
  </md:IDPSSODescriptor>

</md:EntityDescriptor>
```
* Output generated by https://localhost/idp/snoop
```
Requested URL:
https://localhost/idp/snoop
User is max
Authentication information:
 Principal name: max
 Realm: samlsso.sample.net
 Group: CN=IdentityRequestors,DC=samlsso,DC=sample,DC=net
 Group: CN=FrontendServiceUsers,DC=samlsso,DC=sample,DC=net
Request information:
 Request method: GET
 Request URI: /idp/snoop
 Request protocol: HTTP/1.1
 Servlet path: /snoop
 Path info: <none>
 Path translated: <none>
 Query string: <none>
 Content length: <none>
 Content type: <none>
 Server name: localhost
 Server port: 443
 Remote user: max
 Remote address: 0:0:0:0:0:0:0:1
 Remote host: 0:0:0:0:0:0:0:1
 Authorization scheme: BASIC
Request headers:
 Host: localhost
 Connection: keep-alive
 Authorization: Basic bWF4OnBhc3N3MHJk
 Upgrade-Insecure-Requests: 1
 User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.170 Safari/537.36
 Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
 Accept-Encoding: gzip, deflate, br
 Accept-Language: en-US,en;q=0.9
 Cookie: LtpaToken2=oYsXBFW+Z988ySCEyb48EewiIRfxiFqOmluDZKI8+F/OCrJUIls0uEVjr4ZmjAQTPq3ByDolvCIxEU0vXE8wv2yYx5YBquqrUw2FnMMT6on2jG0AIGBI4u+DolDkiNiCVQZUaZ5O2IPADoZcs8KY/HMq5PsjP8aGAncyU0gVjYSQ1nFxSDiYWo+wLXRE5CScrbaYL25ttTXCkZrXdXT1saZ6ZB3ZbUjDsNftGR4ECC1ZKcVjlp8XGjxGUwtMGPeIvWO/4sxvsWy58orxxr6VP/1bpMBHfb2Rf7MfKsfVv3KVgXotyir18oPHIsN2qreO; JSESSIONID=0000TTuB5vXwnYxIpLXGBeBe8lm:7d6caa26-bb41-435e-8a30-e8e59237ec99
HTTPS Information:
Cipher Suite:  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
Java Information:
Java version:  1.8.0_121
Java home:  C:\Program Files\Java\jre1.8.0_121
Java vendor:  Oracle Corporation
Java class version:  52.0
Java class path:
C:\jtools\wlp\bin\tools\ws-server.jar
C:\jtools\wlp\bin\tools\ws-javaagent.jar
```
Step 3a: The FrontendServer needs to be started once for it to create the resource-folder

```
Launching FrontendServer (WebSphere Application Server 18.0.0.1/wlp-1.0.20.cl180120180309-2209) on Java HotSpot(TM) 64-Bit Server VM, version 1.8.0_121-b13 (en_IE)
[AUDIT   ] CWWKE0001I: The server FrontendServer has been launched.
[AUDIT   ] CWWKE0100I: This product is licensed for development, and limited production use. The full license terms can be viewed here: https://public.dhe.ibm.com/ibmdl/export/pub/software/websphere/wasdev/license/base_ilan/ilan/18.0.0.1/lafiles/en.html
[WARNING ] CWWKS3103W: There are no users defined for the BasicRegistry configuration of ID com.ibm.ws.security.registry.basic.config[basic].
[AUDIT   ] CWWKZ0058I: Monitoring dropins for applications.
[AUDIT   ] CWWKI0001I: The CORBA name server is now available at corbaloc:iiop:localhost:2810/NameService.
[AUDIT   ] CWWKT0016I: Web application available (default_host): http://192.168.1.23:9080/FrontendWeb/
[AUDIT   ] CWWKZ0001I: Application Frontend started in 4.828 seconds.
```
Step 3c: Starting the frontend server after adding saml-sp feature 

```
Launching FrontendServer (WebSphere Application Server 18.0.0.1/wlp-1.0.20.cl180120180309-2209) on Java HotSpot(TM) 64-Bit Server VM, version 1.8.0_121-b13 (en_IE)
[AUDIT   ] CWWKE0001I: The server FrontendServer has been launched.
[AUDIT   ] CWWKE0100I: This product is licensed for development, and limited production use. The full license terms can be viewed here: https://public.dhe.ibm.com/ibmdl/export/pub/software/websphere/wasdev/license/base_ilan/ilan/18.0.0.1/lafiles/en.html
[WARNING ] CWWKS3103W: There are no users defined for the BasicRegistry configuration of ID com.ibm.ws.security.registry.basic.config[basic].
[AUDIT   ] CWWKZ0058I: Monitoring dropins for applications.
[AUDIT   ] CWWKI0001I: The CORBA name server is now available at corbaloc:iiop:localhost:2810/NameService.
[WARNING ] CWWKS5207W: The inboundPropagation attribute is set to [false] in the configuration of samlWebSso20 [defaultSP]. The attributes [headerName, audiences] will be ignored during processing.
[WARNING ] CWWKS5207W: The inboundPropagation attribute is set to [false] in the configuration of samlWebSso20 [sp]. The attributes [headerName, audiences] will be ignored during processing.
[AUDIT   ] CWWKT0016I: Web application available (default_host): http://192.168.1.23:9080/ibm/saml20/
[AUDIT   ] CWWKT0016I: Web application available (default_host): http://192.168.1.23:9080/FrontendWeb/
[AUDIT   ] CWWKZ0001I: Application Frontend started in 2.162 seconds.
[AUDIT   ] CWWKF0012I: The server installed the following features: [servlet-3.1, beanValidation-1.1, ssl-1.0, jndi-1.0, jca-1.7, jms-2.0, ejbPersistentTimer-3.2, samlWeb-2.0, appSecurity-2.0, j2eeManagement-1.1, jdbc-4.1, wasJmsServer-1.0, jaxrs-2.0, javaMail-1.5, cdi-1.2, webProfile-7.0, jcaInboundSecurity-1.0, jpa-2.1, wsSecuritySaml-1.1, jsp-2.3, ejbLite-3.2, managedBeans-1.0, jsf-2.2, ejbHome-3.2, jaxws-2.2, localConnector-1.0, jsonp-1.0, el-3.0, jaxrsClient-2.0, concurrent-1.0, appClientSupport-1.0, ejbRemote-3.2, javaee-7.0, jaxb-2.2, mdb-3.2, jacc-1.5, batch-1.0, ejb-3.2, json-1.0, jaspic-1.1, jpaContainer-2.1, wsSecurity-1.1, distributedMap-1.0, websocket-1.1, wasJmsSecurity-1.0, wasJmsClient-2.0].
[AUDIT   ] CWWKF0011I: The server FrontendServer is ready to run a smarter planet.
```

There is a url for downloading the Service Provider metadata, e.g. for our service provider called 'sp' it is: https://localhost:9443/ibm/saml20/sp/samlmetadata

The samlweb-2.0 also sets up a default service provider, for which the meta-data url is: https://localhost:9443/ibm/saml20/defaultSP/samlmetadata

There is an unprojected page https://localhost:9443/FrontendWeb/unprotected.jsp . The application navigates you there after clicking logout. You can also hit it directly.

```
Welcome [WSPrincipal:UNAUTHENTICATED] 
{com.ibm.wsspi.security.cred.uniqueId=user:BasicRealm/UNAUTHENTICATED, com.ibm.wsspi.security.cred.securityName=UNAUTHENTICATED}
```
|Step 3c: Starting the CloudServer for the first time creates the resource directory:

```
Launching CloudServer (WebSphere Application Server 18.0.0.1/wlp-1.0.20.cl180120180309-2209) on Java HotSpot(TM) 64-Bit Server VM, version 1.8.0_121-b13 (en_IE)
[AUDIT   ] CWWKE0001I: The server CloudServer has been launched.
[AUDIT   ] CWWKE0100I: This product is licensed for development, and limited production use. The full license terms can be viewed here: https://public.dhe.ibm.com/ibmdl/export/pub/software/websphere/wasdev/license/base_ilan/ilan/18.0.0.1/lafiles/en.html
[WARNING ] CWWKS3103W: There are no users defined for the BasicRegistry configuration of ID com.ibm.ws.security.registry.basic.config[basic].
[AUDIT   ] CWWKZ0058I: Monitoring dropins for applications.
[AUDIT   ] CWWKS4104A: LTPA keys created in 0.973 seconds. LTPA key file: C:/jtools/wlp/usr/servers/CloudServer/resources/security/ltpa.keys
[AUDIT   ] CWPKI0803A: SSL certificate created in 3.340 seconds. SSL key file: C:/jtools/wlp/usr/servers/CloudServer/resources/security/cloudkey.jks
[AUDIT   ] CWWKI0001I: The CORBA name server is now available at corbaloc:iiop:localhost:2812/NameService.
[AUDIT   ] CWWKE1100I: Waiting for up to 30 seconds for the server to quiesce.
[AUDIT   ] CWWKZ0001I: Application CloudServices started in 17.998 seconds.
[AUDIT   ] CWWKZ0009I: The application CloudServices has stopped successfully.
[AUDIT   ] CWWKF0012I: The server installed the following features: [servlet-3.1, beanValidation-1.1, ssl-1.0, jndi-1.0, jca-1.7, jms-2.0, ejbPersistentTimer-3.2, appSecurity-2.0, j2eeManagement-1.1, jdbc-4.1, wasJmsServer-1.0, jaxrs-2.0, javaMail-1.5, cdi-1.2, webProfile-7.0, jcaInboundSecurity-1.0, jpa-2.1, jsp-2.3, ejbLite-3.2, managedBeans-1.0, jsf-2.2, ejbHome-3.2, jaxws-2.2, localConnector-1.0, jsonp-1.0, el-3.0, jaxrsClient-2.0, concurrent-1.0, appClientSupport-1.0, ejbRemote-3.2, javaee-7.0, jaxb-2.2, mdb-3.2, jacc-1.5, batch-1.0, ejb-3.2, json-1.0, jaspic-1.1, jpaContainer-2.1, distributedMap-1.0, websocket-1.1, wasJmsSecurity-1.0, wasJmsClient-2.0].
[AUDIT   ] CWWKF0011I: The server CloudServer is ready to run a smarter planet.
[AUDIT   ] CWWKI0002I: The CORBA name server is no longer available at corbaloc:iiop:localhost:2812/NameService.
[AUDIT   ] CWWKE0036I: The server CloudServer stopped after 1 minutes, 22.439 seconds.
```
Step 3c.5: Clicking on the CloudService-link

```
Launching CloudServer (WebSphere Application Server 18.0.0.1/wlp-1.0.20.cl180120180309-2209) on Java HotSpot(TM) 64-Bit Server VM, version 1.8.0_121-b13 (en_IE)
[AUDIT   ] CWWKE0001I: The server CloudServer has been launched.
[AUDIT   ] CWWKE0100I: This product is licensed for development, and limited production use. The full license terms can be viewed here: https://public.dhe.ibm.com/ibmdl/export/pub/software/websphere/wasdev/license/base_ilan/ilan/18.0.0.1/lafiles/en.html
[WARNING ] CWWKS3103W: There are no users defined for the BasicRegistry configuration of ID com.ibm.ws.security.registry.basic.config[basic].
[AUDIT   ] CWWKZ0058I: Monitoring dropins for applications.
[AUDIT   ] CWWKI0001I: The CORBA name server is now available at corbaloc:iiop:localhost:2812/NameService.
[AUDIT   ] CWWKT0016I: Web application available (default_host): http://192.168.1.23:9081/CloudServicesEJB/
[AUDIT   ] CWWKZ0001I: Application CloudServices started in 4.919 seconds.
[AUDIT   ] CWWKF0012I: The server installed the following features: [servlet-3.1, beanValidation-1.1, ssl-1.0, jndi-1.0, jca-1.7, jms-2.0, ejbPersistentTimer-3.2, appSecurity-2.0, j2eeManagement-1.1, jdbc-4.1, wasJmsServer-1.0, jaxrs-2.0, javaMail-1.5, cdi-1.2, webProfile-7.0, jcaInboundSecurity-1.0, jpa-2.1, jsp-2.3, ejbLite-3.2, managedBeans-1.0, jsf-2.2, ejbHome-3.2, jaxws-2.2, localConnector-1.0, jsonp-1.0, el-3.0, jaxrsClient-2.0, concurrent-1.0, appClientSupport-1.0, ejbRemote-3.2, javaee-7.0, jaxb-2.2, mdb-3.2, jacc-1.5, batch-1.0, ejb-3.2, json-1.0, jaspic-1.1, jpaContainer-2.1, distributedMap-1.0, websocket-1.1, wasJmsSecurity-1.0, wasJmsClient-2.0].
[AUDIT   ] CWWKF0011I: The server CloudServer is ready to run a smarter planet.
[WARNING ] No assertion builder for type {http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702}TransportBinding registered.
[WARNING ] No assertion builder for type {http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702}TransportToken registered.
[WARNING ] No assertion builder for type {http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702}HttpsToken registered.
[WARNING ] No assertion builder for type {http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702}Layout registered.
[WARNING ] No assertion builder for type {http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702}Lax registered.
[WARNING ] No assertion builder for type {http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702}IncludeTimestamp registered.
[WARNING ] No assertion builder for type {http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702}AlgorithmSuite registered.
[WARNING ] No assertion builder for type {http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702}Basic128 registered.
[WARNING ] No assertion builder for type {http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702}SupportingTokens registered.
[WARNING ] No assertion builder for type {http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702}SamlToken registered.
[WARNING ] No assertion builder for type {http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702}WssSamlV20Token11 registered.
[WARNING ] Interceptor for {http://ejbs.sample.cs.ibm.it/}CloudMessageServiceService has thrown exception, unwinding now
None of the policy alternatives can be satisfied.
```

