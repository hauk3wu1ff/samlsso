## Configure a service provider-initiated SSO with identity propagation

This is an IBM Websphere Liberty SAML SSO example described in this [article](https://www.ibm.com/developerworks/library/mw-1703-maurip1-bluemix/index.html).

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

