

# How to implement mTLS and lock it down to SPECIFIC  client certs on F5s. [Blatantly stolen from here](https://www.docusign.com/blog/dsdev-configuring-f5-load-balancer-mutual-tls/)


Requirements:
1. Need the clients public cert in PEM format (human readable vs DER which is in binary.)
2. Need access to openssl to run "fingerprint" commands.
3. High enough level of access on the F5 to create iRules & iRules:Data Group Lists
4. Previously configured Client SSL Profile where: 
	- we've set the client Auth section to have Client Certificate=require
	- Frequency=Always
	- added our appropriate CA bundle to the Trusted Cert Authorities.
5. Patience...


## First, get the fingerprint in MD5 of the client cert you're trying to whitelist access to the F5 VIP.

Copy the client's public cert file to a location where you can run openssl commands against it.

Now, execute:
```
openssl x509 -noout -fingerprint -md5 -inform pem -in ./<THE_CERT_NAME.CRT>
```

You should get an out put like so:

```
SOMEUSER@SOMESERVER:~/testcerts$ openssl x509 -noout -fingerprint -md5 -inform pem -in ./api.example.com.crt
MD5 Fingerprint=B8:C7:47:20:88:E8:BA:9D:C9:10:3E:E9:79:AC:20:BB
SOMEUSER@SOMESERVER:~/testcerts$
```

You need the MD5 hash or "fingerprint" of the cert to be in LOWERCASE! You can do this via Notepad++ by copying it into a new Notepad++ file, select it, right click it, and select 'lowercase' on the dropdown menu.

B8:C7:47:20:88:E8:BA:9D:C9:10:3E:E9:79:AC:20:BB

is now...

b8:c7:47:20:88:e8:ba:9d:c9:10:3e:e9:79:ac:20:bb

## Now, we'll add the F5 iRule to the F5, create a custom iRules:Data Group List, add our CN=<FQDN_OF_CERT> and MD5 hash.

Add the following F5 iRule as a new iRule:

```
when CLIENTSSL_HANDSHAKE {
    set subject_dn [X509::subject [SSL::cert 0]]
    set cert_hash [X509::hash [SSL::cert 0]]
    set cSSLSubject [findstr $subject_dn "CN=" 0 ","]
    #log local0. "Subject = $subject_dn, Hash = $cert_hash and $cSSLSubject"

    # Check if the client certificate contains the correct CN and
    # Thumbprint from the <MEANINGFUL_DATA_GROUP_LIST_NAME> lookup table
    set Expected_hash [class match -value $cSSLSubject eq <MEANINGFUL_DATA_GROUP_LIST_NAME>]

    #log local0. "Check Expected Hash = $Expected_hash, Hash received = $cert_hash"
    if { $Expected_hash != $cert_hash } {
        #log local0. "Thumbprint presented doesn't match mythumbprints. Expected Hash = $Expected_hash, Hash received = $cert_hash"
        reject
    }
}

```

Where <MEANINGFUL_DATA_GROUP_LIST_NAME> needs to be replaced with the actual name of your Data Group List Object. For example, <MEANINGFUL_DATA_GROUP_LIST_NAME> could be replaced with MyService_Prod_Cert_Whitelist

So...

```
    set Expected_hash [class match -value $cSSLSubject eq MyService_Prod_Cert_Whitelist]

```

Create the iRule:Data Group List object as a type String and add the String=CN=<FQDN_OF_CERT> with a value of our lowercase MD5 hash.

Add it and then click Update!


Finally, add the F5 iRule to your F5 VIP! DONE!!


References:

https://devcentral.f5.com/articles/ssl-profiles-part-8-client-authentication (Specifically this sentence..."This provides some level of identification, but it provides very little access control since almost any valid client certificate could be authenticated...")

https://devcentral.f5.com/articles/irules-event-order-  (Shows iRules Event Order)

https://knowledge.digicert.com/solution/SO28771.html (How to get various fingerprints from a cert file!)

https://www.docusign.com/blog/dsdev-configuring-f5-load-balancer-mutual-tls/ (How to specifically whitelist a cert(s) to access an F5 VIP!)

_Special thanks to Clyde Councill for pointing me in the right direction!_




