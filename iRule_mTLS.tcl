


when CLIENTSSL_HANDSHAKE {
    set subject_dn [X509::subject [SSL::cert 0]]
    set cert_hash [X509::hash [SSL::cert 0]]
    set cSSLSubject [findstr $subject_dn "CN=" 0 ","]
    #log local0. "Subject = $subject_dn, Hash = $cert_hash and $cSSLSubject"

    # Check if the client certificate contains the correct CN and
    # Thumbprint from the AuthThumb lookup table
    set Expected_hash [class match -value $cSSLSubject eq AuthThumb]

    #log local0. "Check Expected Hash = $Expected_hash, Hash received = $cert_hash"
    if { $Expected_hash != $cert_hash } {
        #log local0. "Thumbprint presented doesn't match mythumbprints. Expected Hash = $Expected_hash, Hash received = $cert_hash"
        reject
    }
}
