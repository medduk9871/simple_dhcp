from OpenSSL import crypto
import os, sys

def verify_certificate_chain(cert_path, trusted_certs):
    # Download the certificate from the url and load the certificate
    cert_file = open(cert_path, 'rb')
    cert_data = cert_file.read()
    certificate = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)

    #Create a certificate store and add your trusted certs
    try:
        store = crypto.X509Store()

        # Assuming the certificates are in PEM format in a trusted_certs list
        for _cert in trusted_certs:
            cert_file = open(_cert, 'rb')
            cert_data = cert_file.read()
            client_certificate = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)
            store.add_cert(client_certificate)

        # Create a certificate context using the store and the downloaded certificate
        store_ctx = crypto.X509StoreContext(store, certificate)

        # Verify the certificate, returns None if it can validate the certificate
        store_ctx.verify_certificate()

        return True

    except Exception as e:
        print(e)
        return False

if __name__ == "__main__":
    cert_path = os.path.join("keys", "domain.crt")
    trusted_certs = [os.path.join("keys", "rootCA.crt")]

    if not verify_certificate_chain(cert_path, trusted_certs):
        print("Invalid certificate!")
        sys.exit(1)

    print("Valid certificate!")
    sys.exit(0)