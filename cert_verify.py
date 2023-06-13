import os

from OpenSSL import crypto


def verify_certificate_chain(cert_data, trusted_cert_datas):
    # Download the certificate from the url and load the certificate
    certificate = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)

    # Create a certificate store and add your trusted certs
    try:
        store = crypto.X509Store()

        # Assuming the certificates are in PEM format in a trusted_certs list
        for cert_data in trusted_cert_datas:
            client_certificate = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)
            store.add_cert(client_certificate)

        # Create a certificate context using the store and the downloaded certificate
        store_ctx = crypto.X509StoreContext(store, certificate)

        # Verify the certificate, returns None if it can validate the certificate
        store_ctx.verify_certificate()

        return True

    except Exception as e:
        # print(e)
        return False


if __name__ == "__main__":
    for crt_name in ['domain.crt', 'rogue.crt']:
        cert_path = os.path.join("keys", crt_name)
        trusted_certs = [os.path.join("keys", "rootCA.crt")]

        if not verify_certificate_chain(cert_path, trusted_certs):
            print(f"{crt_name}: Invalid certificate!")
        else:
            print(f"{crt_name}: Valid certificate!")
