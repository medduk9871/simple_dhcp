# Simple_dhcp

## Prerequisite

+ Docker

## Start dhcp server

```
$ ./run.sh
```

## Start dhcp client

```
$ docker exec -it dhcp bash -c "python dhcp_client.py
```

### Test cert verification

```bash
$ python cert_verify.py
```

### How did I generate certificates?

[reference to gen crts](https://www.baeldung.com/openssl-self-signed-cert)

```bash
cd keys
openssl req -newkey rsa:2048 -keyout domain.key -out domain.csr
openssl req -x509 -sha256 -days 1825 -newkey rsa:2048 -keyout issuerCA.key -out issuerCA.crt
openssl x509 -req -CA issuerCA.crt -CAkey issuerCA.key -in domain.csr -out domain.crt -days 365 -CAcreateserial -extfile domain.ext
```
