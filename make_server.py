#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""This is the script used to generate a server cert."""
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, load_pem_private_key

from datetime import datetime

def main():
    with open("ca.crt", 'rb') as cacert_file:
        cacert = x509.load_pem_x509_certificate(cacert_file.read(), default_backend())
    with open("ca.key", 'rb') as cakey_file:
        cakey = load_pem_private_key(cakey_file.read(), password=None, backend=default_backend())

    name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"BR"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Luz"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"gabrielluz.com"),])

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
    public_key = private_key.public_key()

    builder = x509.CertificateBuilder()

    builder = builder.subject_name(name)

    builder = builder.public_key(public_key)

    builder = builder.issuer_name(cacert.subject)

    certificate_not_before = datetime.utcnow()
    certificate_not_after = datetime(2049, 12, 31, hour=23, minute=59, second=59)

    builder = builder.not_valid_before(certificate_not_before)
    builder = builder.not_valid_after(certificate_not_after)

    certificate_serial_number = x509.random_serial_number()
    builder = builder.serial_number(certificate_serial_number)

    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True)

    builder = builder.add_extension(x509.SubjectAlternativeName([
        x509.DNSName("gabrielluz.com")]), critical=False)

    builder = builder.add_extension(x509.ExtendedKeyUsage([
        ExtendedKeyUsageOID.SERVER_AUTH]), critical=True)

    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=None,
            decipher_only=None),
        critical=True)

    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(public_key),
        critical=False)

    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(cacert.public_key()),
        critical=False) #from_issuer_subject_public_key if CA certs does contain this extension

    certificate = builder.sign(private_key=cakey, algorithm=hashes.SHA512(), backend=default_backend())

    cert_pem = certificate.public_bytes(Encoding.PEM)
    with open("server.crt", "w") as text_file:
        text_file.write(cert_pem.decode())

    privkey_pem = private_key.private_bytes( encoding=Encoding.PEM, format=PrivateFormat.TraditionalOpenSSL, encryption_algorithm=NoEncryption() )
    #privkey with password = BestAvailableEncryption(b"password")

    with open("server.key", "w") as text_file:
        text_file.write(privkey_pem.decode())

if __name__ == '__main__':
    main()
