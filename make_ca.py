#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""This is the script used to generate a new CA."""
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

from datetime import datetime

def main():
    """
    Main function
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
    public_key = private_key.public_key()
    name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"BR"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Luz"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"Luz Root"),])
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(name)

    certificate_not_before = datetime.utcnow()
    certificate_not_after = datetime(2049, 12, 31, hour=23, minute=59, second=59)
    builder = builder.not_valid_before(certificate_not_before)
    builder = builder.not_valid_after(certificate_not_after)

    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(public_key)
    builder = builder.issuer_name(name)

    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=None,
            decipher_only=None),
        critical=True)

    builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)

    builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False)

    certificate = builder.sign(private_key=private_key, algorithm=hashes.SHA512(), backend=default_backend())

    cert_pem = certificate.public_bytes(Encoding.PEM)
    with open("ca.crt", "w") as text_file:
        text_file.write(cert_pem.decode())
    privkey_pem = private_key.private_bytes( encoding=Encoding.PEM, format=PrivateFormat.TraditionalOpenSSL, encryption_algorithm=NoEncryption() )
    #privkey with password = BestAvailableEncryption(b"password")
    with open("ca.key", "w") as text_file:
        text_file.write(privkey_pem.decode())

if __name__ == '__main__':
    main()
