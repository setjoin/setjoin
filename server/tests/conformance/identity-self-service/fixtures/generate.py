#!/usr/bin/env python3
"""Create #494's owned test certificates once (cryptography, never custom crypto).

The RSA key is the repository's existing SMTP oracle key. Generated EC material
is test-only. Refuse replacement: immutable HTTP captures depend on these bytes.
"""
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

HERE = Path(__file__).resolve().parent
RUST = HERE.parents[3]
NAMES = ("recipient.pem", "expired.pem", "no-email.pem", "sign-only.pem", "ec.pem", "ec-key.pem")
assert not any((HERE / name).exists() for name in NAMES), "fixture bytes already exist"
rsa_key = serialization.load_pem_private_key(
    (RUST / "crates/protocols/smtp/oracle/auth-fixture/rsa.pem").read_bytes(), None
)
ec_key = ec.generate_private_key(ec.SECP256R1())
name = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Setjoin Oracle"),
                  x509.NameAttribute(NameOID.COMMON_NAME, "IDLOGIN4")])
for index, filename in enumerate(NAMES[:-1]):
    key = ec_key if filename == "ec.pem" else rsa_key
    expired = filename == "expired.pem"
    builder = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
               .public_key(key.public_key()).serial_number(49401 + index)
               .not_valid_before(datetime(2020 if expired else 2026, 10, 1, tzinfo=timezone.utc))
               .not_valid_after(datetime(2021 if expired else 2095, 10, 1, tzinfo=timezone.utc)))
    if filename != "no-email.pem":
        builder = builder.add_extension(x509.SubjectAlternativeName([
            x509.RFC822Name("Person@EXAMPLE.NET")]), critical=False)
    builder = builder.add_extension(x509.KeyUsage(
        digital_signature=True, content_commitment=False,
        key_encipherment=filename != "sign-only.pem", data_encipherment=False,
        key_agreement=False, key_cert_sign=False, crl_sign=False,
        encipher_only=None, decipher_only=None), critical=True)
    wire = builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)
    with (HERE / filename).open("xb") as out:
        out.write(wire)
with (HERE / "ec-key.pem").open("xb") as out:
    out.write(ec_key.private_bytes(serialization.Encoding.PEM,
                                   serialization.PrivateFormat.PKCS8,
                                   serialization.NoEncryption()))
