# Start here

Use this page when the documentation has been extracted onto an offline
workstation.

## If you are running the implemented internal A0 lane

Read [quickstart.md](quickstart.md), then use the **Current A0** sections in
[command-reference.md](command-reference.md). The flow is local and read-only:

```text
registry -> PowerShell collector -> validate -> report -> inspect locally
```

Only create an A0 handling or decision-use receipt after the named event really
occurred. A0 output cannot be imported as a V1A product assessment.

## If you are using or reviewing the default-OFF V1A contract

Read [command-reference.md](command-reference.md),
[compatibility-and-vocabulary.md](compatibility-and-vocabulary.md), and
[generated-content-and-manifests.md](generated-content-and-manifests.md). The
`mailctl exchange assess ...` commands, reducer/API workflow, unified admin UI,
encrypted server custody, signed publication/deletion receipts, registry compiler,
and hermetic verification lanes are implemented with their feature toggle OFF.
This implementation status does not supply controlled-Exchange, customer,
signed-package, representative-scale, or human acceptance evidence.

## If a command failed

Start with [troubleshooting.md](troubleshooting.md). Preserve the artifact and
diagnostic ID before retrying. Do not disable TLS, signature, version,
redaction, authorization, or completeness checks to make a run proceed.

## If you are transferring files without a network

Read [air-gapped-transfer.md](air-gapped-transfer.md). The A0 lane has no product
import path. V1A `bundle.sja` is strict integrity-bound JSON for inspection and
import, not source-side ciphertext; use approved encrypted transfer media. The
server encrypts accepted artifacts at rest and issues signed lifecycle receipts.
