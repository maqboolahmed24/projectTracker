# Identity provisioning and licence issuance

These commands are trusted deployment operations. They do not expose licence issuance over HTTP, give the operator an application Owner account, or provide customer content keys. Run them from a restricted operating-system account with the deployment's runtime control-database credentials. Do not load `.env.admin` into these processes.

## Create persistent operational identity once

After installing dependencies and building, run:

```sh
node --env-file-if-exists=.env dist/scripts/setup-identity.js --origin https://your-application.example
```

The command exclusively creates `.env.identity` with mode `0600`. `--output` can select another private file. `--origin` defaults to `APP_ORIGIN`, or `http://localhost:3400` for local development; production mode requires HTTPS. It writes a generated OPAQUE server setup and service master key, version IDs, and the fixed authentication identity. It prints no secret values and refuses an existing path, including a symbolic link.

Keep this file out of Git and image layers. Load its values through the deployment's secret mechanism, alongside the ordinary runtime configuration. Back up the operational identity securely. A restart reuses these values; running setup again is not a rotation procedure. Changing the OPAQUE setup invalidates existing password registrations, and changing the service master key invalidates existing verifiers and protected protocol state unless an explicit versioned migration preserves them. The authentication identity remains the original registered identity even if a later deployment changes its public address.

## Issue an entitlement into a private file

```sh
node --env-file-if-exists=.env --env-file=.env.identity dist/scripts/licence.js issue --output /private/location/licence.json
```

The parent directory must already exist. The command exclusively creates a `0600` JSON file containing the licence ID and its `LIC-…` activation key. It does not print the key. The control database stores the keyed verification digest and operational key ID; the entitlement starts as `available`. Deliver the activation key through the intended private handover channel. Issuance does not activate a workspace or create an Owner.

The command opens the output before touching the database, then inserts within a transaction, writes and synchronizes the key file and parent directory, and commits. A write failure rolls back the insertion and removes the command's partial output. An existing output is never overwritten. If the database connection fails during COMMIT, the result may be uncertain: the already-synchronized private file is retained. Use its licence ID to inspect `security.licences` through an authorised operational connection before retrying; do not discard the only copy of a possibly issued key. A new command must not silently replace that file or assume that another entitlement is required.

Both commands emit fixed error categories rather than filesystem paths, connection strings, input values, or raw database errors. The configuration and entitlement files themselves intentionally contain secrets and must not be copied into logs, support messages, or test output.

## Change an existing entitlement

The same trusted CLI delegates to the entitlement service for `revoke`, `legacy-expire`, or `reinstate`:

```sh
node --env-file-if-exists=.env --env-file=.env.identity dist/scripts/licence.js revoke --licence-id <licence-uuid> --operation-id <stable-operation-uuid> --operator-id <operator-audit-uuid>
```

Supply a distinct operation UUID for each intended change; retry an interrupted call with the same action, IDs, and operator. These IDs are required rather than generated silently. Operating-system/deployment access authenticates the operator; `operator-id` records audit attribution and is not an application login credential. The command prints only the public receipt and projection status, never a licence key or operational secret. Existing workspace restrictions use the security fence and preserve recovery and read access according to the entitlement policy; reinstatement does not issue a replacement activation key.
