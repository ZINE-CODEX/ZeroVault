# ZeroVault file format (version 1)

A `.zvlt` file is a 38-byte header followed by one or more encrypted chunks. Nothing else is stored: no file name, no timestamps, no length field.

```
+----------------------+----------------+----------------+-----+----------------+
| header (38 bytes)    | chunk 0        | chunk 1        | ... | last chunk     |
+----------------------+----------------+----------------+-----+----------------+
                         ciphertext+tag   ciphertext+tag         ciphertext+tag
```

## Header (all integers big-endian)

| Offset | Size | Field | Notes |
|---:|---:|---|---|
| 0 | 4 | Magic | ASCII `ZVLT` (`5A 56 4C 54`) |
| 4 | 1 | Version | `1` |
| 5 | 1 | KDF id | `1` = PBKDF2-HMAC-SHA256 |
| 6 | 4 | Iterations | PBKDF2 rounds. Accepted range on read: 1,000 to 10,000,000 |
| 10 | 4 | Chunk size | Plaintext bytes per chunk. Accepted range: 1 to 64 MiB |
| 14 | 16 | Salt | Random, unique per file |
| 30 | 8 | IV prefix | Random, unique per file |

The header is not secret. It is authenticated, though (see AAD below), so editing it makes decryption fail.

## Key derivation

```
key = PBKDF2-HMAC-SHA256(password = NFKC(password) as UTF-8,
                         salt     = header.salt,
                         rounds   = header.iterations,
                         length   = 256 bits)
```

## Chunks

The plaintext is split into chunks of `chunk size` bytes; the last chunk may be shorter. An empty file is stored as one empty chunk. Each chunk is encrypted with AES-256-GCM (128-bit tag):

| Input | Value |
|---|---|
| Key | The derived key above |
| IV (12 bytes) | `header.ivPrefix` (8 bytes) + chunk index as uint32 (4 bytes) |
| AAD | `header` (38 bytes) + chunk index as uint32 (4 bytes) + final flag (1 byte: `1` for the last chunk, else `0`) |

Each stored chunk is `ciphertext || 16-byte tag`, so every chunk except possibly the last is exactly `chunk size + 16` bytes.

## Why the AAD looks like this

| AAD part | Attack it stops |
|---|---|
| Header | Editing salt, iterations or chunk size |
| Chunk index | Reordering or duplicating chunks |
| Final flag | Truncation: removing trailing chunks leaves a last chunk that was not flagged final, so it fails to authenticate |

## Decryption outline

1. Read 38 bytes, check magic, version, KDF id and the numeric ranges.
2. `body = fileSize - 38`. `chunkCount = ceil(body / (chunkSize + 16))`. The last chunk must be at least 16 bytes.
3. Derive the key.
4. For each chunk `i`, decrypt with `final = (i == chunkCount - 1)`. Any failure means wrong password or modified data (GCM cannot tell which).

## Size overhead

`encrypted size = plaintext size + 38 + 16 * chunkCount`. Example: 2,500,000 bytes at 1 MiB chunks gives 3 chunks, so 2,500,000 + 38 + 48 = 2,500,086 bytes.

## Versioning

A future format change must bump the version byte. Readers reject versions they do not know.
