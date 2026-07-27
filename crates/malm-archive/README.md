# malm-archive

`malm-archive` verifies a declared archive stream and converts it into Malm tree
objects. It is for ingestion code that accepts archives from untrusted sources.

The crate exists to make archive conversion safe and repeatable without direct
extraction. A frozen decoder profile, exact declaration, bounded work, and
canonical tree encoding give each accepted input a stable interpretation and identity.

## Declare And Bound Input

`ArchiveDeclarationV1::posix_ustar` binds the expected byte length and SHA-256
digest to the supported uncompressed POSIX ustar profile. `ArchiveLimitsV1`
bounds payload size, expanded content, paths, entries, retained objects, reads,
and decoder work.

## Convert A Stream

`decode_archive_v1` reads any caller-provided `std::io::Read`, verifies the full
declaration, and applies the selected limits. `decode_posix_ustar_v1` is the
shorter entry point for the same fixed profile.

```rust
use malm_archive::{
    ArchiveDecodeError, ArchiveDeclarationV1, ArchiveLimitsV1, DecodedArchiveV1,
    decode_archive_v1,
};
use malm_types::Digest;

fn convert(payload: &[u8]) -> Result<DecodedArchiveV1, ArchiveDecodeError> {
    let declaration = ArchiveDeclarationV1::posix_ustar(
        malm_types::usize_to_u64(payload.len()),
        Digest::sha256(payload),
    );
    decode_archive_v1(payload, declaration, ArchiveLimitsV1::default())
}
```

## Use The Result

`DecodedArchiveV1` exposes the verified graph, canonical object bytes, root
digest, and provenance recording the exact declaration, decoder identity, and root.

## Boundary

The crate accepts only uncompressed POSIX ustar and returns in-memory objects;
it never opens destination paths or extracts archive entries onto a host.

See the [archive/v1 schema](../../schemas/archive/v1/README.md), the resulting
[tree/v1 objects](../../schemas/tree/v1/README.md), and the [crate API](src/lib.rs).
