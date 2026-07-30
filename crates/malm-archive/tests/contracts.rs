use std::{
    cell::Cell,
    io::{self, Cursor, Read},
    rc::Rc,
};

use malm_archive::{
    ARCHIVE_DECODER_IDENTITY_V1, ArchiveCompressionV1, ArchiveContainerV1, ArchiveDeclarationV1,
    ArchiveDecodeError, ArchiveLimitsV1, ArchiveResourceV1, USTAR_BLOCK_BYTES, decode_archive_v1,
};
use malm_tree::{TreeEntryKindV1, encode_file_object_v1, file_object_digest_v1};
use malm_types::Digest;

const EMPTY_USTAR: &str =
    include_str!("../../../schemas/archive/v1/fixtures/golden/empty-ustar.hex");
const POSIX_VARIANT_USTAR: &str =
    include_str!("../../../schemas/archive/v1/fixtures/golden/posix-variant-ustar.hex");
const SINGLE_ZERO_BLOCK: &str =
    include_str!("../../../schemas/archive/v1/fixtures/malformed/single-zero-block.hex");
const GOLDEN_DIGESTS: &str =
    include_str!("../../../schemas/archive/v1/fixtures/golden/digests.txt");

#[derive(Clone)]
struct TarEntry {
    header: [u8; USTAR_BLOCK_BYTES],
    data: Vec<u8>,
}

fn write_octal(field: &mut [u8], mut value: u64) {
    assert!(field.len() >= 2);
    let digits = field.len() - 1;
    field.fill(b'0');
    *field.last_mut().unwrap() = 0;
    for byte in field[..digits].iter_mut().rev() {
        *byte = b'0' + (value & 7) as u8;
        value >>= 3;
    }
    assert_eq!(value, 0, "octal value does not fit fixture field");
}

fn write_octal_digits(field: &mut [u8], mut value: u64) {
    field.fill(b'0');
    for byte in field.iter_mut().rev() {
        *byte = b'0' + (value & 7) as u8;
        value >>= 3;
    }
    assert_eq!(value, 0, "octal value does not fit fixture field");
}

/// Writes one POSIX numeric field as `leading` spaces, `digits` octal digits,
/// then a tail of `terminator` bytes.
///
/// It models the space-terminated, short, and leading-space forms POSIX permits
/// and `write_octal` never emits.
fn write_posix_octal(
    field: &mut [u8],
    mut value: u64,
    leading: usize,
    digits: usize,
    terminator: u8,
) {
    assert!(
        leading + digits < field.len(),
        "field needs a terminator byte"
    );
    field.fill(terminator);
    field[..leading].fill(b' ');
    for byte in field[leading..leading + digits].iter_mut().rev() {
        *byte = b'0' + (value & 7) as u8;
        value >>= 3;
    }
    assert_eq!(value, 0, "octal value does not fit fixture field");
}

/// One POSIX-legal spelling of the eight-byte checksum field.
#[derive(Clone, Copy)]
enum ChecksumShape {
    /// Six digits, NUL, space: the historical canonical form.
    DigitsNulSpace,
    /// Six digits, space, NUL.
    DigitsSpaceNul,
    /// Seven digits, NUL.
    SevenDigitsNul,
    /// One leading space, six digits, NUL.
    SpaceDigitsNul,
}

/// Recomputes the checksum over the block and stores it in `shape`.
///
/// Every shape sums the block with the field read as eight spaces, so all of
/// them describe the same header.
fn set_checksum_shape(header: &mut [u8; USTAR_BLOCK_BYTES], shape: ChecksumShape) {
    header[148..156].fill(b' ');
    let sum = header.iter().map(|byte| u64::from(*byte)).sum();
    match shape {
        ChecksumShape::DigitsNulSpace => {
            write_octal_digits(&mut header[148..154], sum);
            header[154] = 0;
            header[155] = b' ';
        }
        ChecksumShape::DigitsSpaceNul => {
            write_octal_digits(&mut header[148..154], sum);
            header[154] = b' ';
            header[155] = 0;
        }
        ChecksumShape::SevenDigitsNul => {
            write_octal_digits(&mut header[148..155], sum);
            header[155] = 0;
        }
        ChecksumShape::SpaceDigitsNul => {
            header[148] = b' ';
            write_octal_digits(&mut header[149..155], sum);
            header[155] = 0;
        }
    }
}

fn write_text(field: &mut [u8], value: &[u8]) {
    assert!(value.len() <= field.len());
    field[..value.len()].copy_from_slice(value);
}

fn write_path(header: &mut [u8; USTAR_BLOCK_BYTES], path: &[u8]) {
    if path.len() <= 100 {
        write_text(&mut header[0..100], path);
        return;
    }
    let split = path
        .iter()
        .enumerate()
        .rev()
        .find_map(|(index, byte)| {
            (*byte == b'/' && index <= 155 && path.len() - index - 1 <= 100).then_some(index)
        })
        .expect("fixture path can be represented by ustar prefix/name");
    write_text(&mut header[345..500], &path[..split]);
    write_text(&mut header[0..100], &path[split + 1..]);
}

fn set_checksum(header: &mut [u8; USTAR_BLOCK_BYTES]) {
    header[148..156].fill(b' ');
    let sum = header.iter().map(|byte| u64::from(*byte)).sum();
    write_octal_digits(&mut header[148..154], sum);
    header[154] = 0;
    header[155] = b' ';
}

fn header(
    path: &[u8],
    mode: u64,
    size: u64,
    typeflag: u8,
    link: &[u8],
    metadata_seed: u64,
) -> [u8; USTAR_BLOCK_BYTES] {
    let mut header = [0_u8; USTAR_BLOCK_BYTES];
    write_path(&mut header, path);
    write_octal(&mut header[100..108], mode);
    write_octal(&mut header[108..116], metadata_seed);
    write_octal(&mut header[116..124], metadata_seed + 1);
    write_octal(&mut header[124..136], size);
    write_octal(&mut header[136..148], 1_700_000_000 + metadata_seed);
    header[156] = typeflag;
    write_text(&mut header[157..257], link);
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    write_text(
        &mut header[265..297],
        format!("user{metadata_seed}").as_bytes(),
    );
    write_text(
        &mut header[297..329],
        format!("group{metadata_seed}").as_bytes(),
    );
    write_octal(&mut header[329..337], 0);
    write_octal(&mut header[337..345], 0);
    set_checksum(&mut header);
    header
}

fn regular(path: &[u8], mode: u64, data: &[u8], metadata_seed: u64) -> TarEntry {
    TarEntry {
        header: header(path, mode, data.len() as u64, b'0', b"", metadata_seed),
        data: data.to_vec(),
    }
}

fn directory(path: &[u8], mode: u64, metadata_seed: u64) -> TarEntry {
    TarEntry {
        header: header(path, mode, 0, b'5', b"", metadata_seed),
        data: Vec::new(),
    }
}

fn symlink(path: &[u8], target: &[u8], metadata_seed: u64) -> TarEntry {
    TarEntry {
        header: header(path, 0o777, 0, b'2', target, metadata_seed),
        data: Vec::new(),
    }
}

/// Builds the same logical entry as `header`, using the space-terminated,
/// leading-space, and short numeric forms other POSIX writers emit, blank device
/// fields, and the conventional directory trailing slash.
fn posix_variant_header(
    path: &[u8],
    mode: u64,
    size: u64,
    typeflag: u8,
    link: &[u8],
    metadata_seed: u64,
) -> [u8; USTAR_BLOCK_BYTES] {
    let mut header = [0_u8; USTAR_BLOCK_BYTES];
    let mut name = path.to_vec();
    if typeflag == b'5' {
        name.push(b'/');
    }
    write_path(&mut header, &name);
    write_posix_octal(&mut header[100..108], mode, 2, 4, b' ');
    write_posix_octal(&mut header[108..116], metadata_seed, 0, 7, b' ');
    write_posix_octal(&mut header[116..124], metadata_seed + 1, 1, 4, 0);
    write_posix_octal(&mut header[124..136], size, 0, 11, b' ');
    write_posix_octal(
        &mut header[136..148],
        1_700_000_000 + metadata_seed,
        0,
        11,
        b' ',
    );
    header[156] = typeflag;
    write_text(&mut header[157..257], link);
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    write_text(
        &mut header[265..297],
        format!("user{metadata_seed}").as_bytes(),
    );
    write_text(
        &mut header[297..329],
        format!("group{metadata_seed}").as_bytes(),
    );
    header[329..345].fill(b' ');
    set_checksum_shape(&mut header, ChecksumShape::DigitsSpaceNul);
    header
}

fn posix_regular(path: &[u8], mode: u64, data: &[u8], metadata_seed: u64) -> TarEntry {
    TarEntry {
        header: posix_variant_header(path, mode, data.len() as u64, b'0', b"", metadata_seed),
        data: data.to_vec(),
    }
}

fn posix_directory(path: &[u8], mode: u64, metadata_seed: u64) -> TarEntry {
    TarEntry {
        header: posix_variant_header(path, mode, 0, b'5', b"", metadata_seed),
        data: Vec::new(),
    }
}

fn posix_symlink(path: &[u8], target: &[u8], metadata_seed: u64) -> TarEntry {
    TarEntry {
        header: posix_variant_header(path, 0o777, 0, b'2', target, metadata_seed),
        data: Vec::new(),
    }
}

/// Rebuilds a one-entry archive after `mutate` edits its first header,
/// recomputing the checksum so the mutation is what fails.
fn mutated_archive(mutate: impl FnOnce(&mut [u8; USTAR_BLOCK_BYTES])) -> Vec<u8> {
    let mut bytes = archive([regular(b"file", 0o644, b"", 0)]);
    let header: &mut [u8; USTAR_BLOCK_BYTES] =
        (&mut bytes[..USTAR_BLOCK_BYTES]).try_into().unwrap();
    mutate(header);
    set_checksum(header);
    bytes
}

/// Overwrites the checksum field verbatim, after `set_checksum` has run.
fn set_raw_checksum(bytes: &mut [u8], field: &[u8; 8]) {
    bytes[148..156].copy_from_slice(field);
}

fn typed_entry(typeflag: u8) -> TarEntry {
    TarEntry {
        header: header(b"entry", 0o644, 0, typeflag, b"target", 0),
        data: Vec::new(),
    }
}

fn archive(entries: impl IntoIterator<Item = TarEntry>) -> Vec<u8> {
    let mut bytes = Vec::new();
    for entry in entries {
        bytes.extend_from_slice(&entry.header);
        bytes.extend_from_slice(&entry.data);
        let remainder = entry.data.len() % USTAR_BLOCK_BYTES;
        if remainder != 0 {
            bytes.resize(bytes.len() + USTAR_BLOCK_BYTES - remainder, 0);
        }
    }
    bytes.resize(bytes.len() + 2 * USTAR_BLOCK_BYTES, 0);
    bytes
}

fn declaration(bytes: &[u8]) -> ArchiveDeclarationV1 {
    ArchiveDeclarationV1::posix_ustar(bytes.len() as u64, Digest::sha256(bytes))
}

fn decode(bytes: &[u8]) -> Result<malm_archive::DecodedArchiveV1, ArchiveDecodeError> {
    decode_archive_v1(
        Cursor::new(bytes),
        declaration(bytes),
        ArchiveLimitsV1::default(),
    )
}

fn decode_with_limits(
    bytes: &[u8],
    limits: ArchiveLimitsV1,
) -> Result<malm_archive::DecodedArchiveV1, ArchiveDecodeError> {
    decode_archive_v1(Cursor::new(bytes), declaration(bytes), limits)
}

fn decode_hex(value: &str) -> Vec<u8> {
    let digits = value
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    assert_eq!(digits.len() % 2, 0);
    digits
        .chunks_exact(2)
        .map(|pair| (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]))
        .collect()
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => panic!("invalid fixture hex byte {byte:#x}"),
    }
}

fn golden_digest(name: &str) -> &str {
    let prefix = format!("{name}=");
    GOLDEN_DIGESTS
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("missing archive golden digest {name}"))
}

fn assert_resource(error: ArchiveDecodeError, expected: ArchiveResourceV1) {
    assert!(
        matches!(
            &error,
            ArchiveDecodeError::ResourceLimitExceeded { resource, .. } if *resource == expected
        ),
        "unexpected error: {error}"
    );
}

#[test]
fn empty_golden_fixture_has_frozen_payload_and_root_identities() {
    let bytes = decode_hex(EMPTY_USTAR);
    assert_eq!(bytes.len(), 1024);
    assert_eq!(
        Digest::sha256(&bytes).as_str(),
        golden_digest("empty-ustar-payload")
    );

    let decoded = decode(&bytes).unwrap();
    assert_eq!(
        decoded.root_digest().as_str(),
        golden_digest("empty-root-tree")
    );
    assert!(decoded.tree_graph().root().entries().is_empty());
    assert!(decoded.objects().file_blobs().is_empty());
    assert!(decoded.objects().symlinks().is_empty());
    assert_eq!(decoded.objects().trees().len(), 1);
    assert_eq!(decoded.provenance().decoder(), ARCHIVE_DECODER_IDENTITY_V1);
    assert_eq!(
        decoded.provenance().declaration().container(),
        ArchiveContainerV1::Tar
    );
    assert_eq!(
        decoded.provenance().declaration().compression(),
        ArchiveCompressionV1::None
    );
}

#[test]
fn declaration_and_provenance_schema_projections_match_models_and_fixture_categories() {
    let declaration_schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/archive/v1/declaration.schema.json"
    ))
    .unwrap();
    let provenance_schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/archive/v1/provenance.schema.json"
    ))
    .unwrap();
    jsonschema::meta::validate(&declaration_schema).unwrap();
    jsonschema::meta::validate(&provenance_schema).unwrap();

    let declaration_validator = jsonschema::validator_for(&declaration_schema).unwrap();
    let mut resolved_provenance_schema = provenance_schema;
    resolved_provenance_schema["properties"]["declaration"] = declaration_schema;
    let provenance_validator = jsonschema::validator_for(&resolved_provenance_schema).unwrap();

    let golden_declaration: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/archive/v1/fixtures/golden/declaration.json"
    ))
    .unwrap();
    let valid_declaration: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/archive/v1/fixtures/valid/declaration.json"
    ))
    .unwrap();
    let golden_provenance: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/archive/v1/fixtures/golden/provenance.json"
    ))
    .unwrap();
    let valid_provenance: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/archive/v1/fixtures/valid/provenance.json"
    ))
    .unwrap();
    assert_eq!(valid_declaration, golden_declaration);
    assert_eq!(valid_provenance, golden_provenance);
    assert!(declaration_validator.is_valid(&golden_declaration));
    assert!(provenance_validator.is_valid(&golden_provenance));

    let bytes = decode_hex(EMPTY_USTAR);
    let decoded = decode(&bytes).unwrap();
    let declaration = decoded.provenance().declaration();
    assert_eq!(
        golden_declaration,
        serde_json::json!({
            "schema_version": declaration.schema_version(),
            "container": declaration.container().as_str(),
            "compression": declaration.compression().as_str(),
            "decoder_version": declaration.decoder_version(),
            "payload_byte_len": declaration.payload_byte_len(),
            "payload_digest": declaration.payload_digest().as_str(),
        })
    );
    assert_eq!(
        golden_provenance,
        serde_json::json!({
            "schema_version": decoded.provenance().schema_version(),
            "declaration": golden_declaration,
            "decoder": {
                "name": decoded.provenance().decoder().name(),
                "version": decoded.provenance().decoder().version(),
            },
            "root_digest": decoded.root_digest().as_str(),
        })
    );

    for fixture in [
        include_str!(
            "../../../schemas/archive/v1/fixtures/malformed/declaration-unknown-field.json"
        ),
        include_str!("../../../schemas/archive/v1/fixtures/unsupported/declaration-version-2.json"),
    ] {
        let value: serde_json::Value = serde_json::from_str(fixture).unwrap();
        assert!(!declaration_validator.is_valid(&value));
    }
    for fixture in [
        include_str!(
            "../../../schemas/archive/v1/fixtures/malformed/provenance-invalid-decoder.json"
        ),
        include_str!("../../../schemas/archive/v1/fixtures/unsupported/provenance-version-2.json"),
    ] {
        let value: serde_json::Value = serde_json::from_str(fixture).unwrap();
        assert!(!provenance_validator.is_valid(&value));
    }
}

#[test]
fn files_directories_and_safe_symlinks_become_a_closed_canonical_graph() {
    let bytes = archive([
        regular(b"bin/tool", 0o755, b"#!/bin/sh\n", 1),
        symlink(b"current", b"bin/tool", 2),
        directory(b"bin", 0o755, 3),
        regular(b"README.txt", 0o644, b"hello\n", 4),
    ]);
    let decoded = decode(&bytes).unwrap();
    let root = decoded.tree_graph().root();
    assert_eq!(
        root.entries()
            .iter()
            .map(|entry| entry.name().as_str())
            .collect::<Vec<_>>(),
        ["README.txt", "bin", "current"]
    );
    assert!(matches!(
        root.entries()[0].kind(),
        TreeEntryKindV1::File { byte_len: 6, .. }
    ));
    assert!(matches!(
        root.entries()[1].kind(),
        TreeEntryKindV1::Directory { .. }
    ));
    assert!(matches!(
        root.entries()[2].kind(),
        TreeEntryKindV1::SafeRelativeSymlink { .. }
    ));
    assert_eq!(decoded.tree_graph().summary().entries(), 4);
    assert_eq!(decoded.tree_graph().summary().file_bytes(), 16);
    assert_eq!(decoded.tree_graph().summary().depth(), 2);
    assert_eq!(decoded.objects().file_blobs().len(), 2);
    assert_eq!(decoded.objects().trees().len(), 2);
    assert_eq!(decoded.objects().symlinks().len(), 1);
    assert_eq!(
        decoded
            .objects()
            .file_blobs()
            .get(&file_object_digest_v1(b"hello\n").unwrap())
            .map(Vec::as_slice),
        Some(encode_file_object_v1(b"hello\n").unwrap().as_slice())
    );
    assert_eq!(
        decoded
            .objects()
            .object_bytes(decoded.root_digest())
            .unwrap(),
        decoded
            .objects()
            .trees()
            .get(decoded.root_digest())
            .unwrap()
            .bytes()
    );
}

#[test]
fn archive_order_and_ownership_or_timestamp_metadata_do_not_change_objects() {
    let first = archive([
        directory(b"bin", 0o700, 1),
        regular(b"bin/tool", 0o744, b"tool", 2),
        regular(b"notice", 0o644, b"same", 3),
    ]);
    let second = archive([
        regular(b"notice", 0o644, b"same", 300),
        regular(b"bin/tool", 0o744, b"tool", 200),
        directory(b"bin", 0o700, 100),
    ]);
    assert_ne!(Digest::sha256(&first), Digest::sha256(&second));

    let first = decode(&first).unwrap();
    let second = decode(&second).unwrap();
    assert_eq!(first.root_digest(), second.root_digest());
    assert_eq!(first.objects(), second.objects());
    assert_ne!(
        first.provenance().declaration().payload_digest(),
        second.provenance().declaration().payload_digest()
    );
}

#[test]
fn repeated_file_content_is_one_blob_identity_and_two_logical_placements() {
    let bytes = archive([
        regular(b"left", 0o644, b"same", 0),
        regular(b"right", 0o600, b"same", 1),
    ]);
    let decoded = decode(&bytes).unwrap();
    let entries = decoded.tree_graph().root().entries();
    assert_eq!(decoded.objects().file_blobs().len(), 1);
    assert_eq!(decoded.tree_graph().summary().entries(), 2);
    assert_eq!(decoded.tree_graph().summary().file_bytes(), 8);
    assert_eq!(entries[0].kind().digest(), entries[1].kind().digest());
    assert_ne!(entries[0].mode(), entries[1].mode());
}

#[test]
fn empty_regular_files_use_the_domain_separated_file_identity() {
    let bytes = archive([regular(b"empty", 0o644, b"", 0)]);
    let decoded = decode(&bytes).unwrap();
    let digest = file_object_digest_v1(&[]).unwrap();
    assert!(decoded.objects().file_blobs().contains_key(&digest));
    assert_ne!(digest, Digest::sha256([]));
}

#[test]
fn valid_ustar_prefix_names_are_supported_without_host_path_resolution() {
    let path = format!("{}/{}", "a".repeat(80), "b".repeat(30));
    assert!(path.len() > 100);
    let bytes = archive([regular(path.as_bytes(), 0o644, b"x", 0)]);
    let decoded = decode(&bytes).unwrap();
    assert_eq!(decoded.tree_graph().summary().depth(), 2);
    assert_eq!(decoded.tree_graph().summary().file_bytes(), 1);
}

#[test]
fn posix_variant_golden_fixture_decodes_to_the_canonical_identity() {
    let bytes = decode_hex(POSIX_VARIANT_USTAR);
    assert_eq!(
        Digest::sha256(&bytes).as_str(),
        golden_digest("posix-variant-payload")
    );
    let decoded = decode(&bytes).expect("POSIX-variant fixture decodes");
    assert_eq!(
        decoded.root_digest().as_str(),
        golden_digest("posix-variant-root-tree")
    );

    let canonical = decode(&archive([
        directory(b"theme", 0o755, 0),
        regular(b"theme/colors.conf", 0o644, b"accent=teal\n", 1),
    ]))
    .expect("strictly written equivalent decodes");
    assert_eq!(
        decoded.root_digest(),
        canonical.root_digest(),
        "the fixture and its strict equivalent are one canonical tree"
    );
    assert_eq!(decoded.objects(), canonical.objects());
}

#[test]
fn posix_numeric_forms_and_directory_slashes_reach_the_canonical_identity() {
    let strict = archive([
        directory(b"bin", 0o755, 3),
        regular(b"bin/tool", 0o755, b"#!/bin/sh\n", 1),
        symlink(b"current", b"bin/tool", 2),
        regular(b"README.txt", 0o644, b"hello\n", 4),
    ]);
    let variant = archive([
        posix_directory(b"bin", 0o755, 30),
        posix_regular(b"bin/tool", 0o755, b"#!/bin/sh\n", 10),
        posix_symlink(b"current", b"bin/tool", 20),
        posix_regular(b"README.txt", 0o644, b"hello\n", 40),
    ]);
    assert_ne!(
        Digest::sha256(&strict),
        Digest::sha256(&variant),
        "the two spellings must differ as bytes, or this proves nothing"
    );

    let strict = decode(&strict).expect("strict archive decodes");
    let variant = decode(&variant).expect("POSIX-variant archive decodes");
    assert_eq!(
        strict.root_digest(),
        variant.root_digest(),
        "widening acceptance must not change canonical output"
    );
    assert_eq!(strict.objects(), variant.objects());
}

#[test]
fn posix_numeric_fields_accept_terminators_and_leading_spaces() {
    let canonical = decode(&archive([regular(b"file", 0o644, b"abc", 0)]))
        .expect("canonical archive decodes")
        .root_digest()
        .clone();
    for field in [
        *b"0000644\0",
        *b"0000644 ",
        *b"644\0\0\0\0\0",
        *b"  644\0\0\0",
        *b"644 \0\0\0\0",
    ] {
        let mut bytes = archive([regular(b"file", 0o644, b"abc", 0)]);
        let header: &mut [u8; USTAR_BLOCK_BYTES] =
            (&mut bytes[..USTAR_BLOCK_BYTES]).try_into().unwrap();
        header[100..108].copy_from_slice(&field);
        set_checksum(header);
        assert_eq!(
            decode(&bytes)
                .expect("POSIX mode field decodes")
                .root_digest(),
            &canonical,
            "mode field {field:?} changed the canonical identity"
        );
    }
}

#[test]
fn non_posix_numeric_forms_including_gnu_base_256_are_rejected() {
    let modes: &[&[u8; 8]] = &[
        b"\0\0\0\0\0\0\0\0",
        b"        ",
        b"000644 1",
        b"00000644",
        b"0644\0x\0\0",
        b"\x80\0\0\0\0\0\x01\xa4",
        b"0000648\0",
    ];
    for field in modes {
        let bytes = mutated_archive(|header| header[100..108].copy_from_slice(*field));
        assert!(
            matches!(
                decode(&bytes),
                Err(ArchiveDecodeError::MalformedHeader {
                    reason: "mode is not an octal field terminated by NUL or space",
                    ..
                })
            ),
            "accepted non-POSIX mode field {field:?}"
        );
    }

    let bytes = mutated_archive(|header| {
        header[124..136].copy_from_slice(b"\x80\0\0\0\0\0\0\0\0\0\x04\0");
    });
    assert!(
        matches!(
            decode(&bytes),
            Err(ArchiveDecodeError::MalformedHeader {
                reason: "size is not an octal field terminated by NUL or space",
                ..
            })
        ),
        "GNU base-256 size must stay rejected"
    );

    let blank = mutated_archive(|header| header[329..345].fill(b' '));
    assert!(decode(&blank).is_ok(), "a blank device field means absent");
    let nonzero = mutated_archive(|header| header[329..337].copy_from_slice(b"0000010 "));
    assert!(matches!(
        decode(&nonzero),
        Err(ArchiveDecodeError::MalformedHeader {
            reason: "device numbers must be zero for an allowed entry",
            ..
        })
    ));
}

#[test]
fn checksum_field_accepts_every_posix_terminator_shape() {
    let canonical = decode(&archive([regular(b"file", 0o644, b"abc", 0)]))
        .expect("canonical archive decodes")
        .root_digest()
        .clone();
    for shape in [
        ChecksumShape::DigitsNulSpace,
        ChecksumShape::DigitsSpaceNul,
        ChecksumShape::SevenDigitsNul,
        ChecksumShape::SpaceDigitsNul,
    ] {
        let mut bytes = archive([regular(b"file", 0o644, b"abc", 0)]);
        let header: &mut [u8; USTAR_BLOCK_BYTES] =
            (&mut bytes[..USTAR_BLOCK_BYTES]).try_into().unwrap();
        set_checksum_shape(header, shape);
        assert_eq!(
            decode(&bytes)
                .expect("POSIX checksum decodes")
                .root_digest(),
            &canonical
        );
    }

    for field in [
        *b"        ",
        *b"012345\0X",
        *b"01234567",
        *b"  \0\0\0\0\0\0",
    ] {
        let mut bytes = archive([regular(b"file", 0o644, b"abc", 0)]);
        set_raw_checksum(&mut bytes, &field);
        assert!(
            matches!(
                decode(&bytes),
                Err(ArchiveDecodeError::MalformedHeader {
                    reason: "checksum field is invalid",
                    ..
                })
            ),
            "accepted checksum field {field:?}"
        );
    }
}

#[test]
fn directory_trailing_slash_is_normalized_and_no_other_entry_kind_is() {
    let decoded = decode(&archive([
        posix_directory(b"dir", 0o755, 0),
        regular(b"dir/file", 0o644, b"x", 1),
    ]))
    .expect("directory with a trailing slash decodes");
    assert_eq!(
        decoded
            .tree_graph()
            .root()
            .entries()
            .iter()
            .map(|entry| entry.name().as_str())
            .collect::<Vec<_>>(),
        ["dir"],
        "the trailing slash is normalized away, not carried into a name"
    );

    assert!(
        matches!(
            decode(&archive([
                directory(b"dir", 0o755, 0),
                posix_directory(b"dir", 0o755, 1),
            ])),
            Err(ArchiveDecodeError::DuplicatePath { path }) if path == "dir"
        ),
        "`dir/` and `dir` name one path"
    );

    for entry in [
        regular(b"trailing/", 0o644, b"x", 0),
        symlink(b"link/", b"target", 0),
    ] {
        assert!(
            matches!(
                decode(&archive([entry])),
                Err(ArchiveDecodeError::InvalidPath {
                    reason: "empty path components are forbidden",
                    ..
                })
            ),
            "only a directory entry may carry a trailing slash"
        );
    }

    let names: &[(&[u8], &str)] = &[
        (b"dir//", "empty path components are forbidden"),
        (b"/", "absolute paths are forbidden"),
        (b"//", "absolute paths are forbidden"),
        (b"/abs/", "absolute paths are forbidden"),
        (b"./", "dot and dot-dot components are forbidden"),
        (b"../", "dot and dot-dot components are forbidden"),
    ];
    for (name, expected) in names {
        assert!(
            matches!(
                decode(&archive([directory(name, 0o755, 0)])),
                Err(ArchiveDecodeError::InvalidPath { reason, .. }) if reason == *expected
            ),
            "accepted directory name {name:?}"
        );
    }
}

#[test]
fn unsafe_and_noncanonical_paths_are_rejected() {
    // Every case is a regular file. Only a directory entry may carry the
    // conventional trailing slash; see
    // `directory_trailing_slash_is_normalized_and_no_other_entry_kind_is`.
    let paths: &[&[u8]] = &[
        b"/absolute",
        b"./relative",
        b"a/./b",
        b"a/../b",
        b"a//b",
        b"trailing/",
        b"a\\b",
        b"line\nbreak",
        b"bad\xffname",
    ];
    for path in paths {
        let bytes = archive([regular(path, 0o644, b"x", 0)]);
        assert!(decode(&bytes).is_err(), "accepted unsafe path {path:?}");
    }
}

#[test]
fn unsafe_and_non_utf8_symlink_targets_are_rejected() {
    let targets: &[&[u8]] = &[
        b"",
        b"/absolute",
        b".",
        b"..",
        b"a/./b",
        b"a/../b",
        b"a//b",
        b"a\\b",
        b"line\nbreak",
        b"bad\xfftarget",
    ];
    for target in targets {
        let bytes = archive([symlink(b"link", target, 0)]);
        assert!(
            decode(&bytes).is_err(),
            "accepted unsafe symlink target {target:?}"
        );
    }
}

#[test]
fn symlink_dependency_cycles_are_rejected_by_the_closed_tree_graph() {
    let bytes = archive([symlink(b"a", b"b", 0), symlink(b"b", b"a", 1)]);
    assert!(matches!(
        decode(&bytes),
        Err(ArchiveDecodeError::InvalidTreeGraph(_))
    ));
}

#[test]
fn duplicate_paths_and_every_file_descendant_collision_direction_fail() {
    let cases = [
        archive([
            regular(b"same", 0o644, b"a", 0),
            regular(b"same", 0o644, b"a", 1),
        ]),
        archive([directory(b"same", 0o755, 0), directory(b"same", 0o755, 1)]),
        archive([
            directory(b"same", 0o755, 0),
            regular(b"same", 0o644, b"a", 1),
        ]),
        archive([
            regular(b"parent", 0o644, b"a", 0),
            regular(b"parent/child", 0o644, b"b", 1),
        ]),
        archive([
            regular(b"parent/child", 0o644, b"b", 0),
            regular(b"parent", 0o644, b"a", 1),
        ]),
        archive([
            symlink(b"parent", b"target", 0),
            regular(b"parent/child", 0o644, b"b", 1),
        ]),
    ];
    for bytes in cases {
        assert!(decode(&bytes).is_err());
    }
}

#[test]
fn hard_links_sparse_special_entries_and_extensions_are_closed_out() {
    assert!(matches!(
        decode(&archive([typed_entry(b'1')])),
        Err(ArchiveDecodeError::HardLink { .. })
    ));
    assert!(matches!(
        decode(&archive([typed_entry(b'S')])),
        Err(ArchiveDecodeError::SparseEntry { .. })
    ));
    for typeflag in *b"3467" {
        assert!(matches!(
            decode(&archive([typed_entry(typeflag)])),
            Err(ArchiveDecodeError::SpecialEntry { .. })
        ));
    }
    for typeflag in *b"xgLKDMNV" {
        assert!(matches!(
            decode(&archive([typed_entry(typeflag)])),
            Err(ArchiveDecodeError::UnsupportedExtension { .. })
        ));
    }
    assert!(matches!(
        decode(&archive([typed_entry(0)])),
        Err(ArchiveDecodeError::UnsupportedEntryType { .. })
    ));
}

#[test]
fn checksum_digest_length_truncation_and_trailing_data_fail_closed() {
    let valid = archive([regular(b"file", 0o644, b"abc", 0)]);

    let mut bad_checksum = valid.clone();
    bad_checksum[1] ^= 1;
    assert!(matches!(
        decode(&bad_checksum),
        Err(ArchiveDecodeError::InvalidChecksum { .. })
    ));

    let wrong_digest =
        ArchiveDeclarationV1::posix_ustar(valid.len() as u64, Digest::sha256(b"not the archive"));
    assert!(matches!(
        decode_archive_v1(
            Cursor::new(&valid),
            wrong_digest,
            ArchiveLimitsV1::default()
        ),
        Err(ArchiveDecodeError::PayloadDigestMismatch { .. })
    ));

    let exact = declaration(&valid);
    assert!(matches!(
        decode_archive_v1(
            Cursor::new(&valid[..valid.len() - 1]),
            exact.clone(),
            ArchiveLimitsV1::default()
        ),
        Err(ArchiveDecodeError::TruncatedPayload { .. })
    ));

    let mut outside_trailing = valid.clone();
    outside_trailing.push(1);
    assert!(matches!(
        decode_archive_v1(
            Cursor::new(&outside_trailing),
            exact,
            ArchiveLimitsV1::default()
        ),
        Err(ArchiveDecodeError::TrailingBytes)
    ));

    assert!(matches!(
        decode(&outside_trailing),
        Err(ArchiveDecodeError::TrailingPayloadData { .. })
    ));

    let short_declaration = ArchiveDeclarationV1::posix_ustar(
        (valid.len() - 1) as u64,
        Digest::sha256(&valid[..valid.len() - 1]),
    );
    assert!(matches!(
        decode_archive_v1(
            Cursor::new(&valid),
            short_declaration,
            ArchiveLimitsV1::default()
        ),
        Err(ArchiveDecodeError::TrailingBytes)
    ));
}

#[test]
fn malformed_terminators_and_nonzero_file_padding_are_rejected() {
    let one_terminator = decode_hex(SINGLE_ZERO_BLOCK);
    assert_eq!(one_terminator.len(), USTAR_BLOCK_BYTES);
    assert!(matches!(
        decode(&one_terminator),
        Err(ArchiveDecodeError::MalformedTerminator { .. })
    ));

    let mut bad_second = vec![0_u8; 2 * USTAR_BLOCK_BYTES];
    bad_second[USTAR_BLOCK_BYTES] = 1;
    assert!(matches!(
        decode(&bad_second),
        Err(ArchiveDecodeError::MalformedTerminator { .. })
    ));

    let mut bad_padding = archive([regular(b"file", 0o644, b"x", 0)]);
    bad_padding[USTAR_BLOCK_BYTES + 1] = 1;
    assert!(matches!(
        decode(&bad_padding),
        Err(ArchiveDecodeError::MalformedEntry { .. })
    ));

    let no_terminator =
        archive([regular(b"file", 0o644, b"x", 0)])[..2 * USTAR_BLOCK_BYTES].to_vec();
    assert!(matches!(
        decode(&no_terminator),
        Err(ArchiveDecodeError::MalformedTerminator { .. })
    ));
}

#[test]
fn malformed_ustar_identity_numeric_fields_reserved_bytes_and_modes_are_rejected() {
    let base = archive([regular(b"file", 0o644, b"", 0)]);
    let mutations: [fn(&mut [u8; USTAR_BLOCK_BYTES]); 5] = [
        |header: &mut [u8; USTAR_BLOCK_BYTES]| header[257] = b'X',
        |header: &mut [u8; USTAR_BLOCK_BYTES]| header[263] = b'1',
        |header: &mut [u8; USTAR_BLOCK_BYTES]| header[100] = b'8',
        |header: &mut [u8; USTAR_BLOCK_BYTES]| header[500] = 1,
        |header: &mut [u8; USTAR_BLOCK_BYTES]| header[335] = b'1',
    ];
    for mutation in mutations {
        let mut bytes = base.clone();
        let header: &mut [u8; USTAR_BLOCK_BYTES] =
            (&mut bytes[..USTAR_BLOCK_BYTES]).try_into().unwrap();
        mutation(header);
        set_checksum(header);
        assert!(decode(&bytes).is_err());
    }

    assert!(matches!(
        decode(&archive([regular(b"file", 0o200, b"", 0)])),
        Err(ArchiveDecodeError::UnsupportedMode { .. })
    ));
    assert!(matches!(
        decode(&archive([directory(b"dir", 0o644, 0)])),
        Err(ArchiveDecodeError::UnsupportedMode { .. })
    ));
    let mut link = symlink(b"link", b"target", 0);
    write_octal(&mut link.header[100..108], 0o755);
    set_checksum(&mut link.header);
    assert!(matches!(
        decode(&archive([link])),
        Err(ArchiveDecodeError::UnsupportedMode { .. })
    ));
}

#[test]
fn every_resource_limit_is_explicit_and_deterministic() {
    let file = archive([regular(b"a/bbb", 0o644, b"abc", 0)]);

    let limits = ArchiveLimitsV1 {
        max_payload_bytes: file.len() as u64 - 1,
        ..ArchiveLimitsV1::default()
    };
    assert_resource(
        decode_with_limits(&file, limits).unwrap_err(),
        ArchiveResourceV1::PayloadBytes,
    );

    let limits = ArchiveLimitsV1 {
        max_file_bytes: 2,
        ..ArchiveLimitsV1::default()
    };
    assert_resource(
        decode_with_limits(&file, limits).unwrap_err(),
        ArchiveResourceV1::FileBytes,
    );

    let aggregate = archive([
        regular(b"first", 0o644, b"abc", 0),
        regular(b"second", 0o644, b"def", 0),
    ]);
    let limits = ArchiveLimitsV1 {
        max_expanded_file_bytes: 5,
        ..ArchiveLimitsV1::default()
    };
    assert_resource(
        decode_with_limits(&aggregate, limits).unwrap_err(),
        ArchiveResourceV1::ExpandedFileBytes,
    );

    let limits = ArchiveLimitsV1 {
        max_entries: 1,
        ..ArchiveLimitsV1::default()
    };
    assert_resource(
        decode_with_limits(&file, limits).unwrap_err(),
        ArchiveResourceV1::Entries,
    );

    let limits = ArchiveLimitsV1 {
        max_path_bytes: 4,
        ..ArchiveLimitsV1::default()
    };
    assert_resource(
        decode_with_limits(&file, limits).unwrap_err(),
        ArchiveResourceV1::PathBytes,
    );

    let limits = ArchiveLimitsV1 {
        max_path_depth: 1,
        ..ArchiveLimitsV1::default()
    };
    assert_resource(
        decode_with_limits(&file, limits).unwrap_err(),
        ArchiveResourceV1::PathDepth,
    );

    let limits = ArchiveLimitsV1 {
        max_path_segment_bytes: 2,
        ..ArchiveLimitsV1::default()
    };
    assert_resource(
        decode_with_limits(&file, limits).unwrap_err(),
        ArchiveResourceV1::PathSegmentBytes,
    );

    let link = archive([symlink(b"link", b"target", 0)]);
    let limits = ArchiveLimitsV1 {
        max_symlink_target_bytes: 5,
        ..ArchiveLimitsV1::default()
    };
    assert_resource(
        decode_with_limits(&link, limits).unwrap_err(),
        ArchiveResourceV1::SymlinkTargetBytes,
    );

    let empty = vec![0_u8; 2 * USTAR_BLOCK_BYTES];
    let limits = ArchiveLimitsV1 {
        max_metadata_bytes: USTAR_BLOCK_BYTES as u64,
        ..ArchiveLimitsV1::default()
    };
    assert_resource(
        decode_with_limits(&empty, limits).unwrap_err(),
        ArchiveResourceV1::MetadataBytes,
    );

    let limits = ArchiveLimitsV1 {
        max_object_bytes: 0,
        ..ArchiveLimitsV1::default()
    };
    assert_resource(
        decode_with_limits(&empty, limits).unwrap_err(),
        ArchiveResourceV1::ObjectBytes,
    );

    let limits = ArchiveLimitsV1 {
        max_read_operations: 1,
        ..ArchiveLimitsV1::default()
    };
    assert_resource(
        decode_with_limits(&empty, limits).unwrap_err(),
        ArchiveResourceV1::ReadOperations,
    );

    let limits = ArchiveLimitsV1 {
        max_work_units: 1,
        ..ArchiveLimitsV1::default()
    };
    assert_resource(
        decode_with_limits(&empty, limits).unwrap_err(),
        ArchiveResourceV1::WorkUnits,
    );

    let exact = ArchiveLimitsV1 {
        max_file_bytes: 3,
        max_expanded_file_bytes: 3,
        max_entries: 2,
        max_path_bytes: 5,
        max_path_depth: 2,
        max_path_segment_bytes: 3,
        ..ArchiveLimitsV1::default()
    };
    assert!(decode_with_limits(&file, exact).is_ok());
}

struct ChunkedReader<'a> {
    bytes: &'a [u8],
    position: Rc<Cell<usize>>,
    max_chunk: usize,
}

impl Read for ChunkedReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let position = self.position.get();
        if position == self.bytes.len() {
            return Ok(0);
        }
        let count = output
            .len()
            .min(self.max_chunk)
            .min(self.bytes.len() - position);
        output[..count].copy_from_slice(&self.bytes[position..position + count]);
        self.position.set(position + count);
        Ok(count)
    }
}

#[test]
fn chunked_reads_are_streamed_and_format_errors_still_drain_the_declared_payload() {
    let mut bytes = archive([regular(b"file", 0o644, b"streamed", 0)]);
    bytes[0] ^= 1;
    let position = Rc::new(Cell::new(0));
    let reader = ChunkedReader {
        bytes: &bytes,
        position: Rc::clone(&position),
        max_chunk: 3,
    };
    assert!(matches!(
        decode_archive_v1(reader, declaration(&bytes), ArchiveLimitsV1::default()),
        Err(ArchiveDecodeError::InvalidChecksum { .. })
    ));
    assert_eq!(position.get(), bytes.len());

    let valid = archive([regular(b"file", 0o644, b"streamed", 0)]);
    let position = Rc::new(Cell::new(0));
    let reader = ChunkedReader {
        bytes: &valid,
        position: Rc::clone(&position),
        max_chunk: 1,
    };
    assert!(decode_archive_v1(reader, declaration(&valid), ArchiveLimitsV1::default()).is_ok());
    assert_eq!(position.get(), valid.len());
}

#[test]
fn symlink_resolved_paths_obey_the_caller_path_budgets() {
    let bytes = archive([symlink(b"dir/link", b"target/leaf", 0)]);
    let limits = ArchiveLimitsV1 {
        max_path_depth: 2,
        ..ArchiveLimitsV1::default()
    };
    assert_resource(
        decode_with_limits(&bytes, limits).unwrap_err(),
        ArchiveResourceV1::PathDepth,
    );

    let limits = ArchiveLimitsV1 {
        max_path_bytes: 14,
        ..ArchiveLimitsV1::default()
    };
    assert_resource(
        decode_with_limits(&bytes, limits).unwrap_err(),
        ArchiveResourceV1::PathBytes,
    );
}
