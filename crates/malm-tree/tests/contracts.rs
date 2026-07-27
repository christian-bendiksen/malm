use malm_tree::{
    ObjectReadError, SymlinkObjectV1, TreeEntryKindV1, TreeEntryV1, TreeGraphError, TreeGraphV1,
    TreeObjectV1, TreePathSegmentV1, TreeValidationError, decode_file_object_v1,
    decode_symlink_object_v1, decode_tree_object_v1, decode_verified_file_object_v1,
    decode_verified_symlink_object_v1, decode_verified_tree_object_v1, encode_file_object_v1,
    encode_symlink_object_v1, encode_tree_object_v1, file_object_digest_v1,
    symlink_object_digest_v1, tree_object_digest_v1,
};
use malm_types::Digest;

const GOLDEN_SYMLINK: &str = include_str!("../../../schemas/tree/v1/fixtures/golden/symlink.hex");
const GOLDEN_FILE_EMPTY: &str =
    include_str!("../../../schemas/tree/v1/fixtures/golden/file-empty.hex");
const GOLDEN_FILE_HELLO: &str =
    include_str!("../../../schemas/tree/v1/fixtures/golden/file-hello.hex");
const GOLDEN_EMPTY_TREE: &str =
    include_str!("../../../schemas/tree/v1/fixtures/golden/empty-tree.hex");
const GOLDEN_TREE: &str = include_str!("../../../schemas/tree/v1/fixtures/golden/tree.hex");
const GOLDEN_DIGESTS: &str = include_str!("../../../schemas/tree/v1/fixtures/golden/digests.txt");

fn decode_hex(value: &str) -> Vec<u8> {
    let value = value.trim_end_matches('\n');
    assert!(!value.is_empty());
    assert_eq!(value.len() % 2, 0);
    assert!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    );
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]))
        .collect()
}

#[test]
fn regular_file_objects_are_domain_separated_and_strictly_verified() {
    let contents = b"hello\n";
    let encoded = encode_file_object_v1(contents).unwrap();
    let digest = file_object_digest_v1(contents).unwrap();

    assert_ne!(digest, Digest::sha256(contents));
    assert_eq!(digest, Digest::sha256(&encoded));
    assert_eq!(decode_file_object_v1(&encoded).unwrap(), contents);
    assert_eq!(
        decode_verified_file_object_v1(&digest, &encoded).unwrap(),
        contents
    );

    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(decode_file_object_v1(&trailing).is_err());
    assert!(matches!(
        decode_verified_file_object_v1(&Digest::sha256(contents), &encoded),
        Err(ObjectReadError::DigestMismatch { .. })
    ));
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => unreachable!("fixture character was prevalidated"),
    }
}

fn golden_digest(name: &str) -> Digest {
    let prefix = format!("{name}=");
    GOLDEN_DIGESTS
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("missing golden digest {name}"))
        .parse()
        .unwrap()
}

fn segment(value: &str) -> TreePathSegmentV1 {
    TreePathSegmentV1::new(value).unwrap()
}

fn golden_models() -> (SymlinkObjectV1, TreeObjectV1, TreeObjectV1) {
    let symlink = SymlinkObjectV1::new("bin/tool").unwrap();
    let empty_tree = TreeObjectV1::new(0o755, vec![]).unwrap();
    let tree = TreeObjectV1::new(
        0o755,
        vec![
            TreeEntryV1::safe_relative_symlink(
                segment("current"),
                symlink_object_digest_v1(&symlink),
            ),
            TreeEntryV1::directory(segment("bin"), 0o755, tree_object_digest_v1(&empty_tree))
                .unwrap(),
            TreeEntryV1::file(
                segment("README.txt"),
                0o644,
                file_object_digest_v1(b"hello\n").unwrap(),
                6,
            )
            .unwrap(),
        ],
    )
    .unwrap();
    (symlink, empty_tree, tree)
}

#[test]
fn canonical_writers_and_sha256_identities_match_golden_objects() {
    let (symlink, empty_tree, tree) = golden_models();
    let empty_file_bytes = decode_hex(GOLDEN_FILE_EMPTY);
    let hello_file_bytes = decode_hex(GOLDEN_FILE_HELLO);
    let symlink_bytes = decode_hex(GOLDEN_SYMLINK);
    let empty_tree_bytes = decode_hex(GOLDEN_EMPTY_TREE);
    let tree_bytes = decode_hex(GOLDEN_TREE);

    assert_eq!(encode_file_object_v1(&[]).unwrap(), empty_file_bytes);
    assert_eq!(encode_file_object_v1(b"hello\n").unwrap(), hello_file_bytes);
    assert_eq!(encode_symlink_object_v1(&symlink), symlink_bytes);
    assert_eq!(encode_tree_object_v1(&empty_tree), empty_tree_bytes);
    assert_eq!(encode_tree_object_v1(&tree), tree_bytes);
    assert_eq!(
        file_object_digest_v1(&[]).unwrap(),
        golden_digest("file-empty")
    );
    assert_eq!(
        file_object_digest_v1(b"hello\n").unwrap(),
        golden_digest("file-hello")
    );
    assert_eq!(symlink_object_digest_v1(&symlink), golden_digest("symlink"));
    assert_eq!(
        tree_object_digest_v1(&empty_tree),
        golden_digest("empty-tree")
    );
    assert_eq!(tree_object_digest_v1(&tree), golden_digest("tree"));
    assert_eq!(
        golden_digest("file-empty"),
        Digest::sha256(&empty_file_bytes)
    );
    assert_eq!(
        golden_digest("file-hello"),
        Digest::sha256(&hello_file_bytes)
    );
    assert_eq!(golden_digest("symlink"), Digest::sha256(&symlink_bytes));
    assert_eq!(golden_digest("tree"), Digest::sha256(&tree_bytes));
}

#[test]
fn strict_readers_round_trip_golden_objects_and_verify_requested_identity() {
    let (symlink, empty_tree, tree) = golden_models();
    let empty_file_bytes = decode_hex(GOLDEN_FILE_EMPTY);
    let hello_file_bytes = decode_hex(GOLDEN_FILE_HELLO);
    let symlink_bytes = decode_hex(GOLDEN_SYMLINK);
    let empty_tree_bytes = decode_hex(GOLDEN_EMPTY_TREE);
    let tree_bytes = decode_hex(GOLDEN_TREE);

    assert_eq!(decode_file_object_v1(&empty_file_bytes).unwrap(), b"");
    assert_eq!(
        decode_file_object_v1(&hello_file_bytes).unwrap(),
        b"hello\n"
    );
    assert_eq!(
        decode_verified_file_object_v1(&golden_digest("file-empty"), &empty_file_bytes).unwrap(),
        b""
    );
    assert_eq!(
        decode_verified_file_object_v1(&golden_digest("file-hello"), &hello_file_bytes).unwrap(),
        b"hello\n"
    );
    assert_eq!(decode_symlink_object_v1(&symlink_bytes).unwrap(), symlink);
    assert_eq!(
        decode_tree_object_v1(&empty_tree_bytes).unwrap(),
        empty_tree
    );
    assert_eq!(decode_tree_object_v1(&tree_bytes).unwrap(), tree);
    assert_eq!(
        decode_verified_symlink_object_v1(&golden_digest("symlink"), &symlink_bytes).unwrap(),
        symlink
    );
    assert_eq!(
        decode_verified_tree_object_v1(&golden_digest("tree"), &tree_bytes).unwrap(),
        tree
    );
    assert!(matches!(
        decode_verified_tree_object_v1(&golden_digest("empty-tree"), &tree_bytes),
        Err(ObjectReadError::DigestMismatch { .. })
    ));
}

#[test]
fn every_malformed_fixture_is_rejected() {
    for (name, fixture) in [
        (
            "wrong file domain",
            include_str!("../../../schemas/tree/v1/fixtures/malformed/file-wrong-domain.hex"),
        ),
        (
            "trailing file byte",
            include_str!("../../../schemas/tree/v1/fixtures/malformed/file-trailing.hex"),
        ),
        (
            "truncated file",
            include_str!("../../../schemas/tree/v1/fixtures/malformed/file-truncated.hex"),
        ),
    ] {
        assert!(
            decode_file_object_v1(&decode_hex(fixture)).is_err(),
            "accepted malformed fixture {name}"
        );
    }

    for (name, fixture) in [
        (
            "wrong domain",
            include_str!("../../../schemas/tree/v1/fixtures/malformed/symlink-wrong-domain.hex"),
        ),
        (
            "empty target",
            include_str!("../../../schemas/tree/v1/fixtures/malformed/symlink-empty-target.hex"),
        ),
        (
            "control target",
            include_str!("../../../schemas/tree/v1/fixtures/malformed/symlink-control-target.hex"),
        ),
        (
            "invalid target UTF-8",
            include_str!("../../../schemas/tree/v1/fixtures/malformed/symlink-invalid-utf8.hex"),
        ),
        (
            "trailing symlink byte",
            include_str!("../../../schemas/tree/v1/fixtures/malformed/symlink-trailing.hex"),
        ),
    ] {
        assert!(
            decode_symlink_object_v1(&decode_hex(fixture)).is_err(),
            "accepted malformed fixture {name}"
        );
    }
    assert!(matches!(
        decode_symlink_object_v1(&decode_hex(include_str!(
            "../../../schemas/tree/v1/fixtures/malformed/symlink-version-2.hex"
        ))),
        Err(ObjectReadError::UnsupportedVersion { found: 2, .. })
    ));

    for (name, fixture) in [
        (
            "unsorted entries",
            include_str!("../../../schemas/tree/v1/fixtures/malformed/tree-unsorted.hex"),
        ),
        (
            "duplicate entries",
            include_str!("../../../schemas/tree/v1/fixtures/malformed/tree-duplicate.hex"),
        ),
        (
            "unsupported root mode",
            include_str!(
                "../../../schemas/tree/v1/fixtures/malformed/tree-unsupported-root-mode.hex"
            ),
        ),
        (
            "unknown entry tag",
            include_str!("../../../schemas/tree/v1/fixtures/malformed/tree-unknown-tag.hex"),
        ),
        (
            "invalid digest",
            include_str!("../../../schemas/tree/v1/fixtures/malformed/tree-invalid-digest.hex"),
        ),
        (
            "too many entries",
            include_str!("../../../schemas/tree/v1/fixtures/malformed/tree-too-many-entries.hex"),
        ),
        (
            "invalid segment UTF-8",
            include_str!(
                "../../../schemas/tree/v1/fixtures/malformed/tree-invalid-segment-utf8.hex"
            ),
        ),
        (
            "truncated tree",
            include_str!("../../../schemas/tree/v1/fixtures/malformed/tree-truncated.hex"),
        ),
        (
            "trailing tree byte",
            include_str!("../../../schemas/tree/v1/fixtures/malformed/tree-trailing.hex"),
        ),
    ] {
        assert!(
            decode_tree_object_v1(&decode_hex(fixture)).is_err(),
            "accepted malformed fixture {name}"
        );
    }
}

#[test]
fn every_unsupported_object_fixture_reports_its_version() {
    assert!(matches!(
        decode_file_object_v1(&decode_hex(include_str!(
            "../../../schemas/tree/v1/fixtures/unsupported/file-version-2.hex"
        ))),
        Err(ObjectReadError::UnsupportedVersion { found: 2, .. })
    ));
    assert!(matches!(
        decode_symlink_object_v1(&decode_hex(include_str!(
            "../../../schemas/tree/v1/fixtures/unsupported/symlink-version-2.hex"
        ))),
        Err(ObjectReadError::UnsupportedVersion { found: 2, .. })
    ));
    assert!(matches!(
        decode_tree_object_v1(&decode_hex(include_str!(
            "../../../schemas/tree/v1/fixtures/unsupported/tree-version-2.hex"
        ))),
        Err(ObjectReadError::UnsupportedVersion { found: 2, .. })
    ));
}

#[test]
fn public_models_are_canonical_and_closed_over_supported_kinds_and_modes() {
    let digest = Digest::sha256(b"object");
    let entries = vec![
        TreeEntryV1::safe_relative_symlink(segment("z-link"), digest.clone()),
        TreeEntryV1::directory(segment("directory"), 0o700, digest.clone()).unwrap(),
        TreeEntryV1::file(segment("executable"), 0o755, digest.clone(), 1).unwrap(),
        TreeEntryV1::file(segment("é"), 0o400, digest, 1).unwrap(),
    ];
    let tree = TreeObjectV1::new(0o500, entries).unwrap();
    assert_eq!(
        tree.entries()
            .iter()
            .map(|entry| entry.name().as_str())
            .collect::<Vec<_>>(),
        ["directory", "executable", "z-link", "é"]
    );
    assert!(matches!(
        tree.entries()[0].kind(),
        TreeEntryKindV1::Directory { .. }
    ));
    assert!(matches!(
        tree.entries()[1].kind(),
        TreeEntryKindV1::File { byte_len: 1, .. }
    ));
    assert!(matches!(
        tree.entries()[2].kind(),
        TreeEntryKindV1::SafeRelativeSymlink { .. }
    ));

    assert!(TreeObjectV1::new(0o7777, vec![]).is_err());
    assert!(TreeEntryV1::file(segment("bad"), 0o100_644, Digest::sha256(b"x"), 1).is_err());
    assert!(TreeEntryV1::directory(segment("bad"), 0o644, Digest::sha256(b"x")).is_err());
}

#[test]
fn complete_graph_contract_resolves_objects_and_rejects_conflicting_file_metadata() {
    let (symlink, empty_tree, tree) = golden_models();
    let graph = TreeGraphV1::new(
        tree_object_digest_v1(&tree),
        [tree.clone(), empty_tree.clone()],
        [symlink.clone()],
    )
    .unwrap();
    assert_eq!(graph.root(), &tree);
    assert_eq!(graph.summary().entries(), 3);
    assert_eq!(graph.summary().file_bytes(), 6);
    assert_eq!(graph.summary().depth(), 1);
    assert_eq!(
        graph.symlink_object(&symlink_object_digest_v1(&symlink)),
        Some(&symlink)
    );

    let shared = Digest::sha256(b"same claimed file object");
    let left = TreeObjectV1::new(
        0o755,
        vec![TreeEntryV1::file(segment("file"), 0o644, shared.clone(), 1).unwrap()],
    )
    .unwrap();
    let right = TreeObjectV1::new(
        0o755,
        vec![TreeEntryV1::file(segment("file"), 0o644, shared, 2).unwrap()],
    )
    .unwrap();
    let root = TreeObjectV1::new(
        0o755,
        vec![
            TreeEntryV1::directory(segment("left"), 0o755, tree_object_digest_v1(&left)).unwrap(),
            TreeEntryV1::directory(segment("right"), 0o755, tree_object_digest_v1(&right)).unwrap(),
        ],
    )
    .unwrap();
    assert!(matches!(
        TreeGraphV1::new(tree_object_digest_v1(&root), [root, left, right], []),
        Err(TreeGraphError::ConflictingFileLength { .. })
    ));
}

#[test]
fn constructor_rejects_duplicate_names_before_any_encoding() {
    let empty = file_object_digest_v1(&[]).unwrap();
    let first = TreeEntryV1::file(segment("same"), 0o644, empty, 0).unwrap();
    let second = TreeEntryV1::directory(segment("same"), 0o755, Digest::sha256(b"tree")).unwrap();
    assert!(matches!(
        TreeObjectV1::new(0o755, vec![first, second]),
        Err(TreeValidationError::DuplicateName(_))
    ));
}
