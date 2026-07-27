use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

use malm_root::{
    CONTAINER_MODE, DESCRIPTOR_CANONICAL_BYTES, DESCRIPTOR_FILENAME, DESCRIPTOR_FORMAT,
    DESCRIPTOR_V1, DESCRIPTOR_VERSION, DescriptorDecodeError, DescriptorField, DescriptorValueType,
    FINAL_ROOT_ENTRIES, FinalRootEntryKind, JsonValueType, MAX_DESCRIPTOR_BYTES, MUTABLE_FILE_MODE,
    OperationV1, PRODUCTION_ROOT_LEAF, RecordFamilyV1, RootPathError, decode_descriptor_v1,
    final_root_entry, require_home, resolve_root, validate_injected_root,
};

const VALID_DESCRIPTOR: &[u8] =
    include_bytes!("../../../schemas/root/v1/fixtures/valid/descriptor.json");
const GOLDEN_DESCRIPTOR: &[u8] =
    include_bytes!("../../../schemas/root/v1/fixtures/golden/descriptor.json");

#[test]
fn constants_and_fixtures_freeze_the_exact_descriptor() {
    assert_eq!(PRODUCTION_ROOT_LEAF, "malm");
    assert_eq!(DESCRIPTOR_FILENAME, "descriptor.json");
    assert_eq!(DESCRIPTOR_FORMAT, "malm-state");
    assert_eq!(DESCRIPTOR_VERSION, 1);
    assert_eq!(MAX_DESCRIPTOR_BYTES, 4_096);
    assert_eq!(
        DESCRIPTOR_CANONICAL_BYTES,
        b"{\"format\":\"malm-state\",\"version\":1}\n"
    );
    assert_eq!(VALID_DESCRIPTOR, DESCRIPTOR_CANONICAL_BYTES);
    assert_eq!(GOLDEN_DESCRIPTOR, DESCRIPTOR_CANONICAL_BYTES);

    let descriptor = decode_descriptor_v1(VALID_DESCRIPTOR).unwrap();
    assert_eq!(descriptor, DESCRIPTOR_V1);
    assert_eq!(descriptor.format(), DESCRIPTOR_FORMAT);
    assert_eq!(descriptor.version(), DESCRIPTOR_VERSION);
    assert_eq!(decode_descriptor_v1(GOLDEN_DESCRIPTOR), Ok(DESCRIPTOR_V1));
}

#[test]
fn malformed_json_and_wrong_top_level_type_are_distinct() {
    assert_eq!(
        decode_descriptor_v1(include_bytes!(
            "../../../schemas/root/v1/fixtures/malformed/truncated.json"
        )),
        Err(DescriptorDecodeError::MalformedJson)
    );
    assert_eq!(
        decode_descriptor_v1(include_bytes!(
            "../../../schemas/root/v1/fixtures/malformed/wrong-top-level-type.json"
        )),
        Err(DescriptorDecodeError::ExpectedObject {
            actual: JsonValueType::Array,
        })
    );
    assert_eq!(
        decode_descriptor_v1(&[0xff]),
        Err(DescriptorDecodeError::MalformedJson)
    );
}

#[test]
fn duplicate_fields_are_rejected_individually() {
    assert_eq!(
        decode_descriptor_v1(include_bytes!(
            "../../../schemas/root/v1/fixtures/malformed/duplicate-format.json"
        )),
        Err(DescriptorDecodeError::DuplicateField {
            field: DescriptorField::Format,
        })
    );
    assert_eq!(
        decode_descriptor_v1(include_bytes!(
            "../../../schemas/root/v1/fixtures/malformed/duplicate-version.json"
        )),
        Err(DescriptorDecodeError::DuplicateField {
            field: DescriptorField::Version,
        })
    );
}

#[test]
fn unknown_and_missing_fields_are_rejected_individually() {
    assert_eq!(
        decode_descriptor_v1(include_bytes!(
            "../../../schemas/root/v1/fixtures/malformed/unknown-field.json"
        )),
        Err(DescriptorDecodeError::UnknownField {
            field: "extra".to_owned(),
        })
    );
    assert_eq!(
        decode_descriptor_v1(include_bytes!(
            "../../../schemas/root/v1/fixtures/malformed/missing-format.json"
        )),
        Err(DescriptorDecodeError::MissingField {
            field: DescriptorField::Format,
        })
    );
    assert_eq!(
        decode_descriptor_v1(include_bytes!(
            "../../../schemas/root/v1/fixtures/malformed/missing-version.json"
        )),
        Err(DescriptorDecodeError::MissingField {
            field: DescriptorField::Version,
        })
    );
}

#[test]
fn both_field_types_are_strict() {
    assert_eq!(
        decode_descriptor_v1(include_bytes!(
            "../../../schemas/root/v1/fixtures/malformed/wrong-format-type.json"
        )),
        Err(DescriptorDecodeError::WrongType {
            field: DescriptorField::Format,
            expected: DescriptorValueType::String,
            actual: JsonValueType::Number,
        })
    );
    assert_eq!(
        decode_descriptor_v1(include_bytes!(
            "../../../schemas/root/v1/fixtures/malformed/wrong-version-type.json"
        )),
        Err(DescriptorDecodeError::WrongType {
            field: DescriptorField::Version,
            expected: DescriptorValueType::UnsignedInteger,
            actual: JsonValueType::String,
        })
    );
}

#[test]
fn every_semantically_equivalent_alternate_encoding_is_noncanonical() {
    for bytes in [
        include_bytes!("../../../schemas/root/v1/fixtures/malformed/noncanonical-whitespace.json")
            as &[u8],
        include_bytes!("../../../schemas/root/v1/fixtures/malformed/noncanonical-order.json"),
        include_bytes!("../../../schemas/root/v1/fixtures/malformed/noncanonical-escape.json"),
    ] {
        assert_eq!(
            decode_descriptor_v1(bytes),
            Err(DescriptorDecodeError::NonCanonical)
        );
    }
}

#[test]
fn unsupported_format_and_version_are_structured_compatibility_errors() {
    assert_eq!(
        decode_descriptor_v1(include_bytes!(
            "../../../schemas/root/v1/fixtures/unsupported/format.json"
        )),
        Err(DescriptorDecodeError::UnsupportedFormat {
            expected: DESCRIPTOR_FORMAT,
            found: "malm-state-next".to_owned(),
        })
    );
    assert_eq!(
        decode_descriptor_v1(include_bytes!(
            "../../../schemas/root/v1/fixtures/unsupported/version.json"
        )),
        Err(DescriptorDecodeError::UnsupportedVersion {
            expected: DESCRIPTOR_VERSION,
            found: 2,
        })
    );
}

#[test]
fn descriptor_size_is_bounded_before_parsing() {
    let oversized = vec![b' '; MAX_DESCRIPTOR_BYTES + 1];
    assert_eq!(
        decode_descriptor_v1(&oversized),
        Err(DescriptorDecodeError::TooLarge {
            limit: MAX_DESCRIPTOR_BYTES,
            actual: MAX_DESCRIPTOR_BYTES + 1,
        })
    );

    let at_limit = vec![b' '; MAX_DESCRIPTOR_BYTES];
    assert_eq!(
        decode_descriptor_v1(&at_limit),
        Err(DescriptorDecodeError::MalformedJson)
    );
}

#[test]
fn production_root_resolution_obeys_xdg_set_and_unset_rules() {
    let home = Path::new("/home/alice");
    assert_eq!(
        resolve_root(Some(home), None).unwrap(),
        PathBuf::from("/home/alice/.local/state/malm")
    );
    assert_eq!(
        resolve_root(Some(home), Some(Path::new("/state/alice"))).unwrap(),
        PathBuf::from("/state/alice/malm")
    );
    assert_eq!(
        resolve_root(None, Some(Path::new("/state/alice"))).unwrap(),
        PathBuf::from("/state/alice/malm")
    );
    assert_eq!(
        resolve_root(
            Some(Path::new("relative-home")),
            Some(Path::new("/state/alice"))
        )
        .unwrap(),
        PathBuf::from("/state/alice/malm")
    );
}

#[test]
fn root_resolution_rejects_invalid_explicit_environment_values() {
    assert_eq!(resolve_root(None, None), Err(RootPathError::HomeMissing));
    assert_eq!(
        resolve_root(Some(Path::new("")), None),
        Err(RootPathError::HomeEmpty)
    );
    assert_eq!(
        resolve_root(Some(Path::new("home/alice")), None),
        Err(RootPathError::HomeNotAbsolute {
            home: PathBuf::from("home/alice"),
        })
    );
    assert_eq!(require_home(None), Err(RootPathError::HomeMissing));
    assert_eq!(
        resolve_root(None, Some(Path::new(""))),
        Err(RootPathError::XdgStateHomeEmpty)
    );
    assert_eq!(
        resolve_root(None, Some(Path::new("state/alice"))),
        Err(RootPathError::XdgStateHomeNotAbsolute {
            xdg_state_home: PathBuf::from("state/alice"),
        })
    );
}

#[test]
fn final_root_top_level_allowlist_is_exact_ordered_and_typed() {
    assert_eq!(CONTAINER_MODE, 0o700);
    assert_eq!(MUTABLE_FILE_MODE, 0o600);
    let expected = [
        ("descriptor.json", FinalRootEntryKind::Descriptor, 0o600),
        ("state", FinalRootEntryKind::Directory, 0o700),
        ("objects", FinalRootEntryKind::Directory, 0o700),
        ("prepared", FinalRootEntryKind::Directory, 0o700),
        ("transactions", FinalRootEntryKind::Directory, 0o700),
        ("transaction.lock", FinalRootEntryKind::Lock, 0o600),
        ("maintenance.lock", FinalRootEntryKind::Lock, 0o600),
    ];
    assert_eq!(FINAL_ROOT_ENTRIES.len(), expected.len());
    for (entry, (name, kind, mode)) in FINAL_ROOT_ENTRIES.iter().zip(expected) {
        assert_eq!(entry.name(), name);
        assert_eq!(entry.kind(), kind);
        assert_eq!(entry.mode(), mode);
        assert_eq!(final_root_entry(name.as_bytes()), Some(*entry));
    }
    assert_eq!(final_root_entry(b"format.json"), None);
    assert_eq!(final_root_entry(b"unknown"), None);
    assert_eq!(final_root_entry(b"state\xff"), None);
}

#[test]
fn injected_roots_must_be_absolute_non_root_and_normalized() {
    assert_eq!(
        validate_injected_root(Path::new("/var/lib/malm-test")),
        Ok(())
    );
    assert!(matches!(
        validate_injected_root(Path::new("var/lib/malm-test")),
        Err(RootPathError::InjectedRootNotAbsolute { .. })
    ));
    assert!(matches!(
        validate_injected_root(Path::new("/")),
        Err(RootPathError::InjectedRootIsFilesystemRoot { .. })
    ));
    assert!(matches!(
        validate_injected_root(Path::new("/var/./malm-test")),
        Err(RootPathError::InjectedRootDotComponent { .. })
    ));
    assert!(matches!(
        validate_injected_root(Path::new("/var/lib/../malm-test")),
        Err(RootPathError::InjectedRootParentComponent { .. })
    ));
    assert!(matches!(
        validate_injected_root(Path::new("/var//lib/malm-test")),
        Err(RootPathError::InjectedRootNotNormalized { .. })
    ));
    assert!(matches!(
        validate_injected_root(Path::new("/var/lib/malm-test/")),
        Err(RootPathError::InjectedRootNotNormalized { .. })
    ));
}

#[test]
fn descriptor_decode_error_strings_are_pinned() {
    let error = |bytes: &[u8]| decode_descriptor_v1(bytes).unwrap_err().to_string();

    assert_eq!(
        error(br#"{"format":"malm-state","format":"malm-state","version":1}"#),
        "descriptor field Format is duplicated"
    );
    assert_eq!(
        error(br#"{"format":"malm-state","version":1,"version":1}"#),
        "descriptor field Version is duplicated"
    );

    assert_eq!(error(b"null"), "descriptor must be an object, found null");
    assert_eq!(
        error(b"true"),
        "descriptor must be an object, found boolean"
    );
    assert_eq!(error(b"7"), "descriptor must be an object, found number");
    assert_eq!(error(b"-7"), "descriptor must be an object, found number");
    assert_eq!(error(b"1.5"), "descriptor must be an object, found number");
    assert_eq!(
        error(b"\"x\""),
        "descriptor must be an object, found string"
    );
    assert_eq!(error(b"[1,2]"), "descriptor must be an object, found array");

    assert_eq!(
        error(br#"{"format":"malm-state","version":1,"extra":0}"#),
        "descriptor field \"extra\" is unknown"
    );

    assert_eq!(
        error(br#"{"format":1,"version":1}"#),
        "descriptor field Format must be string, found number"
    );
    assert_eq!(
        error(br#"{"format":"malm-state","version":"1"}"#),
        "descriptor field Version must be unsigned integer, found string"
    );
    assert_eq!(
        error(br#"{"format":"malm-state","version":-1}"#),
        "descriptor field Version must be unsigned integer, found number"
    );

    // Missing fields are reported in format-then-version order.
    assert_eq!(error(b"{}"), "descriptor field Format is missing");
    assert_eq!(
        error(br#"{"format":"malm-state"}"#),
        "descriptor field Version is missing"
    );
}

#[test]
fn descriptor_decode_error_precedence_is_pinned() {
    // The first in-map error wins in key order.
    assert_eq!(
        decode_descriptor_v1(br#"{"format":"a","format":"b","bogus":1}"#),
        Err(DescriptorDecodeError::DuplicateField {
            field: DescriptorField::Format,
        })
    );
    assert_eq!(
        decode_descriptor_v1(br#"{"bogus":1,"format":"a","format":"b"}"#),
        Err(DescriptorDecodeError::UnknownField {
            field: "bogus".to_owned(),
        })
    );
    // In-map errors take precedence over missing fields.
    assert_eq!(
        decode_descriptor_v1(br#"{"version":1,"version":2}"#),
        Err(DescriptorDecodeError::DuplicateField {
            field: DescriptorField::Version,
        })
    );
    // Format type errors take precedence over version type errors.
    assert_eq!(
        decode_descriptor_v1(br#"{"format":1,"version":"x"}"#),
        Err(DescriptorDecodeError::WrongType {
            field: DescriptorField::Format,
            expected: DescriptorValueType::String,
            actual: JsonValueType::Number,
        })
    );
    // Trailing data makes an otherwise valid top-level value malformed.
    assert_eq!(
        decode_descriptor_v1(b"7 x"),
        Err(DescriptorDecodeError::MalformedJson)
    );
    assert_eq!(
        decode_descriptor_v1(b"[1,2] x"),
        Err(DescriptorDecodeError::MalformedJson)
    );
}

#[test]
fn injected_root_error_strings_are_pinned() {
    let error = |path: &str| {
        validate_injected_root(Path::new(path))
            .unwrap_err()
            .to_string()
    };

    assert_eq!(
        error("/var/./malm-test"),
        "injected root contains a dot component: \"/var/./malm-test\""
    );
    assert_eq!(
        error("/var/lib/../malm-test"),
        "injected root contains a parent component: \"/var/lib/../malm-test\""
    );
    assert_eq!(
        error("/var//lib/malm-test"),
        "injected root is not normalized: \"/var//lib/malm-test\""
    );
    assert_eq!(
        error("/var/lib/malm-test/"),
        "injected root is not normalized: \"/var/lib/malm-test/\""
    );
    // Absoluteness is checked before path components.
    assert_eq!(
        error("var/./malm-test"),
        "injected root must be absolute, found \"var/./malm-test\""
    );
    assert_eq!(
        error("/"),
        "injected root must not be a filesystem root, found \"/\""
    );
}

#[test]
fn record_family_inventory_is_complete_ordered_and_unique() {
    assert_eq!(
        RecordFamilyV1::ALL,
        &[
            RecordFamilyV1::GlobalCatalog,
            RecordFamilyV1::NamespaceGeneration,
            RecordFamilyV1::DesiredSnapshot,
            RecordFamilyV1::TrackedRoot,
            RecordFamilyV1::PreparedRecord,
            RecordFamilyV1::TransactionJournal,
            RecordFamilyV1::Blob,
            RecordFamilyV1::Symlink,
            RecordFamilyV1::Tree,
            RecordFamilyV1::ArchiveDeclaration,
            RecordFamilyV1::ArchiveProvenance,
            RecordFamilyV1::ConfigIr,
            RecordFamilyV1::Transform,
            RecordFamilyV1::Lifecycle,
            RecordFamilyV1::Inspection,
            RecordFamilyV1::Fsck,
            RecordFamilyV1::Retention,
        ]
    );
    let identifiers = RecordFamilyV1::ALL
        .iter()
        .map(|family| family.identifier())
        .collect::<BTreeSet<_>>();
    assert_eq!(identifiers.len(), RecordFamilyV1::ALL.len());
    assert!(identifiers.iter().all(|identifier| !identifier.is_empty()));
}

#[test]
fn operation_inventory_is_complete_ordered_and_unique() {
    assert_eq!(
        OperationV1::ALL,
        &[
            OperationV1::Deployment,
            OperationV1::Update,
            OperationV1::Lifecycle,
            OperationV1::Status,
            OperationV1::History,
            OperationV1::Fsck,
            OperationV1::Retention,
            OperationV1::Inspection,
        ]
    );
    let identifiers = OperationV1::ALL
        .iter()
        .map(|operation| operation.identifier())
        .collect::<BTreeSet<_>>();
    assert_eq!(identifiers.len(), OperationV1::ALL.len());
    assert!(identifiers.iter().all(|identifier| !identifier.is_empty()));
}
