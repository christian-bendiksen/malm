use malm_pack::{
    ComponentInterfaceV1, DependencySourceV1, GitObjectId, GitSourceV1, GitUrl, LocalLocator,
    LockReadError, LockV1, LockValidationError, LockedComponentV1, LockedDependencyV1,
    LockedPackV1, LockedSourceV1, PackDependencyV1, PackManifestV1, PackModuleV1, PackPath,
    PackReadError, PackSubdir, classify_pack_tree_path, decode_lock_v1, decode_pack_v1,
    encode_lock_v1, encode_pack_v1, lock_graph_digest, pack_content_digest, pack_node_id,
    read_pack_object_v1, write_pack_object_v1,
};
use malm_types::{Alias, ContributionName, Digest, PackageId};

const PACK_MINIMAL: &[u8] = include_bytes!("../../../schemas/pack/v1/fixtures/valid/minimal.kdl");
const PACK_FULL: &[u8] = include_bytes!("../../../schemas/pack/v1/fixtures/valid/full.kdl");

fn package(value: &str) -> PackageId {
    PackageId::new(value).unwrap()
}

fn alias(value: &str) -> Alias {
    Alias::new(value).unwrap()
}

fn name(value: &str) -> ContributionName {
    ContributionName::new(value).unwrap()
}

fn path(value: &str) -> PackPath {
    PackPath::new(value).unwrap()
}

fn local(value: &str) -> LockedSourceV1 {
    LockedSourceV1::Local(LocalLocator::new(value).unwrap())
}

fn empty_node(package_id: &str, source: LockedSourceV1, content: &[u8]) -> LockedPackV1 {
    LockedPackV1::new(
        package(package_id),
        source,
        Digest::sha256(content),
        vec![],
        vec![],
    )
    .unwrap()
}

fn sample_lock() -> LockV1 {
    let leaf = empty_node("com.example.common", local("packs/common"), b"common tree");
    let root = LockedPackV1::new(
        package("com.example.root"),
        LockedSourceV1::Root,
        Digest::sha256(b"root tree"),
        vec![LockedDependencyV1::new(
            alias("common"),
            leaf.node_id().clone(),
        )],
        vec![],
    )
    .unwrap();
    LockV1::new(root.node_id().clone(), vec![leaf, root]).unwrap()
}

#[test]
fn pack_fixtures_decode_and_canonical_writer_round_trips() {
    let minimal = decode_pack_v1(PACK_MINIMAL).unwrap();
    assert_eq!(minimal.package_id().as_str(), "com.example.minimal");
    assert!(minimal.modules().is_empty());

    let full = decode_pack_v1(PACK_FULL).unwrap();
    assert_eq!(full.package_id().as_str(), "com.example.desktop");
    assert_eq!(full.modules().len(), 1);
    assert_eq!(full.config_documents().len(), 1);
    assert_eq!(full.dependencies().len(), 2);
    assert_eq!(full.components().len(), 1);

    let canonical = encode_pack_v1(&full);
    assert_eq!(
        canonical,
        include_str!("../../../schemas/pack/v1/fixtures/golden/full.kdl")
    );
    assert_eq!(decode_pack_v1(canonical.as_bytes()).unwrap(), full);
    assert_eq!(encode_pack_v1(&full), canonical);

    let old_spelling = canonical.replace(
        "interface=\"format-component/v1\"",
        "interface=\"format-component/v1\" execution-profile=sha256-1111111111111111111111111111111111111111111111111111111111111111",
    );
    assert!(matches!(
        decode_pack_v1(old_spelling.as_bytes()),
        Err(PackReadError::InvalidManifest(_))
    ));
}

#[test]
fn source_component_omits_profile_while_lock_component_requires_it() {
    let declaration = malm_pack::BundledComponentV1::new(
        name("renderer"),
        path("components/renderer.wasm"),
        Digest::sha256(b"renderer"),
        ComponentInterfaceV1::FormatComponentV1,
    );
    let manifest = PackManifestV1::new(
        package("com.example.root"),
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
        vec![declaration.clone()],
    )
    .unwrap();
    assert!(!encode_pack_v1(&manifest).contains("execution-profile"));

    let profile = Digest::sha256(b"locked execution profile");
    let root = LockedPackV1::new(
        manifest.package_id().clone(),
        LockedSourceV1::Root,
        Digest::sha256(b"root pack"),
        vec![],
        vec![LockedComponentV1::from_declaration(
            &declaration,
            profile.clone(),
        )],
    )
    .unwrap();
    let lock = LockV1::new(root.node_id().clone(), vec![root]).unwrap();
    lock.validate_manifest(lock.root_node_id(), &manifest)
        .unwrap();
    assert_eq!(
        lock.nodes()[0].components()[0].execution_profile(),
        &profile
    );
    let encoded = encode_lock_v1(&lock);
    let text = String::from_utf8(encoded.clone()).unwrap();
    assert!(text.contains("\"execution_profile\""));
    assert!(text.contains(profile.as_str()));
    assert_eq!(decode_lock_v1(&encoded).unwrap(), lock);
}

#[test]
fn pack_reader_rejects_unsupported_and_every_malformed_fixture() {
    let unsupported = include_bytes!("../../../schemas/pack/v1/fixtures/unsupported/version-2.kdl");
    assert!(matches!(
        decode_pack_v1(unsupported),
        Err(PackReadError::UnsupportedVersion { found: 2, .. })
    ));

    for bytes in [
        include_bytes!("../../../schemas/pack/v1/fixtures/malformed/missing-section.kdl")
            as &[u8],
        include_bytes!("../../../schemas/pack/v1/fixtures/malformed/duplicate-alias.kdl"),
        include_bytes!("../../../schemas/pack/v1/fixtures/malformed/unknown-property.kdl"),
        include_bytes!("../../../schemas/pack/v1/fixtures/malformed/annotated.kdl"),
    ] {
        assert!(decode_pack_v1(bytes).is_err());
    }
}

#[test]
fn pack_paths_and_local_locators_are_distinct_strict_types() {
    assert!(PackPath::new("modules/main.kdl").is_ok());
    for invalid in [
        "",
        "/absolute",
        "a//b",
        "a/./b",
        "a/../b",
        "a\\b",
        ".git/config",
        "nested/malm.lock",
        "nested/.malm-lock.tmp",
    ] {
        assert!(PackPath::new(invalid).is_err(), "accepted {invalid:?}");
    }

    for valid in [".", "packs/common", "../shared", "../../shared/pack"] {
        assert!(LocalLocator::new(valid).is_ok(), "rejected {valid:?}");
    }
    for invalid in ["/absolute", "packs/../shared", "./packs", "packs//common"] {
        assert!(LocalLocator::new(invalid).is_err(), "accepted {invalid:?}");
    }

    assert_eq!(classify_pack_tree_path(".git/config").unwrap(), None);
    assert_eq!(classify_pack_tree_path("nested/malm.lock").unwrap(), None);
    assert_eq!(
        classify_pack_tree_path("nested/.malm-lock.tmp").unwrap(),
        None
    );
    assert_eq!(
        classify_pack_tree_path("modules/main.kdl").unwrap(),
        Some(path("modules/main.kdl"))
    );
}

#[test]
fn exact_git_selectors_reject_mutable_or_ambiguous_forms() {
    assert!(GitUrl::new("https://example.org/repo.git").is_ok());
    for invalid in [
        "http://example.org/repo.git",
        "https://user:secret@example.org/repo.git",
        "https://example.org/repo.git?branch=main",
        "https://example.org/repo.git#main",
        " https://example.org/repo.git",
        "https:\\example.org\\repo.git",
    ] {
        assert!(GitUrl::new(invalid).is_err(), "accepted {invalid:?}");
    }
    assert_eq!(
        GitUrl::new("https://EXAMPLE.ORG:443/a/../repo.git")
            .unwrap()
            .as_str(),
        "https://example.org/repo.git"
    );

    assert!(GitObjectId::new(format!("sha1-{}", "a".repeat(40))).is_ok());
    assert!(GitObjectId::new(format!("sha256-{}", "b".repeat(64))).is_ok());
    assert!(GitObjectId::new("abc1234").is_err());
    assert!(GitObjectId::new(format!("sha1-{}", "A".repeat(40))).is_err());
}

#[test]
fn whole_tree_digest_is_sorted_framed_and_sensitive_to_every_included_byte() {
    let manifest = path("malm-pack.kdl");
    let module = path("modules/main.kdl");
    let first = pack_content_digest([
        (&module, b"module bytes".as_slice()),
        (&manifest, PACK_MINIMAL),
    ])
    .unwrap();
    let reordered = pack_content_digest([
        (&manifest, PACK_MINIMAL),
        (&module, b"module bytes".as_slice()),
    ])
    .unwrap();
    let changed = pack_content_digest([
        (&manifest, PACK_MINIMAL),
        (&module, b"module byteS".as_slice()),
    ])
    .unwrap();

    assert_eq!(first, reordered);
    assert_ne!(first, changed);
    let golden: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/pack/v1/fixtures/golden/digests.json"
    ))
    .unwrap();
    assert_eq!(first.as_str(), golden["minimal_manifest_plus_module"]);
}

#[test]
fn canonical_pack_object_bytes_are_the_digest_preimage_and_round_trip() {
    let files = vec![
        malm_pack::PackFileV1::new(path("modules/main.kdl"), b"module bytes"),
        malm_pack::PackFileV1::new(path("malm-pack.kdl"), PACK_MINIMAL),
    ];
    let mut object = Vec::new();
    let digest = write_pack_object_v1(&files, &mut object).unwrap();

    assert_eq!(digest, Digest::sha256(&object));
    assert_eq!(
        digest,
        pack_content_digest(files.iter().map(|file| (file.path(), file.bytes()))).unwrap()
    );
    assert_eq!(
        read_pack_object_v1(&mut object.as_slice(), &digest).unwrap(),
        vec![
            malm_pack::PackFileV1::new(path("malm-pack.kdl"), PACK_MINIMAL),
            malm_pack::PackFileV1::new(path("modules/main.kdl"), b"module bytes"),
        ]
    );

    let mut expected_prefix = b"malm-pack-content\0".to_vec();
    expected_prefix.extend_from_slice(&1_u16.to_be_bytes());
    expected_prefix.extend_from_slice(&2_u64.to_be_bytes());
    assert!(object.starts_with(&expected_prefix));
}

#[test]
fn canonical_pack_object_encoding_matches_golden_bytes_and_digest() {
    // Independently computed from the pack-object/v1 framing: domain,
    // big-endian u16 version, u64 entry count, then length-prefixed entries.
    const GOLDEN_BYTES_HEX: &str = "6d616c6d2d7061636b2d636f6e74656e74000001000000000000000200000000\
                                    0000000d6d616c6d2d7061636b2e6b646c00000000000000086d616e69666573\
                                    7400000000000000106d6f64756c65732f6d61696e2e6b646c00000000000000\
                                    066d6f64756c65";
    const GOLDEN_DIGEST: &str =
        "sha256-ae18a9e1c6a0dbd699bd9e81d14934374e3babd0420dc901773acbdb9112d601";

    let files = vec![
        malm_pack::PackFileV1::new(path("modules/main.kdl"), b"module"),
        malm_pack::PackFileV1::new(path("malm-pack.kdl"), b"manifest"),
    ];
    let mut object = Vec::new();
    let digest = write_pack_object_v1(&files, &mut object).unwrap();

    let golden_hex = GOLDEN_BYTES_HEX
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    let golden_bytes = (0..golden_hex.len())
        .step_by(2)
        .map(|position| u8::from_str_radix(&golden_hex[position..position + 2], 16).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(object, golden_bytes);
    assert_eq!(digest.as_str(), GOLDEN_DIGEST);
    assert_eq!(
        pack_content_digest(files.iter().map(|file| (file.path(), file.bytes())))
            .unwrap()
            .as_str(),
        GOLDEN_DIGEST
    );
}

#[test]
fn canonical_pack_object_reader_rejects_noncanonical_or_corrupt_streams() {
    let files = vec![malm_pack::PackFileV1::new(
        path("malm-pack.kdl"),
        PACK_MINIMAL,
    )];
    let mut object = Vec::new();
    let digest = write_pack_object_v1(&files, &mut object).unwrap();

    let mut trailing = object.clone();
    trailing.push(0);
    assert!(read_pack_object_v1(&mut trailing.as_slice(), &digest).is_err());

    let mut wrong_domain = object.clone();
    wrong_domain[0] = b'M';
    assert!(read_pack_object_v1(&mut wrong_domain.as_slice(), &digest).is_err());

    let mut unsupported = object.clone();
    let version_offset = b"malm-pack-content\0".len();
    unsupported[version_offset..version_offset + 2].copy_from_slice(&2_u16.to_be_bytes());
    assert!(matches!(
        read_pack_object_v1(&mut unsupported.as_slice(), &digest),
        Err(malm_pack::PackObjectReadError::UnsupportedVersion { found: 2, .. })
    ));

    let mut truncated = &object[..object.len() - 1];
    assert!(read_pack_object_v1(&mut truncated, &digest).is_err());
    assert!(matches!(
        read_pack_object_v1(&mut object.as_slice(), &Digest::sha256(b"wrong")),
        Err(malm_pack::PackObjectReadError::DigestMismatch { .. })
    ));
}

#[test]
fn lock_json_round_trips_and_uses_semantic_order() {
    let lock = sample_lock();
    let encoded = encode_lock_v1(&lock);
    assert_eq!(
        encoded,
        include_bytes!("../../../schemas/lock/v1/fixtures/valid/single-dependency.json")
    );
    assert_eq!(decode_lock_v1(&encoded).unwrap(), lock);
    assert_eq!(encode_lock_v1(&decode_lock_v1(&encoded).unwrap()), encoded);

    let mut value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
    value["nodes"].as_array_mut().unwrap().reverse();
    let reordered = serde_json::to_vec(&value).unwrap();
    let decoded = decode_lock_v1(&reordered).unwrap();
    assert_eq!(decoded, lock);
    assert_eq!(lock_graph_digest(&decoded), lock_graph_digest(&lock));
}

#[test]
fn lock_reader_rejects_duplicate_unknown_and_unsupported_json() {
    for bytes in [
        include_bytes!("../../../schemas/lock/v1/fixtures/malformed/duplicate-version.json")
            as &[u8],
        include_bytes!("../../../schemas/lock/v1/fixtures/malformed/missing-version.json"),
        include_bytes!("../../../schemas/lock/v1/fixtures/malformed/wrong-type.json"),
    ] {
        assert!(matches!(
            decode_lock_v1(bytes),
            Err(LockReadError::MalformedJson(_))
        ));
    }
    let unsupported =
        include_bytes!("../../../schemas/lock/v1/fixtures/unsupported/version-2.json");
    assert!(matches!(
        decode_lock_v1(unsupported),
        Err(LockReadError::UnsupportedVersion { found: 2, .. })
    ));

    let encoded = String::from_utf8(encode_lock_v1(&sample_lock())).unwrap();
    let unknown = encoded.replacen(
        "\"schema_version\": 1,",
        "\"schema_version\": 1,\n  \"unknown\": true,",
        1,
    );
    assert!(matches!(
        decode_lock_v1(unknown.as_bytes()),
        Err(LockReadError::MalformedJson(_))
    ));
}

#[test]
fn lock_rejects_dangling_unreachable_and_cyclic_graphs() {
    let missing = empty_node("com.example.missing", local("missing"), b"missing");
    let dangling = LockedPackV1::new(
        package("com.example.root"),
        LockedSourceV1::Root,
        Digest::sha256(b"root"),
        vec![LockedDependencyV1::new(
            alias("missing"),
            missing.node_id().clone(),
        )],
        vec![],
    )
    .unwrap();
    assert!(matches!(
        LockV1::new(dangling.node_id().clone(), vec![dangling]),
        Err(LockValidationError::MissingTarget { .. })
    ));

    let root = empty_node("com.example.root", LockedSourceV1::Root, b"root");
    let extra = empty_node("com.example.extra", local("extra"), b"extra");
    assert!(matches!(
        LockV1::new(root.node_id().clone(), vec![root, extra]),
        Err(LockValidationError::UnreachableNode(_))
    ));

    let root_source = LockedSourceV1::Root;
    let child_source = local("child");
    let root_package = package("com.example.root");
    let child_package = package("com.example.child");
    let root_digest = Digest::sha256(b"root");
    let child_digest = Digest::sha256(b"child");
    let root_id = pack_node_id(&root_source, &root_package, &root_digest);
    let child_id = pack_node_id(&child_source, &child_package, &child_digest);
    let cyclic_root = LockedPackV1::new(
        root_package,
        root_source,
        root_digest,
        vec![LockedDependencyV1::new(alias("child"), child_id.clone())],
        vec![],
    )
    .unwrap();
    let cyclic_child = LockedPackV1::new(
        child_package,
        child_source,
        child_digest,
        vec![LockedDependencyV1::new(alias("root"), root_id.clone())],
        vec![],
    )
    .unwrap();
    assert!(matches!(
        LockV1::new(root_id, vec![cyclic_root, cyclic_child]),
        Err(LockValidationError::Cycle { .. })
    ));
}

#[test]
fn lock_rejects_conflicting_snapshots_for_one_exact_source() {
    let first = empty_node("com.example.shared", local("shared"), b"first");
    let second = empty_node("com.example.shared", local("shared"), b"second");
    let root = LockedPackV1::new(
        package("com.example.root"),
        LockedSourceV1::Root,
        Digest::sha256(b"root"),
        vec![
            LockedDependencyV1::new(alias("first"), first.node_id().clone()),
            LockedDependencyV1::new(alias("second"), second.node_id().clone()),
        ],
        vec![],
    )
    .unwrap();
    assert!(matches!(
        LockV1::new(root.node_id().clone(), vec![root, first, second]),
        Err(LockValidationError::ConflictingSource { .. })
    ));
}

#[test]
fn diamonds_alias_reuse_and_multiple_aliases_to_one_target_are_valid() {
    let shared = empty_node("com.example.shared", local("shared"), b"shared");
    let left = LockedPackV1::new(
        package("com.example.left"),
        local("left"),
        Digest::sha256(b"left"),
        vec![LockedDependencyV1::new(
            alias("base"),
            shared.node_id().clone(),
        )],
        vec![],
    )
    .unwrap();
    let right = LockedPackV1::new(
        package("com.example.right"),
        local("right"),
        Digest::sha256(b"right"),
        vec![LockedDependencyV1::new(
            alias("base"),
            shared.node_id().clone(),
        )],
        vec![],
    )
    .unwrap();
    let root = LockedPackV1::new(
        package("com.example.root"),
        LockedSourceV1::Root,
        Digest::sha256(b"root"),
        vec![
            LockedDependencyV1::new(alias("left"), left.node_id().clone()),
            LockedDependencyV1::new(alias("right"), right.node_id().clone()),
            LockedDependencyV1::new(alias("shared-a"), shared.node_id().clone()),
            LockedDependencyV1::new(alias("shared-b"), shared.node_id().clone()),
        ],
        vec![],
    )
    .unwrap();
    let lock = LockV1::new(root.node_id().clone(), vec![right, shared, root, left]).unwrap();
    assert_eq!(lock.nodes().len(), 4);
}

#[test]
fn manifest_agreement_checks_alias_target_source_package_and_components() {
    let lock = sample_lock();
    let root = lock.node(lock.root_node_id()).unwrap();
    let manifest = PackManifestV1::new(
        package("com.example.root"),
        vec![PackModuleV1::new(name("main"), path("modules/main.kdl"))],
        vec![PackDependencyV1::new(
            alias("common"),
            package("com.example.common"),
            DependencySourceV1::Local(LocalLocator::new("packs/common").unwrap()),
        )],
        vec![],
        vec![],
        vec![],
        vec![],
    )
    .unwrap();
    lock.validate_manifest(root.node_id(), &manifest).unwrap();

    let wrong = PackManifestV1::new(
        package("com.example.wrong"),
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
        vec![],
    )
    .unwrap();
    assert!(matches!(
        lock.validate_manifest(root.node_id(), &wrong),
        Err(LockValidationError::ManifestMismatch { .. })
    ));

    for declaration in [
        PackDependencyV1::new(
            alias("other"),
            package("com.example.common"),
            DependencySourceV1::Local(LocalLocator::new("packs/common").unwrap()),
        ),
        PackDependencyV1::new(
            alias("common"),
            package("com.example.common"),
            DependencySourceV1::Local(LocalLocator::new("packs/other").unwrap()),
        ),
    ] {
        let mismatch = PackManifestV1::new(
            package("com.example.root"),
            vec![],
            vec![declaration],
            vec![],
            vec![],
            vec![],
            vec![],
        )
        .unwrap();
        assert!(matches!(
            lock.validate_manifest(root.node_id(), &mismatch),
            Err(LockValidationError::ManifestMismatch { .. })
        ));
    }

    let component_mismatch = PackManifestV1::new(
        package("com.example.root"),
        vec![],
        vec![PackDependencyV1::new(
            alias("common"),
            package("com.example.common"),
            DependencySourceV1::Local(LocalLocator::new("packs/common").unwrap()),
        )],
        vec![],
        vec![],
        vec![],
        vec![malm_pack::BundledComponentV1::new(
            name("renderer"),
            path("components/renderer.wasm"),
            Digest::sha256(b"renderer"),
            ComponentInterfaceV1::FormatComponentV1,
        )],
    )
    .unwrap();
    assert!(matches!(
        lock.validate_manifest(root.node_id(), &component_mismatch),
        Err(LockValidationError::ManifestMismatch { .. })
    ));
}

#[test]
fn canonical_node_and_graph_digests_have_golden_values() {
    let lock = sample_lock();
    let golden: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/lock/v1/fixtures/golden/digests.json"
    ))
    .unwrap();
    assert_eq!(lock.root_node_id().as_ref(), golden["root_node_id"]);
    assert_eq!(lock_graph_digest(&lock).as_str(), golden["graph_digest"]);
}

#[test]
fn model_constructors_cover_git_and_component_records() {
    let source = GitSourceV1::new(
        GitUrl::new("https://example.org/pack.git").unwrap(),
        GitObjectId::new(format!("sha1-{}", "a".repeat(40))).unwrap(),
        PackSubdir::Root,
    );
    let component = malm_pack::BundledComponentV1::new(
        name("renderer"),
        path("components/renderer.wasm"),
        Digest::sha256(b"component"),
        ComponentInterfaceV1::FormatComponentV1,
    );
    let manifest = PackManifestV1::new(
        package("com.example.pack"),
        vec![],
        vec![PackDependencyV1::new(
            alias("remote"),
            package("com.example.remote"),
            DependencySourceV1::Git(source),
        )],
        vec![],
        vec![],
        vec![],
        vec![component],
    )
    .unwrap();
    assert_eq!(
        decode_pack_v1(encode_pack_v1(&manifest).as_bytes()).unwrap(),
        manifest
    );
}

#[test]
fn lock_schema_is_draft_2020_12_and_strict_at_every_object_level() {
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../schemas/lock/v1/schema.json")).unwrap();
    assert_eq!(
        schema["$schema"],
        "https://json-schema.org/draft/2020-12/schema"
    );
    assert_eq!(schema["properties"]["schema_version"]["const"], 1);
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(schema["$defs"]["node"]["additionalProperties"], false);
    assert_eq!(schema["$defs"]["component"]["additionalProperties"], false);
}
