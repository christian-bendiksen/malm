use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use malm::{
    Engine, EngineConfig, EnginePorts, StoreAccess, StoreErrorCodeV1, StoreErrorDetailsV1,
    StoreMetadataReasonV1, StoreOperationV1, StoreRequestV1, StoreResultV1, StoreStatusV1,
};
use malm_machine::{
    MachineErrorCodeV1, MachineErrorDetailsV1, MachineErrorV1, MachineRequestV1, MachineResultV1,
    RequestEnvelopeV1, RequestIdV1, ResponseStreamValidatorV1, ServerFrameV1, decode_request_v1,
    decode_server_frame_v1, encode_request_v1, encode_server_frame_v1,
};

fn state_home(parent: &Path, name: &str) -> std::path::PathBuf {
    let path = parent.join(name);
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}

fn engine(state_home: &Path, access: StoreAccess) -> Engine {
    Engine::new(
        EngineConfig::from_state_home(state_home, access).unwrap(),
        EnginePorts::system(),
    )
}

fn request_id(value: &str) -> RequestIdV1 {
    RequestIdV1::new(value).unwrap()
}

#[test]
fn machine_records_and_embedded_calls_share_the_store_engine_dtos() {
    let temp = tempfile::tempdir().unwrap();
    let home = state_home(temp.path(), "state");
    let engine = engine(&home, StoreAccess::ReadWrite);

    let request = RequestEnvelopeV1::new(request_id("status-1"), MachineRequestV1::StoreStatus);
    let request = decode_request_v1(&encode_request_v1(&request).unwrap()).unwrap();
    let result = engine.execute_store_v1(StoreRequestV1::status()).unwrap();
    assert_eq!(result, StoreResultV1::status(StoreStatusV1::Absent));

    let mut stream = ResponseStreamValidatorV1::new(&request);
    let started =
        ServerFrameV1::started(request.request_id().clone(), request.request().operation());
    let terminal = ServerFrameV1::result(
        request.request_id().clone(),
        1,
        MachineResultV1::StoreStatus(result.store_status()),
    )
    .unwrap();
    stream.observe(&started).unwrap();
    stream.observe(&terminal).unwrap();
    assert!(stream.is_terminal());
    assert_eq!(
        decode_server_frame_v1(&encode_server_frame_v1(&terminal).unwrap()).unwrap(),
        terminal
    );

    let initialized = engine
        .execute_store_v1(StoreRequestV1::initialize())
        .unwrap();
    assert_eq!(initialized, StoreResultV1::initialized());
    assert_eq!(
        fs::read(home.join("malm/descriptor.json")).unwrap(),
        b"{\"format\":\"malm-state\",\"version\":1}\n"
    );
}

#[test]
fn machine_store_errors_omit_private_host_data() {
    let temp = tempfile::tempdir().unwrap();
    let home = state_home(temp.path(), "private-state-name");
    let engine = engine(&home, StoreAccess::ReadOnly);

    let store_error = engine
        .execute_store_v1(StoreRequestV1::initialize())
        .unwrap_err();
    assert_eq!(store_error.code(), StoreErrorCodeV1::ReadOnlyStore);
    assert_eq!(store_error.details(), StoreErrorDetailsV1::None);

    let frame = ServerFrameV1::error(
        Some(request_id("initialize-1")),
        1,
        MachineErrorV1::from_store(store_error),
    )
    .unwrap();
    let encoded = String::from_utf8(encode_server_frame_v1(&frame).unwrap()).unwrap();
    assert!(encoded.contains("\"code\":\"read-only-store\""));
    assert!(!encoded.contains(home.to_str().unwrap()));
    assert!(!encoded.contains("private-state-name"));
    assert!(!encoded.contains("uid"));
    assert!(!encoded.contains("os error"));
}

#[test]
fn malformed_and_unsupported_store_metadata_remain_structured() {
    for (name, marker, expected_code, expected_details) in [
        (
            "malformed",
            b"{\"format\":\"malm-state\",\"version\":1,\"private\":\"do-not-leak\"}\n".as_slice(),
            StoreErrorCodeV1::MalformedStoreMetadata,
            StoreErrorDetailsV1::StoreMetadata(StoreMetadataReasonV1::InvalidDescriptor),
        ),
        (
            "unsupported",
            b"{\"format\":\"malm-state\",\"version\":2}\n".as_slice(),
            StoreErrorCodeV1::UnsupportedStoreVersion,
            StoreErrorDetailsV1::UnsupportedVersion {
                expected: 1,
                found: 2,
            },
        ),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let home = state_home(temp.path(), name);
        let root = home.join("malm");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let descriptor = root.join("descriptor.json");
        fs::write(&descriptor, marker).unwrap();
        fs::set_permissions(&descriptor, fs::Permissions::from_mode(0o600)).unwrap();

        let error = engine(&home, StoreAccess::ReadWrite)
            .execute_store_v1(StoreRequestV1::status())
            .unwrap_err();
        assert_eq!(error.code(), expected_code);
        assert_eq!(error.details(), expected_details);

        let frame = ServerFrameV1::error(
            Some(request_id("status")),
            1,
            MachineErrorV1::from_store(error),
        )
        .unwrap();
        let encoded = String::from_utf8(encode_server_frame_v1(&frame).unwrap()).unwrap();
        assert!(!encoded.contains(home.to_str().unwrap()));
        assert!(!encoded.contains("do-not-leak"));
        assert!(match decode_server_frame_v1(encoded.as_bytes()).unwrap() {
            ServerFrameV1::Error { error, .. } => match expected_code {
                StoreErrorCodeV1::MalformedStoreMetadata => {
                    error.code() == MachineErrorCodeV1::MalformedStoreMetadata
                        && error.details()
                            == MachineErrorDetailsV1::StoreMetadata(
                                StoreMetadataReasonV1::InvalidDescriptor,
                            )
                }
                StoreErrorCodeV1::UnsupportedStoreVersion => {
                    error.code() == MachineErrorCodeV1::UnsupportedStoreVersion
                }
                _ => false,
            },
            _ => false,
        });
    }
}

#[test]
fn machine_requests_cannot_select_engine_roots_or_host_paths() {
    for request in [
        b"{\"schema_version\":1,\"request_id\":\"r\",\"type\":\"request\",\"root\":\"/tmp/other\",\"request\":{\"type\":\"store_status\"}}\n".as_slice(),
        b"{\"schema_version\":1,\"request_id\":\"r\",\"type\":\"request\",\"request\":{\"type\":\"store_status\",\"root\":\"/tmp/other\"}}\n".as_slice(),
        b"{\"schema_version\":1,\"request_id\":\"r\",\"type\":\"request\",\"request\":{\"type\":\"prepare\"}}\n".as_slice(),
        b"{\"schema_version\":1,\"request_id\":\"r\",\"type\":\"request\",\"request\":{\"type\":\"lock_create\",\"source\":\"/tmp/pack\",\"git_executable\":\"/usr/bin/git\"}}\n".as_slice(),
    ] {
        assert!(decode_request_v1(request).is_err());
    }

    assert_eq!(
        StoreRequestV1::status().operation(),
        StoreOperationV1::Status
    );
}
