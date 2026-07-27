# malm-machine

`malm-machine` models and encodes the `machine/v1` protocol. A client creates a
typed request and encodes one JSON record; the outer `malm machine` process
decodes it, calls Engine, and emits typed event, result, or error records for the
client to decode and validate.

This crate is for authors of machine-protocol clients and process adapters. It
provides the model and codec, not the process that performs operations.

## Wire Rules

Each JSONL frame is one complete JSON object ending in one LF byte. Decoding
requires:

- valid UTF-8, exactly one terminal LF, and no embedded LF or CR;
- schema version 1, no duplicate or unknown object fields, and valid typed
  envelope semantics;
- bounded frame size, nesting depth, object members, array items, and aggregate
  JSON values.

Encoding writes the compact protocol form plus LF and verifies that the result
decodes back to the same semantic model.

## Boundary

The codec performs no I/O and calls no Engine operation. Requests contain stable
semantic data but no host paths, filesystem handles, process access, or
acquisition credentials. The process adapter chooses those capabilities when it
constructs Engine.

## API By Task

- Client requests: `RequestEnvelopeV1`, `MachineRequestV1`,
  `encode_request_v1`, and `decode_request_v1`.
- Server output: `ServerFrameV1`, `MachineResultV1`,
  `encode_server_frame_v1`, and `decode_server_frame_v1`.
- Error and stream checks: `request_error_frame_v1` maps rejected input to a
  bounded error, while `ResponseStreamValidatorV1` checks ordering and request
  correlation.

See [`machine/v1`](../../schemas/machine/v1/README.md),
the [wire protocol](../../schemas/machine/v1/protocol.md), and
[Architecture](../../docs/architecture.md).
