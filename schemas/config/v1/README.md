# config/v1

`config/v1` defines both the syntax and meaning of Malm configuration. Its
strict `rich-config` KDL source evaluates to typed values, provenance,
diagnostics, and desired file, symlink, tree, archive, or transformed outputs.
Configuration and pack authors should start with the authoring guide; this
directory is the exact reference for parser, evaluator, and transform
implementers.

Evaluation receives captured bytes and a finite locked authority graph. It has
no ambient filesystem, environment, network, process, clock, randomness,
terminal, state, or target access.

Compatibility: version 1 fixes source syntax, typed data, evaluation semantics,
identity encoding, and the transform boundary. Legacy `config` and `module`
document kinds are not accepted; an incompatible change requires a new version.

- **Author configuration:** [authoring guide](../../../docs/authoring-types.md)
- **Check or render source:** [source command guide](../../../docs/cli.md#check-or-render-a-pack)
- **Implement top-level parsing:** [document grammar](grammar.md)
- **Implement expressions and statements:** [complete rich grammar](rich-grammar.md)
- **Interpret evaluated data:** [typed intermediate representation](rich-ir.md)
- **Compute document identity:** [identity encoding](canonical.md)
- **Implement transform behavior:** [transform contract](transform.md)
- **Inspect accepted and rejected data:** [fixtures](fixtures/)
