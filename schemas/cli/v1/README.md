# cli/v1

Normal execution of a human-facing command with `--format json` emits one
structured result or error. This format is for scripts that invoke CLI commands;
integrations that need a request protocol should use `machine/v1`. `--help`
remains human-readable help and is not `cli/v1` output.

Success writes one UTF-8 JSON object followed by LF to stdout. Failure writes
one error object followed by LF to stderr and leaves stdout empty. JSON output
contains no prompts, progress, ANSI styling, or unstructured advice.

Structured identity fields always use complete canonical IDs, such as `pp-...`
or `sha256-...`. Commands may accept typed short selectors, and rejected
selector text may appear in an error's human-readable `message`; clients must
not parse that message as an identity field.

Compatibility: `cli/v1` requires `schema_version: 1`. An incompatible envelope
change requires a new version.

- **Choose and run commands:** [CLI reference](../../../docs/cli.md)
- **Implement the envelope:** [JSON Schema](envelope.schema.json)
- **Inspect accepted and rejected examples:** [fixtures](fixtures/)
- **Send process requests:** [machine protocol](../../machine/v1/README.md)
