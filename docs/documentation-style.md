# Documentation language standard

## Standard

The project uses ASD-STE100 Simplified Technical English, Issue 9, for new public technical documents.

The [official standard](https://www.asd-ste100.org/assets/files/ASD-STE100_ISSUE9.pdf) has priority over this project guide.

## Scope

This rule applies to new public instructions, descriptions, support documents, and release documents.

The rule does not change these items:

- License text
- Source code
- Command output
- Schema fields
- Serialized data
- Generated evidence
- Text from an external standard

Keep these items exact when accuracy requires exact text.

## Technical terms

The project uses software terms as approved technical nouns or technical verbs.

Use one term for one item or action. Do not use a different term for the same meaning.

The approved project terms include these terms:

- GitHub, GitHub Action, GitHub Actions, and CODEOWNERS
- repository, branch, commit, tag, issue, and pull request
- webhook, receiver, harness, observer, manifest, fixture, and schema
- CLI, CI, API, JSON, YAML, XML, JUnit, and SQLite
- CPython, uv, uvx, pipx, PyPI, GHCR, Trivy, SBOM, and OIDC
- wheel, source distribution, container, artifact, workflow, metadata, and vulnerability
- build, clone, install, test, validate, scan, sanitize, redact, publish, and upload

## Descriptions

Use these rules for descriptive text:

- Use a maximum of 25 words in each sentence.
- Give one topic in each sentence.
- Give one topic in each paragraph.
- Use a maximum of six sentences in each paragraph.
- Give information gradually.
- Use the active voice.
- Use the simple present, simple past, or simple future tense.

## Procedures

Use these rules for work steps:

1. Use a maximum of 20 words in each sentence.
2. Give one instruction in each sentence.
3. Use the imperative form.
4. Put a condition before the instruction when the reader must know the condition first.
5. Use a vertical list for complex text.

## Words and punctuation

Use American English spelling. Do not use contractions, slang, or a semicolon.

Use only approved dictionary words and approved project terms. Use each word with one consistent meaning.

Do not use a phrasal verb when a direct verb gives the same meaning.

## Review procedure

1. Run `uv run python scripts/check_ste_docs.py`.
2. Correct each reported error.
3. Compare each general word with the controlled dictionary.
4. Confirm each project term is a valid technical term.
5. Confirm that the text keeps its technical meaning.

The automated check finds mechanical errors. A manual dictionary review completes the language review.
