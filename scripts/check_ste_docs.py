"""Check mechanical ASD-STE100 rules in selected public Markdown files."""
# ruff: noqa: C901, INP001, T201

from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Final

ROOT: Final = Path(__file__).resolve().parents[1]
STE_DOCUMENTS: Final = (
    Path("CODE_OF_CONDUCT.md"),
    Path("CONTRIBUTING.md"),
    Path("SECURITY.md"),
    Path("SUPPORT.md"),
    Path(".github/PULL_REQUEST_TEMPLATE.md"),
    Path("docs/documentation-style.md"),
    Path("docs/github-action.md"),
    Path("docs/github-release-readiness.md"),
    Path("validation/final-scorecard.md"),
    Path("validation/unresolved-findings.md"),
)
_FENCE = re.compile(r"^\s*(```|~~~)")
_HEADING = re.compile(r"^\s*#{1,6}\s+")
_LIST_ITEM = re.compile(r"^\s*(?:[-*+] |\d+[.)]\s+)")
_INLINE_CODE = re.compile(r"`[^`]+`")
_LINK = re.compile(r"\[([^]]+)]\([^)]+\)")
_SENTENCE = re.compile(r"(?<=[.!?])(?:\s+|$)")
_WORD = re.compile(r"[A-Za-z0-9]+(?:[-/][A-Za-z0-9]+)*")
_CONTRACTION = re.compile(
    r"\b(?:ain't|can't|couldn't|didn't|doesn't|don't|hadn't|hasn't|haven't|"
    r"isn't|mustn't|shan't|shouldn't|wasn't|weren't|won't|wouldn't|"
    r"i'm|we're|you're|they're|i've|we've|you've|they've|i'll|we'll|"
    r"you'll|they'll|i'd|we'd|you'd|they'd|it's|that's|there's|what's)\b",
    re.IGNORECASE,
)
_PASSIVE = re.compile(
    r"\b(?:am|are|be|been|is|was|were)\s+(?:\w+ly\s+)?\w+(?:ed|en)\b",
    re.IGNORECASE,
)
_PROGRESSIVE = re.compile(
    r"\b(?:am|are|be|been|is|was|were)\s+(?:\w+ly\s+)?\w+ing\b",
    re.IGNORECASE,
)
_PERFECT = re.compile(
    r"\b(?:had|has|have)\s+(?:\w+ly\s+)?\w+(?:ed|en|t)\b",
    re.IGNORECASE,
)
_DISALLOWED_TERMS: Final = {
    "and/or": "use a vertical list or select one relation",
    "etc.": "give the complete list",
    "Github": "use GitHub",
    "repo": "use repository",
}
_MAX_DESCRIPTION_WORDS: Final = 25
_MAX_INSTRUCTION_WORDS: Final = 20
_MAX_PARAGRAPH_SENTENCES: Final = 6


def validate_documents(root: Path = ROOT) -> list[str]:
    """Return deterministic mechanical language errors for the selected documents."""
    errors: list[str] = []
    for relative_path in STE_DOCUMENTS:
        path = root / relative_path
        if not path.is_file():
            errors.append(f"{relative_path}: required ASD-STE100 document is missing")
            continue
        errors.extend(_validate_document(relative_path, path.read_text(encoding="utf-8")))
    return sorted(errors)


def _validate_document(path: Path, text: str) -> list[str]:
    errors: list[str] = []
    prose_lines = tuple(_prose_lines(text))
    prose = "\n".join(line for _, line, _ in prose_lines)
    if ";" in prose:
        errors.append(f"{path}: semicolons are not permitted")
    contraction = _CONTRACTION.search(prose)
    if contraction is not None:
        errors.append(f"{path}: contraction is not permitted: {contraction.group(0)}")
    for term, replacement in _DISALLOWED_TERMS.items():
        match = re.search(rf"(?<![\w-]){re.escape(term)}(?![\w-])", prose)
        if match is not None:
            errors.append(f"{path}: {term!r} is not permitted, {replacement}")
    for line_number, line, is_instruction in prose_lines:
        normalized = _normalize_markdown(line)
        if not normalized:
            continue
        max_words = _MAX_INSTRUCTION_WORDS if is_instruction else _MAX_DESCRIPTION_WORDS
        for sentence in _sentences(normalized):
            word_count = len(_WORD.findall(sentence))
            if word_count > max_words:
                errors.append(
                    f"{path}:{line_number}: sentence has {word_count} words, maximum is {max_words}"
                )
            for name, pattern in (
                ("passive voice", _PASSIVE),
                ("progressive verb", _PROGRESSIVE),
                ("perfect verb", _PERFECT),
            ):
                match = pattern.search(sentence)
                if match is not None:
                    errors.append(
                        f"{path}:{line_number}: {name} is not permitted: {match.group(0)}"
                    )
    errors.extend(_paragraph_errors(path, prose_lines))
    return errors


def _prose_lines(text: str) -> list[tuple[int, str, bool]]:
    lines: list[tuple[int, str, bool]] = []
    in_fence = False
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        if _FENCE.match(raw_line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        stripped = raw_line.strip()
        if not stripped or _HEADING.match(raw_line) or stripped.startswith("<!--"):
            lines.append((line_number, "", False))
            continue
        if stripped.startswith("|") and stripped.endswith("|"):
            continue
        is_instruction = _LIST_ITEM.match(raw_line) is not None
        line = _LIST_ITEM.sub("", raw_line).strip()
        lines.append((line_number, line, is_instruction))
    return lines


def _normalize_markdown(value: str) -> str:
    value = _LINK.sub(r"\1", value)
    value = _INLINE_CODE.sub("TECHNICAL_TERM", value)
    return value.replace("**", "").replace("__", "").strip()


def _sentences(value: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in _SENTENCE.split(value) if part.strip())


def _paragraph_errors(path: Path, lines: tuple[tuple[int, str, bool], ...]) -> list[str]:
    errors: list[str] = []
    paragraph: list[tuple[int, str]] = []
    for line_number, line, is_instruction in (*lines, (0, "", False)):
        if line and not is_instruction:
            paragraph.append((line_number, _normalize_markdown(line)))
            continue
        if paragraph:
            sentence_count = sum(len(_sentences(value)) for _, value in paragraph)
            if sentence_count > _MAX_PARAGRAPH_SENTENCES:
                errors.append(
                    f"{path}:{paragraph[0][0]}: paragraph has {sentence_count} sentences, "
                    f"maximum is {_MAX_PARAGRAPH_SENTENCES}"
                )
            paragraph.clear()
    return errors


def main() -> int:
    """Run the selected documentation checks."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    arguments = parser.parse_args()
    errors = validate_documents(arguments.root.resolve())
    if errors:
        for error in errors:
            print(error)
        return 1
    print(f"ASD-STE100 mechanical checks passed for {len(STE_DOCUMENTS)} documents.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
