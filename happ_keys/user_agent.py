"""Release constants of Happ's User-Agent, read from the DEX method that builds the header.

Happ sends `Happ/<versionName>/<os>/<stamp><versionCode><parity><suffix>`: `stamp` is a millisecond
timestamp baked in at build time, `parity` is `6` on even and `5` on odd UTC days of the month,
and `suffix` is a two-digit literal that differs between releases. R8 folds `stamp + versionCode`
into one string literal that seeds a `StringBuilder`, so the builder is found by its
`"Happ/<versionName>/"` literal rather than by its obfuscated class name.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from happ_keys.verifiers import CheckResult

if TYPE_CHECKING:
    from androguard.core.dex import DEX

_PREFIX_RE = re.compile(r"^Happ/(?P<version>[0-9][0-9A-Za-z.]*)/$")
_STAMP_DIGITS = 13
# `const/16 vN, 54` and `53`: the chars '6' and '5' appended for the day parity.
_PARITY_CHARS = {0x36, 0x35}


@dataclass(frozen=True)
class UserAgentRelease:
    version_name: str
    version_code: int
    build_stamp: str
    suffix: str


def _const_string(ins: Any) -> str | None:
    if not ins.get_name().startswith("const-string"):
        return None
    return ins.get_raw_string()


def _parse_builder(strings: list[str], literals: set[int], version_code: int) -> tuple[str, str] | None:
    code = str(version_code)
    for i, s in enumerate(strings):
        if not (s.isdigit() and s.endswith(code) and len(s) == _STAMP_DIGITS + len(code)):
            continue
        suffix = next((t for t in strings[i + 1 :] if t.isdigit()), None)
        if suffix is None or not _PARITY_CHARS.issubset(literals):
            return None
        return s[: -len(code)], suffix
    return None


def find_user_agent_release(dex_objects: list[DEX], version_name: str, version_code: int) -> UserAgentRelease:
    """Locate the User-Agent builder and return its build stamp and suffix for this APK."""
    found: list[UserAgentRelease] = []
    for dex in dex_objects:
        # Decoding every method is slow; only a DEX holding the literal can hold the builder.
        if not any(_PREFIX_RE.match(s) for s in dex.get_strings()):
            continue
        for method in dex.get_encoded_methods():
            code = method.get_code()
            if not code:
                continue
            instructions = list(code.get_bc().get_instructions())
            strings = [s for s in map(_const_string, instructions) if s is not None]
            prefix = next((m for m in map(_PREFIX_RE.match, strings) if m), None)
            if prefix is None:
                continue
            if prefix["version"] != version_name:
                raise ValueError(
                    f"User-Agent builder says Happ/{prefix['version']}/, manifest versionName is {version_name}"
                )
            literals = {
                ins.get_operands()[1][1]
                for ins in instructions
                if ins.get_name().startswith("const/") and len(ins.get_operands()) > 1
            }
            parsed = _parse_builder(strings, literals, version_code)
            if parsed is None:
                raise ValueError(
                    f"{method.get_class_name()}->{method.get_name()} builds Happ/{version_name}/ "
                    f"without a '<stamp>{version_code}' seed, parity chars and suffix"
                )
            found.append(UserAgentRelease(version_name, version_code, *parsed))
    if len(found) != 1:
        raise ValueError(f"expected one Happ/{version_name}/ User-Agent builder, found {len(found)}")
    return found[0]


def check_user_agent_builder(
    dex_objects: list[DEX], version_name: str, version_code: int
) -> tuple[UserAgentRelease | None, CheckResult]:
    """Run `find_user_agent_release` as a warning-only check, so a moved builder never blocks extraction."""
    description = "User-Agent builder yields the build stamp and suffix"
    try:
        release = find_user_agent_release(dex_objects, version_name, version_code)
    except ValueError as exc:
        return None, CheckResult(
            name="user_agent_builder", description=description, passed=False, is_warning=True, error=str(exc)
        )
    details = {"build_stamp": release.build_stamp, "suffix": release.suffix}
    return release, CheckResult(name="user_agent_builder", description=description, passed=True, details=details)
