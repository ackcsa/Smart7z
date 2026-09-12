"""Archive input discovery and deterministic multi-volume grouping."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

from archive_classifier import has_independent_archive_structure
from models import ArchiveSet

MAX_VOLUME_INDEX = 100_000

_NUMERIC_RE = re.compile(r"^(?P<base>.*\.)(?P<index>\d{3,})$", re.IGNORECASE)
_PART_RAR_RE = re.compile(
    r"^(?P<base>.*\.part)(?P<index>\d+)(?P<suffix>\.rar)$", re.IGNORECASE
)
_CLASSIC_R_RE = re.compile(
    r"^(?P<base>.*)\.(?P<letter>[r-z])(?P<index>\d{2})$",
    re.IGNORECASE,
)
_ZIP_Z_RE = re.compile(r"^(?P<base>.*)\.z(?P<index>\d{2,})$", re.IGNORECASE)
_ARJ_A_RE = re.compile(r"^(?P<base>.*)\.a(?P<index>\d{2,})$", re.IGNORECASE)
_SWM_RE = re.compile(
    r"^(?P<base>.*?)(?P<index>(?:[2-9]|\d{2,}))?\.swm$",
    re.IGNORECASE,
)


def _canonical(path: str) -> str:
    return os.path.normcase(os.path.realpath(os.path.abspath(path)))


def logical_archive_key(path: str) -> str:
    """Return a canonical logical-set key, disambiguating independent .NNN files."""
    absolute = os.path.abspath(os.path.normpath(path))
    directory = os.path.dirname(absolute)
    name = os.path.basename(absolute)
    if _named_volume_is_independent(absolute):
        return _canonical(absolute)
    match = _PART_RAR_RE.match(name)
    if match and _volume_index(match.group("index"), minimum=1) is not None:
        width = len(match.group("index"))
        name = f"{match.group('base')}{1:0{width}d}{match.group('suffix')}"
    else:
        match = _NUMERIC_RE.match(name)
        if match and _volume_index(match.group("index"), minimum=1) is not None:
            width = len(match.group("index"))
            name = f"{match.group('base')}{1:0{width}d}"
        else:
            match = _CLASSIC_R_RE.match(name)
            if match:
                # A continuation name only folds onto a shared key when the
                # set actually has a main volume.  Packages that merely look
                # like continuations keep their own identity instead of being
                # deduplicated against an unrelated sibling.
                if match.group("letter").casefold() == "z":
                    # ``.zNN`` continues a split-ZIP set, not a classic RAR
                    # set; folding it onto ``.rar`` would merge unrelated
                    # packages.
                    if not _zip_split_has_main_volume(directory, match):
                        return _canonical(absolute)
                    name = match.group("base") + ".zip"
                else:
                    if not _classic_rar_has_main_volume(directory, match):
                        return _canonical(absolute)
                    name = match.group("base") + ".rar"
            else:
                match = _ZIP_Z_RE.match(name)
                if match and _volume_index(match.group("index"), minimum=1) is not None:
                    # Only fold onto the shared ".zip" key when that main
                    # volume exists.  Otherwise the file is its own package
                    # and must not be deduplicated away.
                    if not _zip_split_has_main_volume(directory, match):
                        return _canonical(absolute)
                    name = match.group("base") + ".zip"
                else:
                    match = _ARJ_A_RE.match(name)
                    if match and _volume_index(match.group("index"), minimum=1) is not None:
                        name = match.group("base") + ".arj"
                    else:
                        match = _SWM_RE.match(name)
                        if (
                            match
                            and match.group("index")
                            and _volume_index(match.group("index"), minimum=2)
                            is not None
                        ):
                            candidate = match.group("base") + ".swm"
                            if os.path.exists(os.path.join(directory, candidate)):
                                name = candidate
    return _canonical(os.path.join(directory, name))


def _directory_index(directory: str) -> Dict[str, str]:
    try:
        return {name.casefold(): name for name in os.listdir(directory)}
    except OSError:
        return {}


def _actual_path(directory: str, name: str, index: Dict[str, str]) -> str:
    actual = index.get(name.casefold(), name)
    return os.path.join(directory, actual)


def is_multipart_child(path: str) -> bool:
    name = os.path.basename(path)
    directory = os.path.dirname(os.path.abspath(path))
    if _named_volume_is_independent(path):
        return False
    match = _PART_RAR_RE.match(name)
    part_index = (
        _volume_index(match.group("index"), minimum=1) if match else None
    )
    if match and part_index is not None:
        if part_index == 1:
            return False
        selected_exists = os.path.exists(path)
        if selected_exists:
            width = len(match.group("index"))
            main = f"{match.group('base')}{1:0{width}d}{match.group('suffix')}"
            return os.path.exists(os.path.join(directory, main))
        return True
    match = _NUMERIC_RE.match(name)
    numeric_index = (
        _volume_index(match.group("index"), minimum=1) if match else None
    )
    if match and numeric_index is not None:
        if numeric_index == 1:
            return False
        selected_exists = os.path.exists(path)
        if selected_exists:
            width = len(match.group("index"))
            main = f"{match.group('base')}{1:0{width}d}"
            return os.path.exists(os.path.join(directory, main))
        return True
    match = _CLASSIC_R_RE.match(name)
    if match:
        if match.group("letter").casefold() == "z":
            # ``.zNN`` is the ZIP split set (its main volume is ``.zip``).
            # A ``.zNN`` file that is itself a complete archive is a package
            # in its own right, exactly as detect_archive_set() decides.
            if has_independent_archive_structure(path):
                return False
            return _zip_split_has_main_volume(directory, match)
        # Same reasoning for ``.rNN``: a companion ``.rNN`` that carries a
        # complete archive is its own package even when a ``.rar`` exists.
        if _classic_or_zip_child_is_standalone(path):
            return False
        if not _classic_rar_has_main_volume(directory, match):
            return False
        main = os.path.join(directory, match.group("base") + ".rar")
        if os.path.exists(main):
            return True
        selected_exists = os.path.exists(path)
        if selected_exists:
            first = os.path.join(directory, match.group("base") + ".r00")
            return os.path.exists(first) and _classic_rar_index(match) != 0
        return True
    match = _ZIP_Z_RE.match(name)
    if (
        match
        and _volume_index(match.group("index"), minimum=1) is not None
    ):
        return _zip_split_has_main_volume(directory, match)
    match = _ARJ_A_RE.match(name)
    arj_index = (
        _volume_index(match.group("index"), minimum=1) if match else None
    )
    if match and arj_index is not None:
        selected_exists = os.path.exists(path)
        main = os.path.join(directory, match.group("base") + ".arj")
        if os.path.exists(main):
            return True
        if selected_exists:
            first = os.path.join(directory, match.group("base") + ".a01")
            return os.path.exists(first) and arj_index != 1
        return True
    match = _SWM_RE.match(name)
    if (
        match
        and match.group("index")
        and _volume_index(match.group("index"), minimum=2) is not None
    ):
        main = os.path.join(directory, match.group("base") + ".swm")
        return os.path.exists(main)
    return False


def detect_archive_set(path: str) -> ArchiveSet:
    """Group by name only when the selected file is not self-contained."""

    archive_set = _detect_archive_set_by_name(path)
    absolute = os.path.abspath(os.path.normpath(path))
    if archive_set.format_family != "standalone":
        if has_independent_archive_structure(absolute):
            return _standalone_set(absolute)
        if (
            _canonical(archive_set.main_path) != _canonical(absolute)
            and has_independent_archive_structure(archive_set.main_path)
        ):
            return _standalone_set(absolute)
    return archive_set


def _detect_archive_set_by_name(path: str) -> ArchiveSet:
    path = os.path.abspath(os.path.normpath(path))
    directory = os.path.dirname(path)
    name = os.path.basename(path)
    names = _directory_index(directory)

    if _numeric_child_is_standalone(path):
        return _standalone_set(path)

    match = _PART_RAR_RE.match(name)
    if match and _volume_index(match.group("index"), minimum=1) is not None:
        return _part_rar_set(directory, match, names)
    match = _NUMERIC_RE.match(name)
    if match and _volume_index(match.group("index"), minimum=1) is not None:
        return _numeric_set(directory, match, names)
    match = _CLASSIC_R_RE.match(name)
    if match:
        if not _classic_rar_has_main_volume(directory, match):
            return _standalone_set(path)
        if match.group("letter").casefold() == "z":
            return _zip_split_set(directory, match.group("base"), names)
        return _classic_rar_set(directory, match.group("base"), names)
    match = _ZIP_Z_RE.match(name)
    if (
        match
        and _volume_index(match.group("index"), minimum=1) is not None
    ):
        if not _zip_split_has_main_volume(directory, match):
            return _standalone_set(path)
        return _zip_split_set(directory, match.group("base"), names)
    match = _ARJ_A_RE.match(name)
    if (
        match
        and _volume_index(match.group("index"), minimum=1) is not None
    ):
        return _arj_set(directory, match.group("base"), names)
    match = _SWM_RE.match(name)
    if match:
        if match.group("index") and _volume_index(
            match.group("index"), minimum=2
        ) is None:
            match = None
    if match:
        base = match.group("base")
        if match.group("index") and not os.path.exists(
            os.path.join(directory, base + ".swm")
        ):
            base = name[:-4]
        return _swm_set(directory, base, names)
    lower = name.casefold()
    if lower.endswith(".rar"):
        return _classic_rar_set(directory, name[:-4], names)
    if lower.endswith(".zip"):
        return _zip_split_set(directory, name[:-4], names)
    if lower.endswith(".arj"):
        return _arj_set(directory, name[:-4], names)
    if lower.endswith(".swm"):
        return _swm_set(directory, name[:-4], names)
    return _standalone_set(path)


def _standalone_set(path: str) -> ArchiveSet:
    return ArchiveSet(
        main_path=path,
        volumes=[path],
        format_family="standalone",
        missing_indexes=[],
        is_complete=True,
    )


def _numeric_child_is_standalone(path: str) -> bool:
    name = os.path.basename(path)
    match = _NUMERIC_RE.match(name)
    index = _volume_index(match.group("index"), minimum=1) if match else None
    return bool(
        index is not None
        and index > 1
        and has_independent_archive_structure(path)
    )


def _named_volume_is_independent(path: str) -> bool:
    name = os.path.basename(path)
    if any(pattern.match(name) for pattern in (
        _NUMERIC_RE, _PART_RAR_RE, _CLASSIC_R_RE, _ZIP_Z_RE, _ARJ_A_RE, _SWM_RE
    )):
        if has_independent_archive_structure(path):
            return True
    match = _CLASSIC_R_RE.match(name) or _ZIP_Z_RE.match(name)
    if match:
        suffix = ".zip" if name.casefold().rsplit(".", 1)[-1].startswith("z") else ".rar"
        main = os.path.join(os.path.dirname(path), match.group("base") + suffix)
        return has_independent_archive_structure(main)
    return False


def _classic_or_zip_child_is_standalone(path: str) -> bool:
    """Return whether a ``.rNN``/``.zNN``-looking file is a complete package.

    Such a name normally identifies a volume of a multi-volume set, but the
    same name may carry a self-contained archive.  When it does, the file is
    the package and must keep its own identity rather than being folded into
    a sibling set (which would silently drop it as a duplicate).
    """

    name = os.path.basename(path)
    match = _CLASSIC_R_RE.match(name)
    if not match:
        return False
    index = _classic_rar_index(match)
    return index > 0 and has_independent_archive_structure(path)


def _indexed_members(
    directory: str,
    pattern: re.Pattern,
    expected_base: str,
    expected_suffix: str = "",
    minimum_index: int = 0,
) -> Dict[int, str]:
    members: Dict[int, str] = {}
    try:
        entries = os.listdir(directory)
    except OSError:
        return members
    for entry in entries:
        match = pattern.match(entry)
        if not match:
            continue
        if match.group("base").casefold() != expected_base.casefold():
            continue
        if expected_suffix and match.groupdict().get("suffix", "").casefold() != expected_suffix.casefold():
            continue
        index = _volume_index(match.group("index"), minimum=minimum_index)
        if index is None:
            continue
        members[index] = os.path.join(directory, entry)
    return members


def _missing_between(members: Dict[int, str], first: int) -> List[int]:
    if not members:
        return [first]
    highest = max(members)
    return [index for index in range(first, highest + 1) if index not in members]


def _numeric_set(
    directory: str, match: re.Match, names: Dict[str, str]
) -> ArchiveSet:
    base = match.group("base")
    width = len(match.group("index"))
    # Require one consistent numeric width; this avoids grouping unrelated
    # archive.001 and archive.0001 files.
    pattern = re.compile(
        rf"^(?P<base>{re.escape(base)})(?P<index>\d{{{width}}})$", re.IGNORECASE
    )
    members = _indexed_members(directory, pattern, base, minimum_index=1)
    main_name = f"{base}{1:0{width}d}"
    main_path = members.get(1, _actual_path(directory, main_name, names))
    missing = _missing_between(members, 1)
    volumes = [members[index] for index in sorted(members)]
    if not volumes:
        volumes = [main_path]
    return ArchiveSet(
        main_path=main_path,
        volumes=volumes,
        format_family="numeric_split",
        missing_indexes=missing,
        is_complete=not missing,
    )


def _part_rar_set(
    directory: str, match: re.Match, names: Dict[str, str]
) -> ArchiveSet:
    base = match.group("base")
    suffix = match.group("suffix")
    width = len(match.group("index"))
    pattern = re.compile(
        rf"^(?P<base>{re.escape(base)})(?P<index>\d{{{width}}})(?P<suffix>{re.escape(suffix)})$",
        re.IGNORECASE,
    )
    members = _indexed_members(
        directory,
        pattern,
        base,
        suffix,
        minimum_index=1,
    )
    main_name = f"{base}{1:0{width}d}{suffix}"
    main_path = members.get(1, _actual_path(directory, main_name, names))
    missing = _missing_between(members, 1)
    volumes = [members[index] for index in sorted(members)] or [main_path]
    return ArchiveSet(
        main_path=main_path,
        volumes=volumes,
        format_family="part_rar",
        missing_indexes=missing,
        is_complete=not missing,
    )


def _classic_rar_set(
    directory: str, base: str, names: Dict[str, str]
) -> ArchiveSet:
    main_path = _actual_path(directory, base + ".rar", names)
    pattern = re.compile(
        rf"^(?P<base>{re.escape(base)})\.(?P<letter>[r-z])(?P<index>\d{{2}})$",
        re.IGNORECASE,
    )
    members: Dict[int, str] = {}
    try:
        entries = os.listdir(directory)
    except OSError:
        entries = []
    for entry in entries:
        match = pattern.match(entry)
        if match:
            members[_classic_rar_index(match)] = os.path.join(directory, entry)
    volumes: List[str] = []
    missing: List[int] = []
    if os.path.isfile(main_path):
        volumes.append(main_path)
    else:
        missing.append(0)
    if members:
        missing.extend(index + 1 for index in _missing_between(members, 0))
        volumes.extend(members[index] for index in sorted(members))
    if not volumes:
        # A selected non-existing main is still represented deterministically.
        volumes = [main_path]
    return ArchiveSet(
        main_path=main_path if os.path.isfile(main_path) else volumes[0],
        volumes=volumes,
        format_family="classic_rar",
        missing_indexes=sorted(set(missing)),
        is_complete=not missing,
    )


def _zip_split_set(
    directory: str, base: str, names: Dict[str, str]
) -> ArchiveSet:
    main_path = _actual_path(directory, base + ".zip", names)
    pattern = re.compile(
        rf"^(?P<base>{re.escape(base)})\.z(?P<index>\d{{2,}})$", re.IGNORECASE
    )
    members = _indexed_members(directory, pattern, base, minimum_index=1)
    missing = _missing_between(members, 1) if members else []
    volumes = [members[index] for index in sorted(members)]
    if os.path.isfile(main_path):
        volumes.append(main_path)
    elif members:
        # The terminal .zip volume is mandatory for split ZIP sets.
        missing.append(max(members) + 1)
    else:
        volumes = [main_path]
    return ArchiveSet(
        main_path=main_path if os.path.isfile(main_path) else volumes[0],
        volumes=volumes,
        format_family="zip_split",
        missing_indexes=sorted(set(missing)),
        is_complete=not missing,
    )


def _arj_set(directory: str, base: str, names: Dict[str, str]) -> ArchiveSet:
    main_path = _actual_path(directory, base + ".arj", names)
    pattern = re.compile(
        rf"^(?P<base>{re.escape(base)})\.a(?P<index>\d{{2,}})$",
        re.IGNORECASE,
    )
    members = _indexed_members(directory, pattern, base, minimum_index=1)
    volumes: List[str] = []
    missing: List[int] = []
    if os.path.isfile(main_path):
        volumes.append(main_path)
    else:
        missing.append(0)
    if members:
        missing.extend(_missing_between(members, 1))
        volumes.extend(members[index] for index in sorted(members))
    if not volumes:
        volumes = [main_path]
    return ArchiveSet(
        main_path=main_path if os.path.isfile(main_path) else volumes[0],
        volumes=volumes,
        format_family="arj_split",
        missing_indexes=sorted(set(missing)),
        is_complete=not missing,
    )


def _swm_set(directory: str, base: str, names: Dict[str, str]) -> ArchiveSet:
    main_path = _actual_path(directory, base + ".swm", names)
    pattern = re.compile(
        rf"^(?P<base>{re.escape(base)})(?P<index>(?:[2-9]|\d{{2,}}))\.swm$",
        re.IGNORECASE,
    )
    later_members = _indexed_members(
        directory,
        pattern,
        base,
        minimum_index=2,
    )
    members: Dict[int, str] = {}
    if os.path.isfile(main_path):
        members[1] = main_path
    members.update(later_members)
    missing = _missing_between(members, 1)
    volumes = [members[index] for index in sorted(members)] or [main_path]
    return ArchiveSet(
        main_path=main_path if os.path.isfile(main_path) else volumes[0],
        volumes=volumes,
        format_family="wim_split",
        missing_indexes=missing,
        is_complete=not missing,
    )


def _classic_rar_index(match: re.Match) -> int:
    letter_offset = ord(match.group("letter").casefold()) - ord("r")
    return (letter_offset * 100) + int(match.group("index"))


def _volume_index(raw: str, minimum: int = 0) -> Optional[int]:
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return None
    if value < minimum or value > MAX_VOLUME_INDEX:
        return None
    return value


def _zip_split_has_main_volume(directory: str, match: re.Match) -> bool:
    """Return whether a split-ZIP main volume is present for *match*.

    A ``.zNN`` file belongs to the split-ZIP set of the same base name only
    when that set's terminal ``.zip`` volume exists.  Without it the file is a
    package in its own right and must not be merged into (or deduplicated
    against) anything else.
    """

    base = match.group("base")
    zip_main = os.path.join(directory, base + ".zip")
    if os.path.exists(zip_main):
        return True
    # A ``.zNN`` continuation can also belong to a .rar set when that main
    # volume exists and no .zip volume does.
    rar_main = os.path.join(directory, base + ".rar")
    return os.path.exists(rar_main) and not os.path.exists(zip_main)


def _classic_rar_has_main_volume(directory: str, match: re.Match) -> bool:
    """Return whether a classic .rar/.rNN set exists for *match*.

    ``.rNN``/``.zNN`` names only identify a volume of a set; without the main
    ``.rar`` volume (or, for ZIP sets, the terminal ``.zip`` volume) the file
    is an independent package.
    """

    base = match.group("base")
    if os.path.exists(os.path.join(directory, base + ".rar")):
        return True
    if match.group("letter").casefold() == "z":
        return os.path.exists(os.path.join(directory, base + ".zip"))
    return False


def group_into_sets(paths: Iterable[str]) -> Tuple[List[ArchiveSet], List[str]]:
    seen_sets: Set[str] = set()
    archive_sets: List[ArchiveSet] = []
    standalone: List[str] = []
    for path in paths:
        archive_set = detect_archive_set(path)
        key = _canonical(archive_set.main_path)
        if key in seen_sets:
            continue
        seen_sets.add(key)
        if archive_set.format_family == "standalone":
            standalone.append(path)
        else:
            archive_sets.append(archive_set)
    return archive_sets, standalone


def get_archive_volumes(path: str) -> List[str]:
    return detect_archive_set(path).volumes
