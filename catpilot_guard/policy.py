"""The compiled company policy: what the company-rules hook reads instead of the YAML rules file.

`python tools/validate_overlay.py compile FILE --out POLICY` turns the `enforcement` section of a validated
version 2 rules file into this JSON (docs/spec/OVERLAY_V2.md §2.2). Hooks are standard library only and cannot
parse YAML, so they read this instead. The file holds, and only holds:

  format, format_version   "catpilot-company-policy", 1
  source_sha256            the SHA-256 of the rules file's bytes, written into evidence lines
  expires_on               the rules file's expiry date; after it the rules act in monitor (decision 3)
  rules                    each with id, kind, mode (resolved: the rule's own or default_mode), values, and
                           use_instead_text when the rule names an approved alternative
  exceptions               only when the rules file has expiring exceptions (OVERLAY_V2.md §3.1): each with id, rule
                           (the id of the rule it relaxes), allows (values of that rule's kind), expires_on (no later
                           than the policy's), and where ({repositories: [...]}) when it is limited to repositories

The format version stays 1 with exceptions: `exceptions` is an optional key, written only when the file has exceptions,
so a policy without them is unchanged. A hook from before exceptions refuses a policy that has the key, as it refuses any
unknown key, and applies no company rule (policy_error, malformed): install.sh installs the hook and the policy together.

Where it may come from (§2.2, §6.1 invariant 6): only an absolute path on the hook's own command line, never
the project, the home directory or an environment variable. The file must be a regular file, not a symlink, with
the same owner as the catpilot_guard package the hook runs from, and neither it nor its directory may be
writable by group or others. install.sh places both as root, so a person, and an agent acting as them, can
change neither. On Windows, where st_uid is always 0 and st_mode shows only the read-only attribute, the same rule is
read from the owner and the access list (docs/spec/WINDOWS.md §3.1): the file and its directory must be owned by
Administrators, SYSTEM or TrustedInstaller, no allow entry may give anyone else a right to write, append, delete or
change the access list or the owner, and neither may be a reparse point (a symbolic link or a junction). Anything else is a PolicyError with a fixed label, and the hook applies no company rule: the
built-in checks, which run as their own hooks, are unchanged (invariant 5: never less careful than no file).

Nothing here prints or returns a value from the policy in an error. Standard library only. Python 3.8+.
"""
from __future__ import annotations

import datetime as dt
import errno
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path

FORMAT = "catpilot-company-policy"
FORMAT_VERSION = 1
MODES = ("monitor", "ask", "block")
# The kinds a compiled policy may carry: those the validator accepts (tools/validate_overlay.py ACCEPTED_KINDS).
# ENFORCED_KINDS are the ones the company-rules hook acts on; a rule of another known kind is carried and skipped.
KINDS = ("protected_branch", "deploy_host", "package_registry", "cloud_account")
ENFORCED_KINDS = ("protected_branch", "deploy_host", "package_registry", "cloud_account")
RULES_MAX = 50
VALUES_MAX = 100
VALUE_MAX_CHARS = 255
USE_INSTEAD_MAX_CHARS = 200
MAX_POLICY_BYTES = 262_144

# Why a policy could not be used: the only values a policy_error line from the hook carries in `label`.
ERROR_LABELS = ("bad-arguments", "missing", "unreadable", "wrong-owner", "malformed", "internal-error")

RULE_ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
SHA256 = re.compile(r"[0-9a-f]{64}")
ISO_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
CONTROL = re.compile("[\x00-\x1f\x7f]")
TOP_KEYS = {"format", "format_version", "source_sha256", "expires_on", "rules"}
TOP_OPTIONAL = {"exceptions"}
RULE_KEYS = {"id", "kind", "mode", "values"}
RULE_OPTIONAL = {"use_instead_text"}
EXCEPTION_KEYS = {"id", "rule", "allows", "expires_on"}
EXCEPTION_OPTIONAL = {"where"}
EXCEPTIONS_MAX = 50
REPOSITORY_MAX_CHARS = 201  # owner/name, as tools/validate_overlay.py REPOSITORY_RE allows


class PolicyError(Exception):
    """The policy could not be used. Its one argument is a label from ERROR_LABELS, never content."""


@dataclass(frozen=True)
class Rule:
    id: str
    kind: str
    mode: str
    values: tuple
    use_instead_text: str | None


@dataclass(frozen=True)
class RuleException:
    """An expiring exception to one company rule (OVERLAY_V2.md §3.1). It never touches a built-in check."""

    id: str
    rule: str
    allows: tuple
    expires_on: dt.date
    repositories: tuple | None  # where.repositories; None when the exception is not limited to repositories

    def applies(self, today: dt.date, repository: str | None = None) -> bool:
        """Whether this exception relaxes its rule on `today`; the expiry day itself is current.

        An exception with `where` applies only to a repository it lists, ignoring case. The hooks pass no repository,
        so it never applies in a hook: a repository name read from a working tree is something the agent can change.
        This is the seam for the pull-request check, which passes none yet either; it will pass the repository its CI
        platform names."""
        if self.expires_on < today:
            return False
        if self.repositories is None:
            return True
        return repository is not None and repository.casefold() in {name.casefold() for name in self.repositories}


@dataclass(frozen=True)
class Policy:
    source_sha256: str
    expires_on: dt.date
    rules: tuple
    exceptions: tuple = ()

    def expired(self, today: dt.date | None = None) -> bool:
        """True after expires_on, by the machine's local date; the expiry day itself is current."""
        return self.expires_on < (today or dt.date.today())

    def active_exceptions(self, rule_id: str, today: dt.date | None = None) -> tuple:
        """The exceptions a hook applies to this rule today, in policy order: not expired, not limited by `where`. Empty
        once the policy itself has expired, though compile never writes an exception that outlives it."""
        today = today or dt.date.today()
        if self.expired(today):
            return ()
        return tuple(exception for exception in self.exceptions if exception.rule == rule_id and exception.applies(today))


def package_owner() -> int:
    """The owner of the catpilot_guard directory this module runs from: root for an install.sh install."""
    return os.stat(Path(__file__).resolve().parent).st_uid


def _writable_by_others(mode: int) -> bool:
    return bool(mode & (stat.S_IWGRP | stat.S_IWOTH))


def read_checked(path: Path, owner: int | None = None) -> bytes:
    """The policy file's bytes, read from the same open file whose type, owner and mode were checked.

    The final path component is opened without following a symlink, and the checks run on the open descriptor,
    so the file cannot be swapped between the check and the read. Its directory must also have the expected owner
    and be writable by no one else. Raises PolicyError for anything anyone but the package's owner could have changed.
    On Windows the owner and access list are read instead (read_checked_windows); `owner` does not apply there.
    """
    if not path.is_absolute():
        raise PolicyError("bad-arguments")
    if os.name == "nt":
        return read_checked_windows(path)
    try:
        expected = package_owner() if owner is None else owner
        parent = os.stat(path.parent)
    except FileNotFoundError:
        raise PolicyError("missing") from None
    except OSError:
        raise PolicyError("unreadable") from None
    if parent.st_uid != expected or _writable_by_others(parent.st_mode):
        raise PolicyError("wrong-owner")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        raise PolicyError("missing") from None
    except OSError as exc:
        # ELOOP: the final component is a symlink, which O_NOFOLLOW refuses.
        raise PolicyError("wrong-owner" if exc.errno == errno.ELOOP else "unreadable") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):  # a directory, a device, a FIFO
            raise PolicyError("wrong-owner")
        if info.st_uid != expected or _writable_by_others(info.st_mode):
            raise PolicyError("wrong-owner")
        chunks, size = [], 0
        while size <= MAX_POLICY_BYTES:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        return b"".join(chunks)
    except OSError:
        raise PolicyError("unreadable") from None
    finally:
        os.close(fd)


# --- Windows: the owner and the access list, read with ctypes (docs/spec/WINDOWS.md §3.1) -------------------------------
# Who may own the policy and its directory, and the only principals an allow entry may give a write right to.
TRUSTED_SIDS = frozenset((
    "S-1-5-32-544",  # BUILTIN\Administrators
    "S-1-5-18",  # NT AUTHORITY\SYSTEM
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",  # NT SERVICE\TrustedInstaller
))
# Rights that change the file, its directory's entries, its access list or its owner: FILE_WRITE_DATA (ADD_FILE),
# FILE_APPEND_DATA (ADD_SUBDIRECTORY), FILE_WRITE_EA, FILE_DELETE_CHILD, FILE_WRITE_ATTRIBUTES, DELETE, WRITE_DAC,
# WRITE_OWNER, GENERIC_ALL and GENERIC_WRITE.
WRITE_RIGHTS = 0x2 | 0x4 | 0x10 | 0x40 | 0x100 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000
ACCESS_ALLOWED_ACE_TYPES = (0, 9)  # ACCESS_ALLOWED_ACE, ACCESS_ALLOWED_CALLBACK_ACE: a mask, then the SID
ACCESS_DENIED_ACE_TYPES = (1, 6, 10, 12)  # ignored: a deny entry can only take rights away
INHERIT_ONLY_ACE = 0x08  # the entry applies to children created later, not to this object
FILE_ATTRIBUTE_REPARSE_POINT = 0x400


def acl_trusted(owner_sid: str | None, aces) -> bool:
    """Whether an owner SID and a DACL, as (ace type, ace flags, access mask, SID or None) entries, leave the object
    changeable only by TRUSTED_SIDS. aces None is a NULL DACL, which gives everyone every right. An allow entry of a
    type whose SID is not read (an object or compound entry, or a type not known here) fails when it carries a write
    right. Deny entries are ignored, which can only make the check stricter."""
    if owner_sid not in TRUSTED_SIDS or aces is None:
        return False
    for ace_type, flags, mask, sid in aces:
        if ace_type in ACCESS_DENIED_ACE_TYPES or flags & INHERIT_ONLY_ACE or not mask & WRITE_RIGHTS:
            continue
        if ace_type not in ACCESS_ALLOWED_ACE_TYPES or sid not in TRUSTED_SIDS:
            return False
    return True


def _windows_security(handle: int | None = None, name: str | None = None) -> tuple:
    """(owner SID string, DACL entries or None) of an open handle or a named file, through advapi32. Raises OSError."""
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    pointer = ctypes.POINTER(ctypes.c_void_p)
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    advapi32.IsValidSid.argtypes = [ctypes.c_void_p]
    advapi32.IsValidSid.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    advapi32.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, pointer]
    advapi32.GetAce.restype = wintypes.BOOL
    owner, dacl, descriptor = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
    wanted = 0x1 | 0x4  # OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION; SE_FILE_OBJECT is 1
    if handle is not None:
        call = advapi32.GetSecurityInfo
        call.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.DWORD, pointer, pointer, pointer, pointer, pointer]
        call.restype = wintypes.DWORD
        status = call(handle, 1, wanted, ctypes.byref(owner), None, ctypes.byref(dacl), None, ctypes.byref(descriptor))
    else:
        call = advapi32.GetNamedSecurityInfoW
        call.argtypes = [wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD, pointer, pointer, pointer, pointer, pointer]
        call.restype = wintypes.DWORD
        status = call(name, 1, wanted, ctypes.byref(owner), None, ctypes.byref(dacl), None, ctypes.byref(descriptor))
    if status != 0:  # a Win32 error code
        raise OSError(status, "security information unavailable")

    def sid_string(address) -> str | None:
        if not address or not advapi32.IsValidSid(address):
            return None
        text = ctypes.c_void_p()
        if not advapi32.ConvertSidToStringSidW(address, ctypes.byref(text)):
            raise OSError(ctypes.get_last_error(), "SID conversion failed")
        try:
            return ctypes.wstring_at(text.value)
        finally:
            kernel32.LocalFree(text)

    class AclHeader(ctypes.Structure):
        _fields_ = [("revision", ctypes.c_ubyte), ("sbz1", ctypes.c_ubyte), ("size", ctypes.c_ushort),
                    ("count", ctypes.c_ushort), ("sbz2", ctypes.c_ushort)]

    class AceHeader(ctypes.Structure):
        _fields_ = [("type", ctypes.c_ubyte), ("flags", ctypes.c_ubyte), ("size", ctypes.c_ushort)]

    try:
        owner_sid = sid_string(owner.value)
        if not dacl.value:
            return owner_sid, None  # a NULL DACL
        aces = []
        for index in range(ctypes.cast(dacl, ctypes.POINTER(AclHeader)).contents.count):
            ace = ctypes.c_void_p()
            if not advapi32.GetAce(dacl, index, ctypes.byref(ace)):
                raise OSError(ctypes.get_last_error(), "access list unreadable")
            header = ctypes.cast(ace, ctypes.POINTER(AceHeader)).contents
            mask = ctypes.cast(ace.value + 4, ctypes.POINTER(wintypes.DWORD)).contents.value
            # ACCESS_ALLOWED_ACE and its callback form: the header, the mask, then the SID at offset 8.
            sid = sid_string(ace.value + 8) if header.type in ACCESS_ALLOWED_ACE_TYPES else None
            aces.append((header.type, header.flags, mask, sid))
        return owner_sid, aces
    finally:
        kernel32.LocalFree(descriptor)


def _reparse_point(info: os.stat_result) -> bool:
    return bool(getattr(info, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT) or stat.S_ISLNK(info.st_mode)


def read_checked_windows(path: Path) -> bytes:
    """read_checked on Windows: the directory and then the open file must be owned by a trusted SID, writable by no
    one else (acl_trusted), and not reparse points. The file is opened first, then its open handle's identity (volume
    serial and file index, from os.fstat) is compared with the path's own (os.lstat, which does not follow a link), and
    the access list is read from the open handle, so the file cannot be swapped between the check and the read."""
    try:
        parent = os.lstat(path.parent)
    except FileNotFoundError:
        raise PolicyError("missing") from None
    except OSError:
        raise PolicyError("unreadable") from None
    if _reparse_point(parent) or not stat.S_ISDIR(parent.st_mode):
        raise PolicyError("wrong-owner")
    try:
        trusted = acl_trusted(*_windows_security(name=str(path.parent)))
    except OSError:
        raise PolicyError("unreadable") from None
    if not trusted:
        raise PolicyError("wrong-owner")
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
    except FileNotFoundError:
        raise PolicyError("missing") from None
    except OSError:
        raise PolicyError("unreadable") from None
    try:
        import msvcrt

        info, named = os.fstat(fd), os.lstat(path)
        if _reparse_point(named) or not stat.S_ISREG(info.st_mode) or not stat.S_ISREG(named.st_mode):
            raise PolicyError("wrong-owner")
        if not info.st_ino or (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino):
            raise PolicyError("wrong-owner")
        if not acl_trusted(*_windows_security(handle=msvcrt.get_osfhandle(fd))):
            raise PolicyError("wrong-owner")
        chunks, size = [], 0
        while size <= MAX_POLICY_BYTES:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        return b"".join(chunks)
    except OSError:
        raise PolicyError("unreadable") from None
    finally:
        os.close(fd)


def _string(value: object, longest: int) -> str:
    if not isinstance(value, str) or not value or len(value) > longest or CONTROL.search(value):
        raise PolicyError("malformed")
    return value


def _rule(value: object, seen: set) -> Rule:
    if not isinstance(value, dict):
        raise PolicyError("malformed")
    keys = set(value)
    if not RULE_KEYS <= keys or keys - RULE_KEYS - RULE_OPTIONAL:
        raise PolicyError("malformed")
    rule_id = value["id"]
    if not isinstance(rule_id, str) or len(rule_id) > 64 or not RULE_ID.fullmatch(rule_id) or rule_id in seen:
        raise PolicyError("malformed")
    seen.add(rule_id)
    if value["kind"] not in KINDS or value["mode"] not in MODES:
        raise PolicyError("malformed")
    values = value["values"]
    if not isinstance(values, list) or not 1 <= len(values) <= VALUES_MAX:
        raise PolicyError("malformed")
    use_instead = value.get("use_instead_text")
    return Rule(
        id=rule_id,
        kind=value["kind"],
        mode=value["mode"],
        values=tuple(_string(v, VALUE_MAX_CHARS) for v in values),
        use_instead_text=None if use_instead is None else _string(use_instead, USE_INSTEAD_MAX_CHARS),
    )


def _date(value: object) -> dt.date:
    if not isinstance(value, str) or not ISO_DATE.fullmatch(value):
        raise PolicyError("malformed")
    try:
        return dt.date.fromisoformat(value)
    except ValueError:
        raise PolicyError("malformed") from None


def _list(value: object, longest_item: int, most: int) -> tuple:
    if not isinstance(value, list) or not 1 <= len(value) <= most:
        raise PolicyError("malformed")
    return tuple(_string(item, longest_item) for item in value)


def _exception(value: object, rule_ids: set, seen: set, policy_expires: dt.date) -> RuleException:
    if not isinstance(value, dict):
        raise PolicyError("malformed")
    keys = set(value)
    if not EXCEPTION_KEYS <= keys or keys - EXCEPTION_KEYS - EXCEPTION_OPTIONAL:
        raise PolicyError("malformed")
    exception_id = value["id"]
    if not isinstance(exception_id, str) or len(exception_id) > 64 or not RULE_ID.fullmatch(exception_id) or exception_id in seen:
        raise PolicyError("malformed")
    seen.add(exception_id)
    rule = value["rule"]
    if not isinstance(rule, str) or rule not in rule_ids:
        raise PolicyError("malformed")
    expires_on = _date(value["expires_on"])
    if expires_on > policy_expires:  # an exception never outlives the file
        raise PolicyError("malformed")
    repositories = None
    if "where" in value:
        where = value["where"]
        if not isinstance(where, dict) or set(where) != {"repositories"}:
            raise PolicyError("malformed")
        repositories = _list(where["repositories"], REPOSITORY_MAX_CHARS, VALUES_MAX)
    return RuleException(id=exception_id, rule=rule, allows=_list(value["allows"], VALUE_MAX_CHARS, VALUES_MAX),
                         expires_on=expires_on, repositories=repositories)


def parse(raw: bytes) -> Policy:
    """A policy from its bytes. Raises PolicyError("malformed") for anything but the format compile writes."""
    if len(raw) > MAX_POLICY_BYTES:
        raise PolicyError("malformed")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise PolicyError("malformed") from None
    if not isinstance(data, dict) or not TOP_KEYS <= set(data) or set(data) - TOP_KEYS - TOP_OPTIONAL:
        raise PolicyError("malformed")
    if data["format"] != FORMAT or data["format_version"] != FORMAT_VERSION or isinstance(data["format_version"], bool):
        raise PolicyError("malformed")
    sha = data["source_sha256"]
    if not isinstance(sha, str) or not SHA256.fullmatch(sha):
        raise PolicyError("malformed")
    expires_on = _date(data["expires_on"])
    rules = data["rules"]
    if not isinstance(rules, list) or not 1 <= len(rules) <= RULES_MAX:
        raise PolicyError("malformed")
    seen: set = set()
    parsed = tuple(_rule(rule, seen) for rule in rules)
    exceptions = ()
    if "exceptions" in data:
        listed = data["exceptions"]
        if not isinstance(listed, list) or not 1 <= len(listed) <= EXCEPTIONS_MAX:
            raise PolicyError("malformed")
        rule_ids = {rule.id for rule in parsed}
        # Exception ids share one namespace with rule ids (OVERLAY_V2.md §6.3 rule 3).
        exceptions = tuple(_exception(entry, rule_ids, seen, expires_on) for entry in listed)
    return Policy(source_sha256=sha, expires_on=expires_on, rules=parsed, exceptions=exceptions)


def load(path: str | Path, owner: int | None = None) -> Policy:
    """The policy at path, after the location checks. Raises PolicyError with a label from ERROR_LABELS."""
    return parse(read_checked(Path(path), owner))


def branch_matches(value: str, branch: str) -> bool:
    """Whether a protected_branch value covers a branch name, ignoring case as the built-in check does.

    A trailing `/*` covers every branch under the prefix (`release/*` covers `release/2026.11` and
    `release/a/b`), as the built-in `release/*` does; anything else must match the whole name.
    """
    if not branch:
        return False
    if value.startswith("refs/heads/"):  # the validator refuses this form; a push destination is read without it
        value = value[len("refs/heads/"):]
    if value.endswith("/*"):
        prefix = value[:-1].casefold()
        name = branch.casefold()
        return name.startswith(prefix) and len(name) > len(prefix)
    return value.casefold() == branch.casefold()
