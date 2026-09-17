# LDAP Blind Injection Extractor

A Python tool implementing boolean-based blind LDAP injection to enumerate directory entries and exfiltrate attribute values through a true/false HTTP oracle.

Built while working through the LDAP Injection module of the CWEE Injection Attacks path (HTB Academy).

## How it works

LDAP has no `substring()`/`name()`/`count()` functions like XPath, so extraction relies on the wildcard `*` operator instead:

```
(&(uid=htb-stdnt)(password=a*))     -> true if password starts with 'a'
(&(uid=htb-stdnt)(password=p@*))    -> true if password starts with 'p@'
```

Growing that prefix one character at a time recovers the whole value. To turn *any* attribute on *any* entry into an oracle — not just your own login — the username field is used to inject an OR-clause:

```
username: htb-stdnt)(|(description=a*
password: invalid)

-> (&(uid=htb-stdnt)(|(description=a*)(password=invalid)))
```

Since the real password is wrong, the OR's truth depends entirely on whether `description` starts with `a` — the same trick as the password itself, generalized to any field.

**Attribute existence** is schema-driven in LDAP (unlike XPath's arbitrary app-defined trees), so there's no structural walk to lean on — it's dictionary-based: `(attr=*)` returns true only if the entry has that attribute at all, tested against a wordlist.

**User enumeration** reuses the same OR trick with a wildcard base (`uid=*`) to search the whole directory instead of one known entry, chaining `(!(uid=<found>))` exclusions after each hit so the next round finds a different entry.

## Usage

Everything target-specific — building the HTTP request and deciding true/false — lives in the `Oracle` class. Extraction logic (`LDAPBlindExtractor`) sits on top of it.

**Discover which attributes exist on an entry:**
```bash
python ldap_blind_extractor.py "http://target/index.php" --uid htb-stdnt --true-marker "Login successful" --discover
```

**Enumerate all users directory-wide:**
```bash
python ldap_blind_extractor.py "http://target/index.php" --uid '*' --true-marker "Login successful" --discover-users
```

**Extract attribute values once you know they exist:**
```bash
python ldap_blind_extractor.py "http://target/index.php" --uid htb-stdnt --true-marker "Login successful" --attr description --attr userPassword
```

### Key options

| Flag | Description |
|---|---|
| `--uid` | Known username to target, or `'*'` for a directory-wide search |
| `--username-param` / `--password-param` | Form field names (default `username`/`password`) |
| `--password-closer` | Value sent in the password field to close the injected filter (default `invalid)`) |
| `--true-marker` | Substring present in the response only on a true predicate |
| `--timing` | Use response-time delta instead of content matching |
| `--discover` | Dictionary-based attribute discovery (`--wordlist` for a custom list) |
| `--discover-users` | Enumerate distinct usernames directory-wide (`--max-users` caps the loop) |
| `--attr` | Attribute(s) to extract the value of (repeatable) |
| `--charset` | Character set tried during string extraction — widen it (e.g. add `{}` `/` `:`) if extraction stalls early |

### Notes from the field

- **Case-insensitive matching**: most LDAP attributes match case-insensitively, so a hit on a character confirms *some* case variant matches, not the exact original casing.
- **Not every attribute supports substring matching**: `objectClass` (OID-based equality) and DN-syntax attributes like `creatorsName`/`modifiersName` often have no `SUBSTR` matching rule at all — wildcard extraction against them will silently fail regardless of charset. Free-text attributes (`description`, `cn`) are the reliable targets.
- **`userPassword` may be ACL-protected**: existence checks (`attr=*`) can succeed while equality/substring comparison against it is denied — an empty extraction result doesn't necessarily mean an empty password.
- If your target's injectable context differs from the default `(&(uid=%s)(password=%s))` template, adjust `Oracle.build_payloads()`.

## Disclaimer

For authorized security testing, CTF challenges, and educational use only (labs, your own applications, or engagements you have written permission for).
