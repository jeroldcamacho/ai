---
name: sharp-edges-and-insecure-defaults
description: Find footgun APIs and fail-open defaults — designs where the easy path is the insecure one. Use when reviewing an API or configuration schema for misuse resistance, when a security control has an off switch or an undefined zero value, or when auditing for default credentials, fallback secrets, debug features and weak-crypto defaults.
---

# SKILL: Sharp Edges & Insecure Defaults

Some vulnerabilities are not in the code — they are in the shape of the interface the code
exposes, or in the value a setting takes when nobody sets it. This skill finds those.

**The pit of success:** secure usage should be the path of least resistance. If a developer must
understand cryptography, read documentation carefully, or remember a special rule to avoid a
vulnerability, the API has failed — and the finding belongs to the API, not to its caller.

Two related hunts: **sharp edges** (an interface that invites misuse) and **insecure defaults** (a
value that fails open when unset). The first is a design finding; the second is usually an
exploitable configuration finding in a specific deployment.

## Rationalizations to Reject

| Rationalization | Why it is wrong |
|---|---|
| "It's documented" | Developers do not read docs under deadline pressure. Documentation affects severity, not existence |
| "Advanced users need the flexibility" | Most "advanced" usage is copy-paste. Provide a safe high-level API; hide the primitives |
| "It's the developer's responsibility" | Blame-shifting. Someone designed the footgun |
| "Nobody would actually do that" | Under pressure, developers do everything imaginable |
| "It's just a configuration option" | Config is code, and wrong configs ship |
| "We need backwards compatibility" | An insecure default cannot be grandfathered. Deprecate loudly |
| "The default is fine, callers can override it" | A sensible *default* with an unvalidated *parameter* is still a footgun — see below |

## Part 1 — Sharp Edge Categories

### 1. Algorithm and mode selection

An API that lets the caller choose the algorithm invites choosing wrong — and an API that lets
*untrusted input* choose it is broken by construction.

The canonical case is **JWT**: the token's own header names the algorithm, so an attacker sets
`"alg": "none"` to skip verification, or flips `RS256`→`HS256` so the *public* key is used as an
HMAC secret. Root cause: untrusted input controlling a security-critical decision.

Detection: parameters named `algorithm`, `alg`, `mode`, `cipher`, `hash`, `hash_type`, `curve`,
`padding`; enums or **strings** selecting a cryptographic primitive; a config option naming a
security mechanism. A string parameter is worse than an enum, because it accepts `"crc32"`.

### 2. Dangerous defaults and magic values

The core question for every security-relevant numeric or string setting: **what does zero mean?
what does empty mean? what does negative mean?**

```python
def verify_otp(code, lifetime=300):
    if lifetime == 0:
        return True        # "no expiry" — or "expired immediately"? Both readings exist in the wild
```

Detection: timeouts and lifetimes that accept `0`; `max_attempts=0`; `key=""`; `-1` with undefined
semantics; null values that skip validation rather than failing; a boolean whose default disables
a security feature. Ask of each: **is the default the most secure option, and can *any* accepted
value disable security entirely?**

### 3. Primitive vs semantic types

An API that takes raw `bytes`/`string`/`[]byte` for distinct security concepts invites swapping
them. `sodium_crypto_box($message, $nonce, $keypair)` — three byte strings, and nothing stops the
nonce and the keypair being passed in the wrong order, or the nonce being reused. A typed API
(`Crypto::seal($msg, new EncryptionPublicKey($key))`) turns the mistake into a compile error.

Detection: the same type used for keys, nonces, ciphertexts, signatures, and plaintexts;
parameters that could be transposed without a type error.

The comparison footgun is the same class: `hmac == expected` and `hmac.Equal(mac, expected)` have
identical types and different security properties, so nothing flags the wrong one
(`crypto-side-channel-audit`).

### 4. Configuration cliffs

One wrong setting, catastrophic failure, no warning.

```yaml
verify_ssl: fasle          # typo — silently truthy in many parsers, so TLS verification is ON... or the
                           # key is unrecognised and the default applies. Either way, nobody is told
session_timeout: -1        # "never expire"?
auth_required: true
bypass_auth_for_health_checks: true
health_check_path: "/"     # the combination is the vulnerability
```

Detection: boolean flags that disable security entirely; unvalidated string configs; **combinations**
that interact dangerously while each is individually reasonable; environment variables that
override a security setting; and **constructor parameters with sensible defaults but no
validation** — a good default does not protect against a caller that passes `md5` or `0`.

### 5. Silent failures

An error that does not surface, or a success that masks a failure.

```python
def verify_signature(sig, data, key):
    if not key:
        return True     # no key supplied → verification "succeeds"
```

Detection: security functions returning a boolean instead of throwing; empty catch blocks around
security operations; a default value substituted on a parse error; a verifier that "succeeds" on
malformed input; two sibling APIs where one throws and one returns `False`, so a caller who
forgets the return check is silently unprotected.

### 6. Stringly-typed security

Permissions as comma-separated strings (`permissions += ",admin"` is one character from privilege
escalation); roles and scopes as arbitrary strings instead of enums; SQL and commands built by
concatenation; URLs and paths built by joining strings. Detection is by grep for the concatenation
plus a read of what the string later authorizes.

## Part 2 — Insecure Defaults: The Five Families

This half is concrete and greppable. Each family is a fail-open pattern with a specific shape.

**1. Default credentials.** A hardcoded username/password/key that works when nothing is
configured. Look for `admin`/`admin`, `root` with an empty password, a default API key or JWT
secret in a sample config that the loader also uses as a fallback, a seeded initial user, and a
"change this in production" comment next to a value that works without changing.

```bash
rg -n -i "(password|passwd|secret|token|api_?key|private_?key)\s*[:=]\s*[\"'][^\"']{1,60}[\"']" --glob '!test*'
rg -n -i "default_(password|secret|key|token)|CHANGE_?ME|changeme|insecure|placeholder"
rg -n -i "(admin|root|guest|test|demo)\s*[:=]\s*[\"'](admin|root|password|123|)[\"']"
```

**2. Fallback secrets.** The most exploitable of the five, because it fails open *silently*: a
secret read from the environment with a literal default.

```bash
rg -n -i "getenv\(|os\.environ\.get\(|env\[|ENV\[|process\.env\." -A1 | rg -i "secret|key|token|password|salt|pepper"
rg -n -i "(SECRET|KEY|TOKEN|PASSWORD|SALT)[A-Z_]*\s*[,)]\s*[\"'][^\"']+[\"']"   # a default 2nd arg
rg -n -i "unwrap_or\(|unwrap_or_else\(|\|\|\s*[\"']|or\s+[\"']|\?\?\s*[\"']" | rg -i "secret|key|token"
```

`os.environ.get("SECRET_KEY", "dev-secret")` in a production deployment that forgot the variable
is a **known signing key** — trivially exploitable, and invisible in every log.

**3. Debug features reachable in production.** Look for a debug flag defaulting on; a debug/admin
endpoint registered unconditionally; verbose error pages returning stack traces; a test or
impersonation backdoor behind an environment check that can be spoofed; profiling, `/metrics`, or
a REPL/console endpoint exposed without auth.

```bash
rg -n -i "debug\s*[:=]\s*(true|1|on|yes)|DEBUG\s*=\s*True|app\.debug|RAILS_ENV|NODE_ENV"
rg -n -i "/debug|/__debug|/console|/admin/|/actuator|/metrics|/pprof|/graphql\?|introspection"
rg -n -i "if\s+.*(debug|dev|test|staging).*:\s*$" -A3
```

The refutation to check for is genuine: is the flag actually off in the shipped
config/Dockerfile/Helm values? Verify it in the deployment artifact, not the source default —
plenty of projects ship with it on.

**4. Permissive access defaults.** Deny-by-default is the correct posture, so any default-allow is
a finding: `chmod 0777` / `0666`, a world-writable directory, an `umask` of `0`, `CORS: *` with
credentials, a bind to `0.0.0.0` for a service intended to be local, a `NULL` DACL, an
`AllowAny`/`permit_all` default permission class, a policy `Effect: Allow` with `Resource: "*"`,
an authorization decision whose fall-through returns allow.

```bash
rg -n "0777|0666|0o777|S_IRWXO|umask\s*\(\s*0\s*\)|chmod\s+-R\s+777"
rg -n -i "0\.0\.0\.0|::\s*|allow_?origin.*\*|Access-Control-Allow-Origin.*\*"
rg -n -i "AllowAny|permit_all|authorize\s*=\s*false|require_auth\s*=\s*false|anonymous.*allow"
rg -n -i "return\s+(True|true|1|Allow|ALLOW)\s*$" -B4 | rg -i "def (check|can|is_allowed|authorize|has_perm)"
```

**5. Weak crypto defaults.** `md5`/`sha1` for anything security-relevant, DES/3DES/RC4, ECB mode, a
static or zero IV, an unauthenticated mode, RSA without OAEP, a KDF with no salt or a trivial
iteration count, `random`/`Math.random`/`rand` where a CSPRNG belongs, TLS version or cipher
downgrade options defaulting permissive, certificate verification defaulting off.

```bash
rg -n -i "\b(md5|sha1|des|3des|rc4|ecb|blowfish)\b" --glob '!test*'
rg -n -i "verify\s*=\s*(False|false|0)|InsecureSkipVerify|rejectUnauthorized\s*:\s*false|CURLOPT_SSL_VERIFY(PEER|HOST)\s*,\s*0"
rg -n -i "iv\s*=\s*(\[?0|b?[\"']\\\\x00|new byte\[)|IV\s*=\s*null"
rg -n -i "SSLv2|SSLv3|TLSv1(\.0|\.1)?[^.]|MinVersion|ssl_version"
```

## Part 3 — Workflow

**Phase 1 — Surface identification.** Map the security-relevant APIs: authentication,
authorization, cryptography, session management, input validation, deserialization. Then find the
**developer choice points** — everywhere the caller picks an algorithm, sets a timeout, chooses a
mode. Then find the configuration schemas: environment variables, config files, constructor
parameters, CLI flags, Helm values, Terraform variables.

**Phase 2 — Edge-case probing.** For each choice point, ask: what happens with `0`, `""`, `null`,
`[]`? What does `-1` mean? Can two security concepts be transposed without a type error? Is the
default the secure option? What happens on invalid input — silent acceptance, a substituted
default, or a hard failure?

**Phase 3 — Threat model against three adversaries.** They find different bugs:

- **The scoundrel** — actively malicious, and controls configuration or input. Can they disable
  security via config? Downgrade the algorithm? Inject a value the parser accepts?
- **The lazy developer** — copy-pastes the first example, skips the docs. Is the first example in
  the README secure? Is the path of least resistance secure? Do the error messages steer toward the
  safe API?
- **The confused developer** — misunderstands the API. Can they transpose parameters? Use the
  wrong key type by accident? Are failure modes obvious or silent?

**Phase 4 — Validate.** Write minimal code demonstrating the misuse. Verify it creates a **real**
vulnerability, not just an ugly call. Check whether the danger is documented (this affects
severity, not existence). Confirm the API *can* be used safely with reasonable effort — if it
cannot, that is a stronger finding.

For an insecure-defaults finding specifically, the validation is: **does this default actually
apply in the shipped deployment?** Check the Dockerfile, the Helm values, the systemd unit, the
production config, the CI environment. A dangerous default overridden everywhere it matters is a
hardening note; one that survives into production is an exploitable finding.

## Severity

| Severity | Criterion | Example |
|---|---|---|
| **Critical** | The default or the obvious usage is insecure | `verify: false` default; a fallback signing secret; an empty password accepted |
| **High** | Easy misconfiguration breaks security | an algorithm parameter accepting `"none"`; debug endpoint reachable in the shipped image |
| **Medium** | Unusual but possible misconfiguration | a negative timeout with unexpected meaning; an unvalidated constructor parameter |
| **Low** | Requires deliberate misuse | an obscure parameter combination nobody would reach by accident |

A finding here still needs the same discipline as any other: name the attacker, the capability,
and the harm, and run it through `false-positive-refutation` — particularly brocard 5 (documented
behaviour) and brocard 6 (cure worse than the disease), which is where design findings most often
fail honestly.

## Cross-references

- Refuting a design finding, and the documented-behaviour brocard → `false-positive-refutation`
- Every other call site of the footgun API → `variant-analysis`
- The C/C++ classes this overlaps (`banned-api-with-attacker-data`, `exploit-mitigations` with its silently misspelled flags) → `c-cpp-review`
- Rust's `CARGOLINT` and unvalidated trait-supplied bounds → `rust-security-audit`
- Non-constant-time comparison as a footgun, and weak-RNG defaults → `crypto-side-channel-audit`
- A dependency's own dangerous defaults and install scripts → `supply-chain-audit`
- Auth-specific default and fallback patterns in web targets → `auth-sec`, `code-security`
- LLM/agent tool-permission defaults → `llm-security`
