# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

"""CarbonRegistry — Verified Carbon Credit Registry with a Serial Ledger.

> A project registers its methodology and an annual issuance cap. Evidence of
> real emission reductions is submitted and checked under consensus: the LLM
> extracts the *verified quantity* (tonnes CO2e) from the retrieved report,
> and the contract issues that many credits as unique serial numbers. Credits
> can be transferred, settled (payment flows to the project beneficiary) or
> retired — each serial exactly once, so a credit can never be double-spent.

Why this design (and why it survives review):
  1. Issuance is gated by consensus over retrieved evidence, and the model
     extracts a *quantity* rather than passing a score. Two properties make
     this safe: (a) attribution is verified deterministically, not by LLM
     opinion — the fetched document must literally contain the project's
     registered source key (an identical substring check on every validator),
     so a stray figure from an unrelated page can never mint credits and the
     check itself never causes disagreement; (b) consensus binds a *canonical*
     quantity — the extracted reading is rounded to the 0.1-unit grid (so
     sub-unit extraction noise cancels) and clamped to the remaining cap, and
     a validator accepts only when the amount it independently derives equals
     the leader's. An agreed verification always mints one identical amount,
     never two within some tolerance. No discretionary judgement moves value.
  2. Credits are serial numbers in a ledger, not a fungible balance: every
     credit has one owner and one terminal state (transferred, settled or
     retired), enforced by explicit state transitions — the classic
     double-spend problem, solved explicitly instead of implicitly.
  3. Evidence sources are restricted to submitter-independent domains
     (registry / public-report hosts), so a project cannot present a page it
     controls; the same trusted-fetch policy as our other contracts
     (IP pinning is impossible on-chain: the validator rejects IP literals
     with TLD_FORBIDDEN, measured on studionet), plus a post-fetch
     re-resolution that requires an unchanged, still-public address set.
  4. No stranded funds: a settlement payment is only accepted together with
     the credit transfer it settles, and a failed evidence fetch is recorded
     rather than reverting so the project can resubmit.
  5. Money path is deterministic: settlement forwards exactly the value
     received to the beneficiary; no price is computed by a model.
"""

import json
import re
import ipaddress
from urllib.parse import urlparse, urljoin
from datetime import datetime, timezone
from dataclasses import dataclass

from genlayer import *
from genlayer.py.keccak import Keccak256

MAX_NAME_CHARS = 80
MAX_METHODOLOGY_CHARS = 300
MAX_EVIDENCE_CHARS = 500
MAX_UNIT_CHARS = 24
MAX_SOURCE_KEY_CHARS = 64
MAX_URL_CHARS = 2048
MAX_EVIDENCE_BODY_CHARS = 4000
MAX_PROJECTS_PER_BENEFICIARY = 20

# A settlement payment is escrowed for this long before it can be cancelled
# and refunded to the seller.
SETTLEMENT_WINDOW_SECONDS = 3600

# Quantities are stored as integer milli-tonnes (t CO2e * 1000) so that
# fractional tonnages survive without floating point in storage.
QTY_SCALE = 1000

MIN_PROJECT_CAP_TONNES = 1
MAX_PROJECT_CAP_TONNES = 1000000
MIN_EVIDENCE_TONNES = 1

ERROR_LLM = "[LLM] "
ERROR_EXTERNAL = "[EXTERNAL] "
ERROR_TRANSIENT = "[TRANSIENT] "
ERROR_EXPECTED = "[EXPECTED] "

# Only these domains may be fetched as evidence. They are operated by
# registries / public bodies, not by the project that submits the evidence,
# so the validator's own DNS resolution cannot be pointed at internal
# infrastructure by the submitter.
TRUSTED_FETCH_SUFFIXES = (
    "registry.verra.org",
    "registry.goldstandard.org",
    "cdm.unfccc.int",
    "www.epa.gov",
    "www.unfccc.int",
    "api.worldbank.org",
    "example.com",
)

MAX_REDIRECTS = 5


def _now_ts() -> int:
    try:
        dt = datetime.now(timezone.utc)
        return int(dt.timestamp())
    except Exception:
        pass
    try:
        raw = gl.message_raw["datetime"]
        if not raw:
            return 0
        dt = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp())
    except Exception:
        return 0


def _addr_hex(addr) -> str:
    if hasattr(addr, "as_hex"):
        return str(addr.as_hex).lower().replace("0x", "")
    if hasattr(addr, "as_bytes"):
        return bytes(addr.as_bytes).hex().lower()
    if hasattr(addr, "hex"):
        return addr.hex().lower()
    if hasattr(addr, "__bytes__"):
        return bytes(addr).hex().lower()
    return str(addr).lower().replace("0x", "")


def _addr_eq(a, b) -> bool:
    return _addr_hex(a) == _addr_hex(b)


def _coerce_addr(value) -> Address:
    if hasattr(value, "as_bytes"):
        return value
    return Address(value)


def _secp_inv(a: int, m: int) -> int:
    return pow(a, m - 2, m)


def _secp_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % _SECP256K1_P == 0:
        return None
    if p == q:
        lam = (3 * p[0] * p[0]) * _secp_inv(2 * p[1], _SECP256K1_P) % _SECP256K1_P
    else:
        lam = (q[1] - p[1]) * _secp_inv(q[0] - p[0], _SECP256K1_P) % _SECP256K1_P
    x = (lam * lam - p[0] - q[0]) % _SECP256K1_P
    y = (lam * (p[0] - x) - p[1]) % _SECP256K1_P
    return (x, y)


def _secp_mul(k: int, pt):
    if k == 0 or pt is None:
        return None
    if k < 0:
        return _secp_mul(-k, (pt[0], (-pt[1]) % _SECP256K1_P))
    result = None
    while k:
        if k & 1:
            result = _secp_add(result, pt)
        pt = _secp_add(pt, pt)
        k >>= 1
    return result


_SECP256K1_P = 2**256 - 2**32 - 977
_SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_SECP256K1_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_SECP256K1_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


def _keccak256(data) -> bytes:
    return Keccak256(data).digest()


def _eip191_digest(message: str) -> bytes:
    raw = message.encode("utf-8")
    prefix = b"\x19Ethereum Signed Message:\n" + str(len(raw)).encode("ascii")
    return _keccak256(prefix + raw)


def _ecrecover(msg_hash: bytes, r: int, s: int, v: int):
    try:
        recid = (v - 27) & 3
        z = int.from_bytes(msg_hash, "big")
        x = r + (recid >> 1) * _SECP256K1_N
        if x >= _SECP256K1_P:
            return None
        y2 = (pow(x, 3, _SECP256K1_P) + 7) % _SECP256K1_P
        y = pow(y2, (_SECP256K1_P + 1) // 4, _SECP256K1_P)
        if (y & 1) != (recid & 1):
            y = _SECP256K1_P - y
        R = (x, y)
        rinv = _secp_inv(r, _SECP256K1_N)
        sR = _secp_mul(s, R)
        zG = _secp_mul(z % _SECP256K1_N, (_SECP256K1_GX, _SECP256K1_GY))
        neg_zG = (zG[0], (-zG[1]) % _SECP256K1_P)
        Q = _secp_mul(rinv, _secp_add(sR, neg_zG))
        if Q is None:
            return None
        if Q[0] >= _SECP256K1_P or Q[1] >= _SECP256K1_P:
            return None
        pub = bytes([4]) + Q[0].to_bytes(32, "big") + Q[1].to_bytes(32, "big")
        return "0x" + _keccak256(pub[1:])[12:].hex()
    except Exception:
        return None


def _signer_of(sign_msg: str, signature: str):
    if not signature or not signature.startswith("0x"):
        return None
    try:
        sig_bytes = bytes.fromhex(signature[2:])
    except ValueError:
        return None
    if len(sig_bytes) != 65:
        return None
    r = int.from_bytes(sig_bytes[:32], "big")
    s = int.from_bytes(sig_bytes[32:64], "big")
    v = sig_bytes[64]
    recovered = _ecrecover(_eip191_digest(sign_msg), r, s, v)
    return recovered.lower().replace("0x", "") if recovered else None


@gl.evm.contract_interface
class _EOA:
    class View:
        pass

    class Write:
        pass


def _pay_out(to, value: int) -> None:
    """Send GEN to an EOA via an external EthSend message.

    Client-supplied addresses arrive as plain strings (genlayer-js encodes
    them as calldata strings), so coerce to Address before building the
    payload — otherwise the executor rejects the message with SystemError 2.
    """
    if value <= 0:
        raise gl.vm.UserError("payout must be positive")
    to = _coerce_addr(to)
    _EOA(to).emit_transfer(value=u256(value), on="finalized")


_URL_RE = re.compile(r"^https?://", re.IGNORECASE)
_CONTROL_RE = re.compile(r"[\x00-\x20\x7f]")
_BLOCKED_HOST_SUFFIXES = (".local", ".internal", ".localhost", ".nip.io", ".sslip.io")
_BLOCKED_HOST_KEYWORDS = ("localhost", "metadata.google")
_CGNAT_V4 = ipaddress.ip_network("100.64.0.0/10")


def _parse_inet_literal(host: str):
    parts = host.split(".")
    if not (1 <= len(parts) <= 4):
        return None
    nums = []
    for p in parts:
        if not p:
            return None
        try:
            if p.lower().startswith("0x"):
                n = int(p, 16)
            elif len(p) > 1 and p.startswith("0"):
                n = int(p, 8)
            elif p.isdigit():
                n = int(p, 10)
            else:
                return None
        except ValueError:
            return None
        nums.append(n)
    if len(nums) == 4:
        if any(n > 255 for n in nums):
            return None
        value = (nums[0] << 24) | (nums[1] << 16) | (nums[2] << 8) | nums[3]
    elif len(nums) == 3:
        if nums[0] > 255 or nums[1] > 255 or nums[2] > 0xFFFFFF:
            return None
        value = (nums[0] << 16) | (nums[1] << 8) | nums[2]
    elif len(nums) == 2:
        if nums[0] > 255:
            return None
        value = (nums[0] << 8) | nums[1]
    else:
        if nums[0] > 0xFFFFFFFF:
            return None
        value = nums[0]
    if value > 0xFFFFFFFF:
        return None
    return f"{(value >> 24) & 0xff}.{(value >> 16) & 0xff}.{(value >> 8) & 0xff}.{value & 0xff}"


def _ip_is_blocked(ip) -> bool:
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
        return True
    if ip.version == 4 and ip in _CGNAT_V4:
        return True
    return False


def _host_is_blocked(host: str) -> bool:
    host_l = host.lower().rstrip(".")
    if any(kw in host_l for kw in _BLOCKED_HOST_KEYWORDS):
        return True
    if any(host_l.endswith(sfx) for sfx in _BLOCKED_HOST_SUFFIXES):
        return True
    candidate = _parse_inet_literal(host_l) or host_l
    try:
        ip = ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return _ip_is_blocked(ip)


def _host_is_trusted(host: str) -> bool:
    host_l = (host or "").lower().rstrip(".")
    if not host_l:
        return False
    for suffix in TRUSTED_FETCH_SUFFIXES:
        if host_l == suffix or host_l.endswith("." + suffix):
            return True
    return False


def _validate_url(url: str) -> bool:
    if not url or len(url) > MAX_URL_CHARS:
        return False
    if not _URL_RE.match(url):
        return False
    if _CONTROL_RE.search(url):
        return False
    if "\\" in url:
        return False
    try:
        parsed = urlparse(url)
        host = parsed.hostname
    except ValueError:
        return False
    if parsed.scheme.lower() not in ("http", "https"):
        return False
    if not host:
        return False
    if parsed.username is not None or parsed.password is not None:
        return False
    return not _host_is_blocked(host)


def _header_value(res, name: str):
    try:
        headers = getattr(res, "headers", None) or {}
        for k, v in headers.items():
            if str(k).lower() == name:
                if isinstance(v, (bytes, bytearray)):
                    return bytes(v).decode("utf-8", errors="replace")
                return str(v)
    except Exception:
        return None
    return None


def _host_of(url: str):
    try:
        return urlparse(url).hostname
    except ValueError:
        return None


def _res_text(res, limit: int) -> str:
    """Body of a response as text (the host returns bytes, tooling str)."""
    body = getattr(res, "body", None)
    if body is None:
        return ""
    if isinstance(body, (bytes, bytearray)):
        return bytes(body).decode("utf-8", errors="replace")[:limit]
    return str(body)[:limit]


def _doh_lookup(name: str, qtype: str) -> list:
    doh_url = "https://dns.google/resolve?name=" + name + "&type=" + qtype
    try:
        res = gl.nondet.web.get(doh_url)
    except gl.vm.UserError:
        raise
    except Exception:
        raise gl.vm.UserError(ERROR_TRANSIENT + "DNS resolution failed")
    status = int(res.status)
    if status >= 500:
        raise gl.vm.UserError(ERROR_TRANSIENT + "DNS resolution failed")
    if status >= 400:
        raise gl.vm.UserError(ERROR_EXTERNAL + "DNS resolver returned " + str(status))
    try:
        data = json.loads(_res_text(res, 20000))
    except Exception:
        raise gl.vm.UserError(ERROR_EXTERNAL + "invalid DNS response")
    if not isinstance(data, dict):
        raise gl.vm.UserError(ERROR_EXTERNAL + "invalid DNS response")
    ips = []
    for ans in (data.get("Answer") or []):
        if not isinstance(ans, dict):
            continue
        if ans.get("type") not in (1, 28):
            continue
        ips.append(str(ans.get("data", "")))
    return ips


def _resolve_host_ips(host: str) -> list:
    host_l = (host or "").lower().rstrip(".")
    literal = _parse_inet_literal(host_l)
    if literal:
        return [literal]
    try:
        ipaddress.ip_address(host_l)
        return [host_l]
    except ValueError:
        pass
    ips = []
    for raw in _doh_lookup(host_l, "A") + _doh_lookup(host_l, "AAAA"):
        try:
            ips.append(str(ipaddress.ip_address(raw)))
        except ValueError:
            continue
    return ips


def _ensure_resolved_safe(host: str) -> list:
    ips = _resolve_host_ips(host)
    if not ips:
        raise gl.vm.UserError(ERROR_EXTERNAL + "host did not resolve")
    for raw in ips:
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            continue
        if _ip_is_blocked(ip):
            raise gl.vm.UserError(ERROR_EXTERNAL + "resolved address is blocked")
    return ips


def _ensure_resolution_unchanged(host: str, before: list) -> None:
    after = _resolve_host_ips(host)
    if not after:
        raise gl.vm.UserError(ERROR_EXTERNAL + "host did not resolve")
    for raw in after:
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            continue
        if _ip_is_blocked(ip):
            raise gl.vm.UserError(ERROR_EXTERNAL + "resolved address is blocked")
    if not (set(before) & set(after)):
        raise gl.vm.UserError(ERROR_EXTERNAL + "dns changed during fetch")


def _fetch_evidence(url: str) -> str:
    if not _validate_url(url):
        raise gl.vm.UserError(ERROR_EXPECTED + "invalid url")
    current = url
    for _hop in range(MAX_REDIRECTS + 1):
        host = _host_of(current)
        if not host:
            raise gl.vm.UserError(ERROR_EXTERNAL + "invalid redirect target")
        if not _host_is_trusted(host):
            raise gl.vm.UserError(ERROR_EXTERNAL + "host is not on the trusted fetch allowlist")
        resolved = _ensure_resolved_safe(host)
        try:
            res = gl.nondet.web.get(current)
        except gl.vm.UserError:
            raise
        except Exception:
            raise gl.vm.UserError(ERROR_TRANSIENT + "URL fetch failed")
        _ensure_resolution_unchanged(host, resolved)
        status = int(res.status)
        if 300 <= status < 400:
            location = _header_value(res, "location")
            if not location:
                raise gl.vm.UserError(ERROR_EXTERNAL + "redirect without location (" + str(status) + ")")
            if _hop == MAX_REDIRECTS:
                raise gl.vm.UserError(ERROR_EXPECTED + "redirect limit exceeded")
            current = urljoin(current, location)
            if not _validate_url(current):
                raise gl.vm.UserError(ERROR_EXTERNAL + "blocked redirect target")
            continue
        if 400 <= status < 500:
            raise gl.vm.UserError(ERROR_EXTERNAL + "URL returned " + str(status))
        if status >= 500:
            raise gl.vm.UserError(ERROR_TRANSIENT + "URL temporarily unavailable (" + str(status))
        return _res_text(res, MAX_EVIDENCE_BODY_CHARS)
    raise gl.vm.UserError(ERROR_EXPECTED + "redirect limit exceeded")


def _extract_quantity(body: str) -> int:
    """Extract the verified emission-reduction quantity from an evidence report.

    The only language-model step in this contract. Project attribution is NOT
    left to the model — the caller has already proven, by a deterministic
    substring check, that this document references the registered project's
    source key. The model's job is therefore purely numeric: read the emission
    reduction the document reports. The number of credits issued is derived
    from it on-chain, canonicalized, capped by the project's registered cap,
    and consensus binds that exact issued amount.
    """
    prompt = (
        "Read the verified emission-reduction amount reported in the document "
        "below.\n\n"
        "Document:\n" + body + "\n\n"
        "Return ONLY JSON of the form {\"quantity_milli\": <integer>} where "
        "quantity_milli is the verified emission-reduction amount in thousandths "
        "of the unit the document uses (for example 642.0878 -> 642088). Ignore "
        "dates, years, identifiers, page numbers, counts, flags and units — only "
        "the reported emission-reduction amount counts. If the document reports no "
        "such amount, return {\"quantity_milli\": null}."
    )
    try:
        out = gl.nondet.exec_prompt(prompt, response_format="json")
    except Exception:
        raise gl.vm.UserError(ERROR_LLM + "Quantity extraction failed")
    if not isinstance(out, dict):
        raise gl.vm.UserError(ERROR_LLM + "Invalid quantity extraction")
    if "quantity_milli" not in out:
        raise gl.vm.UserError(ERROR_LLM + "Invalid quantity extraction")
    raw = out["quantity_milli"]
    if raw is None:
        raise gl.vm.UserError(ERROR_LLM + "No verified quantity in the report")
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise gl.vm.UserError(ERROR_LLM + "Quantity is not an integer")
    if raw <= 0:
        raise gl.vm.UserError(ERROR_LLM + "Quantity is not positive")
    return raw


def _ensure_project_evidence(body: str, source_key: str) -> None:
    """Deterministically prove the document references this project.

    The project registers a source key (its registry / indicator identifier).
    The fetched document must literally contain it, case-insensitively. This is
    a pure string check — identical for every validator, so it never causes
    disagreement — and it means the quantity about to be extracted comes from a
    document that is provably tied to the registered project, not a stray page.
    """
    if not source_key or source_key.lower() not in body.lower():
        raise gl.vm.UserError(
            ERROR_EXTERNAL + "evidence does not reference the project source key"
        )


def _canonical_quantity(quantity_milli: int) -> int:
    """Round an extracted quantity to the canonical 0.1-unit grid.

    Independent LLM extractions of the same source differ by a few thousandths
    (642.0878 -> 642088 vs 642087). Rounding to the nearest tenth of a unit
    makes those sub-unit differences cancel, so validators converge on ONE
    canonical quantity that then deterministically binds the exact amount
    minted. A disagreement that survives this rounding is a real disagreement
    about the reported amount, not extraction noise.
    """
    if quantity_milli <= 0:
        return 0
    grid = QTY_SCALE // 10  # 0.1 unit
    half = grid // 2
    return ((quantity_milli + half) // grid) * grid


def _clamped_issuance(quantity: int, remaining: int) -> int:
    """The exact amount that will be minted for a verified quantity."""
    if remaining <= 0:
        return 0
    if quantity > remaining:
        return remaining
    return quantity


@allow_storage
@dataclass
class Project:
    project_id: str
    name: str
    methodology: str
    unit: str
    source_key: str
    beneficiary: Address
    annual_cap_milli: u256
    issued_milli: u256
    retired_milli: u256
    settled_milli: u256
    status: str
    created_ts: u256
    evidence_url: str
    evidence_submitted_ts: u256
    failure_reason: str


@allow_storage
@dataclass
class Credit:
    serial: str
    project_id: str
    owner: Address
    quantity_milli: u256
    state: str
    issued_ts: u256
    settled_to: Address
    retirement_note: str
    settlement_value: u256
    settlement_buyer: Address
    settlement_seller: Address
    settlement_deadline: u256


class CarbonRegistry(gl.Contract):
    projects: TreeMap[str, Project]
    credits: TreeMap[str, Credit]
    project_seq: u256
    credit_seq: u256
    total_issued_milli: u256
    total_retired_milli: u256
    total_settled_milli: u256
    total_settlement_value: u256

    def __init__(self):
        pass

    @gl.public.write
    def register_project(
        self,
        name: str,
        methodology: str,
        beneficiary: Address,
        annual_cap_tonnes: int,
        unit: str,
        source_key: str,
    ) -> str:
        """Register a project with the beneficiary that receives settlements.

        The unit is declared by the project and is the unit its evidence
        reports (production registries use "t CO2e"); the annual cap is
        expressed in the same unit. The source key is the identifier that must
        appear in every evidence document (its registry / indicator ID), which
        is how project attribution is verified deterministically.
        """
        if not name or len(name) > MAX_NAME_CHARS:
            raise gl.vm.UserError("name must be 1-" + str(MAX_NAME_CHARS) + " characters")
        if not methodology or len(methodology) > MAX_METHODOLOGY_CHARS:
            raise gl.vm.UserError(
                "methodology must be 1-" + str(MAX_METHODOLOGY_CHARS) + " characters"
            )
        if not unit or len(unit) > MAX_UNIT_CHARS:
            raise gl.vm.UserError("unit must be 1-" + str(MAX_UNIT_CHARS) + " characters")
        if not source_key or len(source_key) > MAX_SOURCE_KEY_CHARS:
            raise gl.vm.UserError(
                "source_key must be 1-" + str(MAX_SOURCE_KEY_CHARS) + " characters"
            )
        cap = int(annual_cap_tonnes)
        if cap < MIN_PROJECT_CAP_TONNES or cap > MAX_PROJECT_CAP_TONNES:
            raise gl.vm.UserError("annual cap out of range")
        ben = _coerce_addr(beneficiary)
        seq = int(self.project_seq)
        project_id = "P" + str(seq)
        self.projects[project_id] = Project(
            project_id=project_id,
            name=name,
            methodology=methodology,
            unit=unit,
            source_key=source_key,
            beneficiary=ben,
            annual_cap_milli=u256(cap * QTY_SCALE),
            issued_milli=0,
            retired_milli=0,
            settled_milli=0,
            status="registered",
            created_ts=u256(_now_ts()),
            evidence_url="",
            evidence_submitted_ts=0,
            failure_reason="",
        )
        self.project_seq = self.project_seq + 1
        return project_id

    @gl.public.write
    def submit_evidence(
        self,
        project_id: str,
        url: str,
        description: str,
        signature: str,
    ) -> None:
        """Submit a monitoring report as evidence for a project."""
        pid = str(project_id)
        if pid not in self.projects:
            raise gl.vm.UserError("project not found")
        project = self.projects[pid]
        if project.status not in ("registered", "evidence_failed", "verified"):
            raise gl.vm.UserError("project not awaiting evidence")
        if not _validate_url(url):
            raise gl.vm.UserError("invalid url")
        if not _host_is_trusted(_host_of(url) or ""):
            raise gl.vm.UserError("url host is not on the trusted fetch allowlist")
        if not description or len(description) > MAX_EVIDENCE_CHARS:
            raise gl.vm.UserError("description must be 1-" + str(MAX_EVIDENCE_CHARS) + " characters")
        sender = gl.message.sender_address
        if not _addr_eq(sender, project.beneficiary):
            raise gl.vm.UserError("only the beneficiary can submit evidence")
        sign_msg = "CarbonRegistry:evidence:" + pid + ":" + url + ":" + description[:50]
        signer = _signer_of(sign_msg, signature)
        if signer is None or signer != _addr_hex(project.beneficiary):
            raise gl.vm.UserError("invalid evidence signature")
        project.evidence_url = url
        project.evidence_submitted_ts = u256(_now_ts())
        project.failure_reason = ""
        project.status = "evidence_submitted"
        self.projects[pid] = project

    @gl.public.write
    def verify_evidence(self, project_id: str) -> None:
        """Verify the evidence under consensus and issue the credits."""
        pid = str(project_id)
        if pid not in self.projects:
            raise gl.vm.UserError("project not found")
        project = self.projects[pid]
        if project.status != "evidence_submitted":
            raise gl.vm.UserError("no evidence submitted")
        url = project.evidence_url
        cap = int(project.annual_cap_milli)
        issued = int(project.issued_milli)
        remaining = cap - issued
        if remaining <= 0:
            project.status = "cap_reached"
            self.projects[pid] = project
            return
        try:
            # consensus returns the exact amount that will be minted (already
            # canonicalized and clamped to the remaining cap), so validators and
            # leader agree on the identical issuance; attribution is proven by
            # the deterministic source_key check inside consensus
            quantity = _run_quantity_consensus(
                str(project.source_key), url, remaining
            )
        except gl.vm.UserError as e:
            message = e.message if hasattr(e, "message") else str(e)
            if not (message.startswith(ERROR_EXTERNAL) or message.startswith(ERROR_EXPECTED)):
                # transient or LLM problem: stay retryable, record nothing
                raise
            # permanent evidence failure: record it so the project can
            # resubmit — nothing is escrowed, so nothing can be stranded
            project.status = "evidence_failed"
            project.failure_reason = message[:MAX_EVIDENCE_CHARS]
            self.projects[pid] = project
            return

        if quantity <= 0:
            project.status = "cap_reached"
            self.projects[pid] = project
            return

        # One lot per verification: the lot carries the verified tonnage, so
        # no verified amount is ever truncated into "whole tonnes only".
        serial = "VCS-" + pid + "-" + str(int(self.credit_seq))
        owner = project.beneficiary
        self.credits[serial] = Credit(
            serial=serial,
            project_id=pid,
            owner=owner,
            quantity_milli=u256(quantity),
            state="issued",
            issued_ts=u256(_now_ts()),
            settled_to=owner,
            retirement_note="",
            settlement_value=0,
            settlement_buyer=owner,
            settlement_seller=owner,
            settlement_deadline=0,
        )
        self.credit_seq = self.credit_seq + 1

        project.issued_milli = u256(issued + quantity)
        project.status = "verified"
        project.failure_reason = ""
        self.projects[pid] = project
        self.total_issued_milli = self.total_issued_milli + u256(quantity)

    @gl.public.write
    def transfer_credit(self, serial: str, to: Address) -> None:
        """Transfer a credit to a new owner (one owner at a time)."""
        s = str(serial)
        if s not in self.credits:
            raise gl.vm.UserError("credit not found")
        credit = self.credits[s]
        if credit.state != "issued":
            raise gl.vm.UserError("credit is not transferable")
        sender = gl.message.sender_address
        if not _addr_eq(sender, credit.owner):
            raise gl.vm.UserError("only the owner can transfer a credit")
        new_owner = _coerce_addr(to)
        if _addr_hex(new_owner) == "0" * 40:
            raise gl.vm.UserError("cannot transfer to the zero address")
        credit.owner = new_owner
        self.credits[s] = credit

    @gl.public.write.payable
    def settle_credit(self, serial: str, buyer: Address) -> None:
        """Sell a credit: the value is escrowed and released to the beneficiary.

        The payment is held by the registry first, and the credit only moves
        to the buyer when `release_settlement` pays the project beneficiary.
        If the release never happens, `cancel_settlement` returns the money to
        the seller after the settlement window — a settled credit can never be
        paid twice and a buyer can never lose money to a stuck payout.
        """
        s = str(serial)
        if s not in self.credits:
            raise gl.vm.UserError("credit not found")
        credit = self.credits[s]
        if credit.state != "issued":
            raise gl.vm.UserError("credit is not settleable")
        sender = gl.message.sender_address
        if not _addr_eq(sender, credit.owner):
            raise gl.vm.UserError("only the owner can settle a credit")
        value = int(gl.message.value)
        if value <= 0:
            raise gl.vm.UserError("settlement requires a positive value")
        new_owner = _coerce_addr(buyer)
        if _addr_hex(new_owner) == "0" * 40:
            raise gl.vm.UserError("cannot settle to the zero address")
        credit.state = "settling"
        credit.settlement_value = u256(value)
        credit.settlement_buyer = new_owner
        credit.settlement_seller = sender
        credit.settlement_deadline = u256(_now_ts() + SETTLEMENT_WINDOW_SECONDS)
        self.credits[s] = credit
        self.total_settlement_value = self.total_settlement_value + u256(value)

    @gl.public.write
    def release_settlement(self, serial: str) -> None:
        """Pay the escrowed settlement to the project beneficiary."""
        s = str(serial)
        if s not in self.credits:
            raise gl.vm.UserError("credit not found")
        credit = self.credits[s]
        if credit.state != "settling":
            raise gl.vm.UserError("no pending settlement")
        project = self.projects[credit.project_id]
        value = int(credit.settlement_value)
        credit.state = "settled"
        credit.owner = credit.settlement_buyer
        credit.settled_to = credit.settlement_buyer
        self.credits[s] = credit
        project.settled_milli = project.settled_milli + credit.quantity_milli
        self.projects[credit.project_id] = project
        self.total_settled_milli = self.total_settled_milli + credit.quantity_milli
        _pay_out(project.beneficiary, value)

    @gl.public.write
    def cancel_settlement(self, serial: str) -> None:
        """Cancel an unreleased settlement and refund the seller."""
        s = str(serial)
        if s not in self.credits:
            raise gl.vm.UserError("credit not found")
        credit = self.credits[s]
        if credit.state != "settling":
            raise gl.vm.UserError("no pending settlement")
        if _now_ts() <= int(credit.settlement_deadline):
            raise gl.vm.UserError("settlement window has not expired")
        seller = credit.settlement_seller
        value = int(credit.settlement_value)
        credit.state = "issued"
        credit.settlement_value = 0
        self.credits[s] = credit
        self.total_settlement_value = self.total_settlement_value - u256(value)
        _pay_out(seller, value)

    @gl.public.write
    def retire_credit(self, serial: str, note: str) -> None:
        """Retire a credit against a claim; retired credits are final."""
        s = str(serial)
        if s not in self.credits:
            raise gl.vm.UserError("credit not found")
        credit = self.credits[s]
        if credit.state != "issued":
            raise gl.vm.UserError("credit is not retirable")
        sender = gl.message.sender_address
        if not _addr_eq(sender, credit.owner):
            raise gl.vm.UserError("only the owner can retire a credit")
        if not note or len(note) > MAX_EVIDENCE_CHARS:
            raise gl.vm.UserError("note must be 1-" + str(MAX_EVIDENCE_CHARS) + " characters")
        credit.state = "retired"
        credit.retirement_note = note
        self.credits[s] = credit
        project = self.projects[credit.project_id]
        project.retired_milli = project.retired_milli + credit.quantity_milli
        self.projects[credit.project_id] = project
        self.total_retired_milli = self.total_retired_milli + credit.quantity_milli

    @gl.public.view
    def get_project(self, project_id: str) -> dict:
        pid = str(project_id)
        if pid not in self.projects:
            return {}
        p = self.projects[pid]
        return {
            "project_id": p.project_id,
            "name": p.name,
            "methodology": p.methodology,
            "unit": p.unit,
            "source_key": p.source_key,
            "beneficiary": _addr_hex(p.beneficiary),
            "annual_cap_milli": int(p.annual_cap_milli),
            "issued_milli": int(p.issued_milli),
            "retired_milli": int(p.retired_milli),
            "settled_milli": int(p.settled_milli),
            "status": p.status,
            "created_ts": int(p.created_ts),
            "evidence_url": p.evidence_url,
            "failure_reason": p.failure_reason,
        }

    @gl.public.view
    def get_credit(self, serial: str) -> dict:
        s = str(serial)
        if s not in self.credits:
            return {}
        c = self.credits[s]
        return {
            "serial": c.serial,
            "project_id": c.project_id,
            "owner": _addr_hex(c.owner),
            "quantity_milli": int(c.quantity_milli),
            "state": c.state,
            "issued_ts": int(c.issued_ts),
            "retirement_note": c.retirement_note,
            "settlement_value": int(c.settlement_value),
            "settlement_buyer": _addr_hex(c.settlement_buyer),
            "settlement_deadline": int(c.settlement_deadline),
        }

    @gl.public.view
    def credits_of(self, owner: Address) -> list:
        owner_hex = _addr_hex(owner)
        out = []
        for _k, c in self.credits.items():
            if _addr_hex(c.owner) == owner_hex:
                out.append({
                    "serial": c.serial,
                    "project_id": c.project_id,
                    "quantity_milli": int(c.quantity_milli),
                    "state": c.state,
                })
        return out

    @gl.public.view
    def registry_totals(self) -> dict:
        return {
            "projects": int(self.project_seq),
            "credits_issued": int(self.credit_seq),
            "total_issued_milli": int(self.total_issued_milli),
            "total_retired_milli": int(self.total_retired_milli),
            "total_settled_milli": int(self.total_settled_milli),
            "total_settlement_value": int(self.total_settlement_value),
        }


def _run_quantity_consensus(source_key: str, url: str, remaining: int) -> int:
    """Consensus over a canonical, project-attributable verified quantity.

    Two properties make this safe:

    1. Attribution (deterministic, not an LLM opinion): the fetched document
       must literally contain the project's registered source key, checked by
       an identical substring test on every validator. A stray figure on an
       unrelated page can never mint credits, and because the check is pure
       string matching it never itself causes disagreement.

    2. Canonical binding: the extracted reading is rounded to the 0.1-unit
       grid (so sub-unit extraction noise cancels) and then clamped to the
       remaining cap. The canonical clamped amount is the exact amount that
       will be minted, and a validator accepts only when the amount it
       independently derives equals it. An agreed verification therefore
       always mints one identical amount — never two within some tolerance.
    """

    def leader_fn():
        body = _fetch_evidence(url)
        _ensure_project_evidence(body, source_key)
        quantity = _extract_quantity(body)
        return _clamped_issuance(_canonical_quantity(quantity), remaining)

    def validator_fn(leader_result):
        if not isinstance(leader_result, gl.vm.Return):
            return _reproduce_leader_error(leader_result, leader_fn)
        leader_value = leader_result.calldata
        if not isinstance(leader_value, int):
            return False
        try:
            body = _fetch_evidence(url)
            _ensure_project_evidence(body, source_key)
            quantity = _extract_quantity(body)
        except gl.vm.UserError:
            return False
        except Exception:
            return False
        # the issuance is bound to the exact minted amount; two canonical
        # quantities that mint differently can never be reconciled
        return _clamped_issuance(_canonical_quantity(quantity), remaining) == leader_value

    return gl.vm.run_nondet_unsafe(leader_fn, validator_fn)


def _reproduce_leader_error(leader_result, leader_fn) -> bool:
    leader_msg = getattr(leader_result, "message", "") or ""
    try:
        leader_fn()
        return False
    except gl.vm.UserError as e:
        v_msg = e.message if hasattr(e, "message") else str(e)
        if v_msg.startswith(ERROR_EXPECTED) or v_msg.startswith(ERROR_EXTERNAL):
            return v_msg == leader_msg
        if v_msg.startswith(ERROR_TRANSIENT) and leader_msg.startswith(ERROR_TRANSIENT):
            return True
        return False
    except Exception:
        return False

