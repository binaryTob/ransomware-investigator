"""Ransomware Artifact Analyzer: deterministic, offline, non-executing heuristics."""
from __future__ import annotations

import codecs
import re
from pathlib import PurePosixPath

from .audit import digest


ANALYZER_VERSION = "1.0.1"
MAX_FINDINGS = 256
DOMAIN_TEXT = r"(?:[A-Za-z0-9-]{1,63}\.){1,8}[A-Za-z]{2,24}"
EMAIL = re.compile(r"(?<![\w.+-])([A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@" + DOMAIN_TEXT + r")(?![\w-]|\.[\w-])")
URL = re.compile(r"\b(?:https?|hxxps?)://[^\s<>\"']{1,2048}", re.I)
DOMAIN = re.compile(r"(?<![\w@.-])" + DOMAIN_TEXT + r"(?![\w-]|\.[\w-])")
CRYPTO = re.compile(r"\b(?:AES(?:[-_ ]?(?:128|192|256))?|RSA(?:[-_ ]?(?:1024|2048|4096))?|ChaCha20(?:-Poly1305)?|Salsa20|Curve25519|X25519|ECC)\b", re.I)
LABEL = re.compile(r"\b(?:ransomware|family|familia)\s*[:=]\s*([A-Za-z][A-Za-z0-9_.-]{1,63})", re.I)
FAMILIES = re.compile(r"\b(?:LockBit|BlackCat|ALPHV|Conti|Ryuk|REvil|Sodinokibi|Akira|Clop|Djvu)\b", re.I)
VICTIM = re.compile(r"\b(?:(?:personal|victim|recovery|your|case)\s+)?(?:ID|identifier|identificador)\s*[:=]\s*([A-Za-z0-9][A-Za-z0-9_-]{2,127})", re.I)
SIGNALS = {
    "encrypted_files_claim": re.compile(r"\b(?:(?:your|all|tus|sus)\s+(?:\w+\s+){0,3}(?:files|archivos|datos)\s+(?:have\s+been|are|han\s+sido|fueron|est[aá]n)\s+(?:encrypted|cifrados|encriptados)|we\s+(?:have\s+)?encrypted\s+your\s+files)\b", re.I),
    "payment_demand_language": re.compile(r"\b(?:pay|payment|ransom|bitcoin|monero|pagar|pago|rescate|BTC|XMR)\b", re.I),
    "recovery_language": re.compile(r"\b(?:decrypt(?:ion|or)?|descifrar|descifrado|recuperar\s+(?:sus|tus)\s+archivos)\b", re.I),
    "educational_context": re.compile(r"\b(?:ransomware\s+awareness|training\s+example|educational\s+example|this\s+(?:document|article)\s+(?:describes|explains)|ejemplo\s+(?:educativo|de\s+capacitaci[oó]n)|simulaci[oó]n\s+did[aá]ctica)\b", re.I),
}
BARE_TLDS = frozenset({"com", "net", "org", "io", "ru", "onion", "xyz", "top", "info", "online", "test", "invalid", "example"})
COMPARABLE = frozenset({"email", "url", "domain", "cryptographic_reference", "ransomware_label", "victim_identifier", "file_extension"})


def _domain(value: str) -> bool:
    if len(value) > 253 or not re.fullmatch(DOMAIN_TEXT, value):
        return False
    return all(not label.startswith("-") and not label.endswith("-") for label in value.split("."))


def identify_format(sample: bytes, *, truncated: bool) -> tuple[dict, str | None]:
    signatures = [(b"\x7fELF", "ELF", "application/x-elf"), (b"%PDF-", "PDF", "application/pdf"),
                  (b"PK\x03\x04", "ZIP", "application/zip"), (b"PK\x05\x06", "ZIP", "application/zip"),
                  (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE compound", "application/x-ole-storage"),
                  (b"\x89PNG\r\n\x1a\n", "PNG", "image/png"), (b"\xff\xd8\xff", "JPEG", "image/jpeg"),
                  (b"GIF87a", "GIF", "image/gif"), (b"GIF89a", "GIF", "image/gif")]
    if not sample:
        return {"format": "empty", "mime_hint": "application/x-empty", "basis": "zero_bytes"}, ""
    if sample.startswith(b"MZ"):
        offset = int.from_bytes(sample[60:64], "little") if len(sample) >= 64 else -1
        pe = offset >= 64 and sample[offset:offset + 4] == b"PE\0\0"
        return {"format": "PE" if pe else "MZ/DOS candidate", "mime_hint": "application/x-dosexec", "basis": "header_signature_only"}, None
    for signature, name, mime in signatures:
        if sample.startswith(signature):
            return {"format": name, "mime_hint": mime, "basis": "header_signature_only"}, None
    encoding = "utf-8"
    for bom, enc in ((codecs.BOM_UTF32_LE, "utf-32"), (codecs.BOM_UTF32_BE, "utf-32"),
                     (codecs.BOM_UTF16_LE, "utf-16"), (codecs.BOM_UTF16_BE, "utf-16"), (codecs.BOM_UTF8, "utf-8-sig")):
        if sample.startswith(bom):
            encoding = enc
            break
    try:
        decoded = codecs.getincrementaldecoder(encoding)(errors="strict").decode(sample, final=not truncated)
    except UnicodeError:
        return {"format": "unknown binary", "mime_hint": "application/octet-stream", "basis": "no_supported_signature_or_text_encoding"}, None
    printable = sum(c.isprintable() or c in "\r\n\t" for c in decoded)
    if "\0" in decoded or printable / max(1, len(decoded)) < 0.95:
        return {"format": "unknown binary", "mime_hint": "application/octet-stream", "basis": "non_text_content"}, None
    stripped = decoded.lstrip().lower()
    name, mime = "text", "text/plain"
    if stripped.startswith(("<!doctype html", "<html")):
        name, mime = "HTML-like text", "text/html"
    elif stripped.startswith("<?xml"):
        name, mime = "XML-like text", "application/xml"
    elif stripped.startswith("{\\rtf"):
        name, mime = "RTF-like text", "application/rtf"
    return {"format": name, "mime_hint": mime, "encoding": encoding, "basis": "bounded_text_decode_no_document_execution"}, decoded


def analyze_sample(sample: bytes, *, source_item: str, copy_name: str, truncated: bool) -> dict:
    format_info, decoded = identify_format(sample, truncated=truncated)
    observations, seen, limited = [], set(), False

    def add(kind, value, *, normalized=None, origin="sample_text", start=None, end=None):
        nonlocal limited
        normalized = value if normalized is None else normalized
        key = (kind, normalized, origin)
        if key in seen:
            return None
        if len(observations) >= MAX_FINDINGS:
            limited = True
            return None
        seen.add(key)
        finding = {"classification": "observation", "kind": kind, "value": value,
                   "normalized": normalized, "origin": origin, "maliciousness": "not_established"}
        if start is not None:
            finding["span"] = {"start": start, "end": end, "unit": "decoded_character", "sample_offset_bytes": 0}
        finding["id"] = "obs-" + digest(finding)[:20]
        observations.append(finding)
        return finding["id"]

    for origin, name in (("source_name", source_item.replace("\\", "/").rsplit("/", 1)[-1]), ("copy_name", copy_name)):
        for extension in PurePosixPath(name).suffixes[-4:]:
            add("file_extension", extension, normalized=extension.casefold(), origin=origin)
    signal_ids = {}
    if decoded is not None:
        for name, pattern in SIGNALS.items():
            match = pattern.search(decoded)
            if match:
                signal_ids[name] = add("ransom_note_signal", match.group(), normalized=name, start=match.start(), end=match.end())
        for pattern, kind, group in ((EMAIL, "email", 1), (URL, "url", 0), (CRYPTO, "cryptographic_reference", 0),
                                     (LABEL, "ransomware_label", 1), (FAMILIES, "ransomware_label", 0), (VICTIM, "victim_identifier", 1)):
            for index, match in enumerate(pattern.finditer(decoded)):
                if index >= MAX_FINDINGS:
                    limited = True
                    break
                value = match.group(group).rstrip(".,;)]}") if kind == "url" else match.group(group)
                normalized = value
                if kind == "email":
                    local, domain = value.rsplit("@", 1)
                    if not _domain(domain):
                        continue
                    normalized = local + "@" + domain.lower()
                elif kind == "url":
                    normalized = re.sub(r"^hxxp", "http", value, flags=re.I)
                elif kind in ("cryptographic_reference", "ransomware_label"):
                    normalized = value.casefold().replace("_", "-").replace(" ", "-")
                add(kind, value, normalized=normalized, start=match.start(group), end=match.start(group) + len(value))
        # Bare domains are lexical candidates, never resolved or reputation-checked.
        for index, match in enumerate(DOMAIN.finditer(decoded)):
            if index >= MAX_FINDINGS:
                limited = True
                break
            value = match.group()
            if _domain(value) and value.rsplit(".", 1)[-1].lower() in BARE_TLDS:
                add("domain", value, normalized=value.lower(), start=match.start(), end=match.end())
        for finding in list(observations):
            value = finding["value"]
            if finding["kind"] == "email":
                host = value.rsplit("@", 1)[-1]
                offset = value.rfind("@") + 1
            elif finding["kind"] == "url":
                authority = value.split("://", 1)[-1].split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
                host = authority.rsplit("@", 1)[-1].split(":", 1)[0]
                offset = value.find("://") + 3 + authority.rfind(host)
            else:
                continue
            if _domain(host):
                start = finding["span"]["start"] + offset
                add("domain", host, normalized=host.lower(), start=start, end=start + len(host))

    contact = [f["id"] for f in observations if f["kind"] in ("email", "url")]
    strong = "encrypted_files_claim" in signal_ids and "payment_demand_language" in signal_ids and (bool(contact) or "recovery_language" in signal_ids)
    educational = "educational_context" in signal_ids
    candidate = bool(strong and not educational)
    status = "possible_ransom_note" if candidate else "inconclusive_educational_context" if strong and educational else "no_candidate_in_analyzed_sample"
    support = [value for key, value in signal_ids.items() if key != "educational_context" and value] + contact
    hypotheses = []
    if strong:
        hypotheses.append({"kind": "possible_ransom_note", "state": "supported_not_confirmed" if candidate else "inconclusive",
                           "supported_by": support, "counterevidence": [signal_ids["educational_context"]] if educational else [],
                           "requires": "Revisión humana, contexto y correlación con otras fuentes; el texto puede ser imitado."})
    return {"analyzer": {"name": "Ransomware Artifact Analyzer", "version": ANALYZER_VERSION},
            "format": format_info, "observations": observations, "hypotheses": hypotheses,
            "ransom_note_assessment": {"status": status, "candidate": candidate, "confirmed": False},
            "confirmed_variant": None, "cryptographic_implementation_confirmed": False,
            "coverage": {"sample_bytes": len(sample), "sample_truncated": truncated, "text_decoded": decoded is not None,
                         "findings_truncated": limited, "occurrences": "first per normalized value and origin",
                         "max_findings": MAX_FINDINGS},
            "handling": {"untrusted_input": True, "network_used": False, "sample_executed": False,
                         "remote_disclosure_authorized": False},
            "limits": ["Formatos por firma o decodificación limitada, sin validar documentos completos.",
                       "Indicadores observados no prueban malicia, familia, algoritmo usado ni acceso inicial.",
                       "Sin extracción de archivos de contenedores, OCR, análisis dinámico ni descifrado.",
                       "Solo se buscan indicadores en el prefijo de texto; ausencia no prueba ausencia en todo el archivo."]}


def compare_results(left: dict, right: dict) -> dict:
    def index(result):
        values = {}
        for finding in result["observations"]:
            if finding["kind"] in COMPARABLE:
                values.setdefault((finding["kind"], finding["normalized"]), []).append(finding["id"])
        return values
    a, b = index(left), index(right)

    def items(keys):
        return [{"kind": key[0], "normalized": key[1], "left_observations": a.get(key, []), "right_observations": b.get(key, [])}
                for key in sorted(keys)]
    return {"common": items(a.keys() & b.keys()), "left_only": items(a.keys() - b.keys()),
            "right_only": items(b.keys() - a.keys()), "classification": "comparison_of_observations",
            "limit": "Coincidencias lexicales entre resultados guardados no prueban atribución ni que los archivos actuales conserven integridad."}
