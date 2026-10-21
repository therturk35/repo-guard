"""Kural kataloğu: Rule veri yapısı + kayıt defteri (registry).

Her kural BİLGİDİR, kod değildir: bir regex, açıklama, düzeltme önerisi ve
kendi kendini sınayan örnekler (positive/negative) içerir. Testler her kuralın
örneklerini otomatik doğrular; böylece bir regex bozulursa CI hemen yakalar.

ReDoS (regex ile servis dışı bırakma) koruması:
  * Tüm desenlerde sınırlı nicelik ({0,N}) kullanırız, iç içe `.*` yok.
  * `keywords` ön-filtresi: satırda anahtar kelime yoksa regex hiç çalışmaz (hız + güvenlik).
  * Çok uzun satırlar (bkz. scanner) parçalanarak işlenir.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from .models import Severity


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    confidence: str                     # low | medium | high
    category: str
    pattern: "re.Pattern[str]"
    why: str
    fix: str
    keywords: tuple[str, ...] = ()      # küçük harfli ön-filtre; boşsa her satıra uygulanır
    langs: Optional[frozenset] = None   # None = tüm diller; aksi halde yalnız bu dillerde
    mitre: tuple[str, ...] = ()
    positives: tuple[str, ...] = ()     # eşleşmesi GEREKEN örnekler (self-test)
    negatives: tuple[str, ...] = ()     # eşleşmemesi GEREKEN örnekler (self-test)
    multiline: bool = False             # True: tüm dosya metnine uygulanır (satır satır değil)
    secret_group: int = 0               # >0: bu yakalama grubu maskelenir (sızdırılmış sır)
    is_secret: bool = False             # sır sızıntısı kuralı mı (tehdit skorundan ayrı sayılır)


REGISTRY: dict[str, Rule] = {}


def _re(p: str, flags: int = re.IGNORECASE) -> "re.Pattern[str]":
    return re.compile(p, flags)


def add(rule_id: str, title: str, severity: Severity, confidence: str, category: str,
        pattern: str, why: str, fix: str, *, keywords=(), langs=None, mitre=(),
        positives=(), negatives=(), multiline=False, secret_group=0, is_secret=False,
        flags: int = re.IGNORECASE) -> Rule:
    """Kuralı kayda ekler. Aynı kimlik iki kez eklenemez (kopyala-yapıştır hatasını yakalar)."""
    if rule_id in REGISTRY:
        raise ValueError(f"yinelenen kural kimliği: {rule_id}")
    if confidence not in ("low", "medium", "high"):
        raise ValueError(f"{rule_id}: geçersiz confidence")
    r = Rule(
        id=rule_id, title=title, severity=severity, confidence=confidence, category=category,
        pattern=re.compile(pattern, flags), why=why, fix=fix,
        keywords=tuple(k.lower() for k in keywords),
        langs=frozenset(langs) if langs else None, mitre=tuple(mitre),
        positives=tuple(positives), negatives=tuple(negatives), multiline=multiline,
        secret_group=secret_group, is_secret=is_secret,
    )
    REGISTRY[rule_id] = r
    return r


def all_rules() -> list[Rule]:
    """Tüm kuralları yükler (modüller import edilince kendilerini kaydeder)."""
    from . import (rules_exec, rules_credentials, rules_destructive,  # noqa: F401
                   rules_persistence, rules_secrets, rules_misc)
    return list(REGISTRY.values())
