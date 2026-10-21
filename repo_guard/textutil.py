"""Metin yardımcıları: güvenli gösterim, sır maskeleme, entropi, benzerlik.

Bu modül GÜVENLİK açısından kritiktir, çünkü raporlara taranan (saldırgan
kontrollü) metin girer. Üç tehlikeyi ele alırız:
  1) Terminal kaçış dizileri (ANSI): Kötü niyetli bir dosya, raporu terminalde
     gösterdiğimizde ekranı/başlığı manipüle eden kodlar içerebilir.
  2) Çift yönlü (bidi) ve görünmez Unicode karakterler: raporda metnin
     yanlış sırada görünmesine veya gizli kalmasına yol açar.
  3) Sızdırılmış sırlar: Raporun kendisi sır sızıntısı kaynağı olmamalıdır.
"""

from __future__ import annotations

import math
import re
from collections import Counter

# Çift yönlü kontrol karakterleri (Trojan Source, CVE-2021-42574)
BIDI_CHARS = frozenset("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")
# Sıfır genişlikli / görünmez karakterler
ZERO_WIDTH_CHARS = frozenset("\u200b\u200c\u200d\u2060\u180e\ufeff")


def _is_tag_char(ch: str) -> bool:
    """Unicode 'tag' karakterleri (U+E0000-E007F): görünmez ASCII gizlemek için kötüye kullanılır."""
    return 0xE0000 <= ord(ch) <= 0xE007F


def sanitize(text: str, max_len: int = 180) -> str:
    """Metni terminale ve HTML'e güvenle gösterilecek hale getirir.

    * Kontrol karakterleri (ESC dahil) \\xNN biçiminde GÖRÜNÜR hale getirilir.
    * Bidi / sıfır genişlikli / tag karakterleri <U+XXXX> olarak gösterilir.
    * Uzun metin kısaltılır.
    """
    out: list[str] = []
    for ch in text:
        code = ord(ch)
        if ch == "\t":
            out.append(" ")
        elif code < 0x20 or code == 0x7F or 0x80 <= code <= 0x9F:
            out.append(f"\\x{code:02x}")
        elif ch in BIDI_CHARS or ch in ZERO_WIDTH_CHARS or _is_tag_char(ch):
            out.append(f"<U+{code:04X}>")
        else:
            out.append(ch)
        if len(out) > max_len + 40:      # çok uzun girdiyi erken kes (bellek/zaman)
            break
    s = "".join(out).strip()
    if len(s) > max_len:
        s = s[: max_len - 1] + "\u2026"
    return s


def window(line: str, start: int, end: int, width: int = 180) -> str:
    """Satırın eşleşme çevresindeki bir pencereyi döndürür (uzun satırlarda tüm satırı basmayız)."""
    if len(line) <= width:
        return line
    left = max(0, start - width // 3)
    right = min(len(line), left + width)
    prefix = "\u2026" if left > 0 else ""
    suffix = "\u2026" if right < len(line) else ""
    return prefix + line[left:right] + suffix


def mask_secret(value: str) -> str:
    """Bir sırrı ASLA tam göstermeden maskeler: ilk 4 karakter + uzunluk."""
    if len(value) <= 8:
        return "****"
    return f"{value[:4]}\u2026[maskelendi, {len(value)} krk]"


def shannon_entropy(s: str) -> float:
    """Shannon entropisi (bit/karakter). Rastgele anahtarlar yüksek (~4+), sıradan kelimeler düşüktür."""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def osa_distance(a: str, b: str, max_dist: int = 2) -> int:
    """'Optimal string alignment' (Damerau-Levenshtein benzeri) uzaklığı.

    Typosquatting tespiti için: 'reqeusts' ile 'requests' arası 1 (yer değiştirme).
    max_dist aşılırsa erken çıkar ve max_dist+1 döndürür (hız için).
    """
    la, lb = len(a), len(b)
    if abs(la - lb) > max_dist:
        return max_dist + 1
    prev2 = None
    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        cur = [i] + [0] * lb
        row_min = cur[0]
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if prev2 is not None and i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)   # iki harfin yer değiştirmesi
            row_min = min(row_min, cur[j])
        if row_min > max_dist:
            return max_dist + 1
        prev2, prev = prev, cur
    return prev[lb]


_PLACEHOLDER_RE = re.compile(
    r"(?:example|sample|your|dummy|placeholder|changeme|change_me|xxxx|\*{4,}|<[^>]+>|\$\{|\{\{|todo|fake|test)",
    re.IGNORECASE,
)


def looks_like_placeholder(value: str) -> bool:
    """'YOUR_API_KEY', 'xxxx', '<token>' gibi sahte/örnek değerleri ayıklar (yanlış alarmı azaltır)."""
    return bool(_PLACEHOLDER_RE.search(value))
