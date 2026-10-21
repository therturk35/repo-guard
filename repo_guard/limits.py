"""Kaynak sınırları.

Neden var? Taranan içerik GÜVENİLMEZDİR. Saldırgan aşırı büyük dosya, milyonlarca
küçük dosya, zip-bomb veya sonsuz derinlikte klasör hazırlayarak tarayıcıyı
çökertmeyi/yavaşlatmayı (ya da dikkatimizi dağıtmayı) deneyebilir. Her kaynak
için bir üst sınır koyarız; sınır aşılırsa bu BİR BULGU/HATA olarak raporlanır
(sessizce geçilmez), böylece eksik tarama "temiz" gibi görünmez.
"""

from __future__ import annotations

from dataclasses import dataclass

MIB = 1024 * 1024


@dataclass(frozen=True)
class Limits:
    # --- Dosya sistemi ---
    max_file_bytes: int = 2 * MIB         # Bir dosyadan içerik analizi için okunacak en fazla bayt
    tail_bytes: int = 256 * 1024          # Büyük dosyada SONDAN da bu kadar okunur (sona yük saklama hilesine karşı)
    max_files: int = 50_000                # Taranacak en fazla dosya
    max_depth: int = 60                    # En fazla klasör derinliği
    max_total_bytes: int = 1024 * MIB      # Toplam okuma bütçesi
    max_seconds: float = 900.0             # Toplam süre sınırı (saniye)

    # --- Arşivler ---
    max_archive_depth: int = 2             # Arşiv içinde arşiv en fazla kaç kat açılır
    max_archive_members: int = 20_000      # Bir arşivde en fazla üye
    max_archive_total_bytes: int = 512 * MIB  # Bir arşivden okunacak/bildirilen en fazla açılmış boyut
    max_ratio: int = 200                   # Sıkıştırma oranı bundan büyükse "bomba" şüphesi
    ratio_min_size: int = 10 * MIB         # ...ve açılmış boyut en az bu kadarsa

    # --- Metin ---
    max_findings_per_file: int = 60        # Bir dosyadan en fazla bulgu (rapor şişmesin)
    snippet_chars: int = 180               # Rapordaki alıntı uzunluğu
