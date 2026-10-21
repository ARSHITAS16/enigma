"""
Cryptographically Secure Password & Passphrase Generator for ENIGMA
Uses Python's `secrets` module (CSPRNG via os.urandom) to generate high-entropy credentials.

Local-first: Generated credentials are created in-memory only and never persisted or transmitted.
"""

from __future__ import annotations

import secrets
import string
from typing import List

# Memorable wordlist for Diceware-style passphrase generation (EFF-inspired)
_PASSPHRASE_WORDS = [
    "abandon", "ability", "absorb", "abstract", "academy", "accent", "acoustic", "acquire",
    "across", "action", "active", "actor", "adapt", "address", "advance", "aerobic",
    "affair", "afford", "afraid", "agency", "agent", "agile", "agree", "ahead",
    "airport", "alarm", "album", "alert", "alien", "alpha", "alpine", "alps",
    "always", "amateur", "amazing", "amber", "ambient", "amend", "among", "amount",
    "amused", "anchor", "ancient", "angel", "anger", "animal", "annual", "answer",
    "antenna", "antique", "anvil", "apology", "apple", "approve", "apron", "arch",
    "arctic", "arena", "argon", "armor", "arrow", "artist", "aspect", "assault",
    "asset", "assist", "assume", "asteroid", "athlete", "atlas", "atom", "attack",
    "attend", "attitude", "attract", "auction", "audit", "august", "author", "auto",
    "autumn", "average", "avocado", "avoid", "awake", "aware", "awesome", "axis",
    "badge", "baggage", "balance", "balcony", "ballot", "bamboo", "banana", "banner",
    "baron", "barrel", "barrier", "basalt", "basic", "basket", "battery", "battle",
    "beacon", "beauty", "behavior", "belief", "belong", "benefit", "best", "beyond",
    "bicycle", "biology", "bison", "bitter", "bizarre", "blade", "blanket", "blast",
    "blender", "blessing", "blind", "blizzard", "block", "blossom", "bonus", "booster",
    "border", "bounce", "boundary", "bracket", "brave", "breeze", "brick", "bridge",
    "brief", "bright", "brisk", "bronze", "bubble", "budget", "buffalo", "build",
    "bulletin", "bundle", "bunker", "burst", "cabin", "cable", "cactus", "cage",
    "calendar", "calm", "camera", "camp", "canary", "candle", "cannon", "canyon",
    "capable", "capital", "captain", "carbon", "cardinal", "cargo", "carousel", "carpet",
    "carrier", "carrot", "cascade", "castle", "catalyst", "catcher", "cave", "cedar",
    "ceiling", "celery", "cement", "census", "central", "century", "cereal", "chain",
    "chamber", "champion", "change", "channel", "chaos", "chapter", "charger", "chariot",
    "charity", "charm", "chart", "chaser", "cheetah", "cherry", "chest", "chimney",
    "cipher", "circuit", "citizen", "citrus", "civic", "civil", "classic", "climate",
    "clinic", "clock", "clone", "cloth", "cloud", "clover", "cluster", "clutch",
    "coastal", "cobra", "coffee", "cohort", "collect", "colony", "column", "combine",
    "comfort", "comic", "command", "compact", "compass", "complex", "compost", "compute",
    "concept", "concert", "conduit", "conifer", "connect", "conquer", "consent", "console",
    "contact", "contour", "control", "convex", "copper", "coral", "corner", "corridor",
    "cosmos", "cottage", "courage", "courier", "cradle", "craft", "crane", "crater",
    "crayon", "creek", "crescent", "crest", "cricket", "crimson", "crisis", "critical",
    "cross", "crowd", "crucial", "cruise", "crumble", "crystal", "cube", "culture",
    "current", "curtain", "cushion", "custom", "cyclone", "cylinder", "dagger", "dairy",
    "damage", "danger", "daring", "darkness", "daybreak", "daylight", "dazzle", "december",
    "decimal", "decode", "deep", "defense", "defiant", "degree", "delta", "deluxe",
    "density", "deposit", "depth", "deputy", "desert", "design", "desk", "destiny",
    "detect", "device", "diagonal", "diagram", "diamond", "digest", "digital", "dignity",
    "dilemma", "diploma", "direct", "disco", "discover", "display", "distance", "diver",
    "diverse", "divide", "divine", "dock", "doctor", "document", "dolphin", "domain",
    "domino", "donkey", "dorm", "double", "dove", "dragon", "drain", "dramatic",
    "drift", "driver", "drone", "drum", "dryer", "duck", "dune", "duplicate",
    "duration", "dusk", "dynamic", "eagle", "early", "earth", "easel", "echo",
    "eclipse", "ecology", "economy", "edge", "editor", "educate", "effort", "elastic",
    "elbow", "elder", "electric", "element", "elephant", "elevator", "elite", "embark",
    "emblem", "emerald", "emerge", "emotion", "empire", "empower", "enact", "enclave",
    "endless", "endorse", "endure", "energy", "enforce", "engage", "engine", "enigma",
    "enhance", "enormous", "enough", "enter", "entropy", "entry", "envelope", "episode",
    "epoch", "equal", "equip", "era", "erase", "erosion", "escape", "essay",
    "essence", "estate", "eternal", "ethics", "evidence", "exact", "exceed", "excel",
    "excess", "exchange", "exhibit", "exile", "expand", "expect", "expert", "explore",
    "express", "extend", "extra", "fabric", "factor", "falcon", "fame", "fantasy",
    "fathom", "feather", "feature", "federal", "feedback", "fellow", "fence", "ferret",
    "festival", "fiber", "fiction", "field", "fierce", "filter", "final", "finance"
]


def generate_random_password(
    length: int = 16,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True
) -> str:
    """
    Generates a cryptographically strong random password using secrets.choice.
    Ensures at least one character from each selected class is included.
    """
    if length < 8:
        length = 8
    if length > 128:
        length = 128

    pools: List[str] = []
    guaranteed: List[str] = []

    if use_upper:
        pools.append(string.ascii_uppercase)
        guaranteed.append(secrets.choice(string.ascii_uppercase))
    if use_lower:
        pools.append(string.ascii_lowercase)
        guaranteed.append(secrets.choice(string.ascii_lowercase))
    if use_digits:
        pools.append(string.digits)
        guaranteed.append(secrets.choice(string.digits))
    if use_symbols:
        symbols = "!@#$%^&*()-_=+[]{}|;:,.<>?"
        pools.append(symbols)
        guaranteed.append(secrets.choice(symbols))

    # Fallback to alphanumeric if nothing selected
    if not pools:
        pools.append(string.ascii_letters + string.digits)
        guaranteed.append(secrets.choice(string.ascii_letters))

    combined_pool = "".join(pools)
    remaining_len = length - len(guaranteed)
    
    # Fill remaining positions with cryptographically chosen characters
    random_chars = [secrets.choice(combined_pool) for _ in range(remaining_len)]
    full_list = guaranteed + random_chars

    # Cryptographic Fisher-Yates shuffle
    for i in range(len(full_list) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        full_list[i], full_list[j] = full_list[j], full_list[i]

    return "".join(full_list)


def generate_passphrase(
    word_count: int = 5,
    separator: str = "-",
    capitalize_words: bool = True,
    append_number: bool = True
) -> str:
    """
    Generates an EFF-style multi-word passphrase using secrets.choice.
    Combines high entropy with human memorability.
    """
    if word_count < 3:
        word_count = 3
    if word_count > 10:
        word_count = 10

    chosen_words = [secrets.choice(_PASSPHRASE_WORDS) for _ in range(word_count)]
    if capitalize_words:
        chosen_words = [w.capitalize() for w in chosen_words]

    passphrase = separator.join(chosen_words)
    if append_number:
        # Append a cryptographically random 2-digit number (10-99)
        num = secrets.randbelow(90) + 10
        passphrase = f"{passphrase}{separator}{num}"

    return passphrase
