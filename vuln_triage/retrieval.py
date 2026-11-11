"""Nearest NVD neighbours of a report, by TF-IDF cosine similarity over a pool of NVD-scored CVEs.

The pool (evals/pool.jsonl.gz) holds CVEs published in 2022, before both eval windows. Retrieval is
local and deterministic: no embeddings API, no extra model calls.
"""

import gzip
import json
import math
import re
from collections import Counter
from functools import cache
from pathlib import Path

POOL_PATH = Path(__file__).parent.parent / "evals" / "pool.jsonl.gz"
TOKEN = re.compile(r"[a-z][a-z0-9_+-]{1,}")
STOPWORDS = {"the", "a", "an", "of", "in", "to", "and", "or", "for", "via", "with", "by", "on", "is", "are"}
STOPWORDS |= {"be", "this", "that", "from", "as", "it", "its", "which"}


def tokens(text: str) -> list[str]:
    return [t for t in TOKEN.findall(text.lower()) if t not in STOPWORDS]


class Index:
    def __init__(self, docs: list[dict]):
        self.docs = docs
        counts = [Counter(tokens(d["text"])) for d in docs]
        df = Counter(t for c in counts for t in c)
        self.idf = {t: math.log(len(docs) / n) for t, n in df.items()}
        self.postings: dict[str, list[tuple[int, float]]] = {}
        for i, c in enumerate(counts):
            weights = {t: (1 + math.log(n)) * self.idf[t] for t, n in c.items()}
            norm = math.sqrt(sum(w * w for w in weights.values())) or 1.0
            for t, w in weights.items():
                self.postings.setdefault(t, []).append((i, w / norm))

    def nearest(self, text: str, k: int) -> list[dict]:
        weights = {t: (1 + math.log(n)) * self.idf[t] for t, n in Counter(tokens(text)).items() if t in self.idf}
        norm = math.sqrt(sum(w * w for w in weights.values())) or 1.0
        scores: Counter[int] = Counter()
        for t, w in weights.items():
            for i, dw in self.postings[t]:
                scores[i] += w / norm * dw
        return [self.docs[i] for i, _ in scores.most_common(k)]


@cache
def pool_index(path: Path = POOL_PATH) -> Index:
    with gzip.open(path, "rt") as f:
        return Index([json.loads(line) for line in f])
