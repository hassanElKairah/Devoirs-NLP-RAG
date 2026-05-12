from __future__ import annotations

import math
import re
from collections import Counter
from typing import Dict, Iterable, List


def tokenize(text: str) -> List[str]:
    return re.findall(r"[a-zA-Z0-9_.$:-]+", str(text).lower())


def jaccard(a: str, b: str) -> float:
    sa, sb = set(tokenize(a)), set(tokenize(b))
    if not sa and not sb:
        return 1.0
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)


def valid_snort_syntax(rule: str) -> bool:
    rule = str(rule).strip()
    if not rule.startswith("alert "):
        return False
    if "(" not in rule or ")" not in rule:
        return False
    required = ["msg:", "sid:", "rev:"]
    return all(x in rule for x in required)


def precision_at_k(retrieved_ids: List[str], expected_id: str, k: int = 3) -> float:
    if k <= 0:
        return 0.0
    return 1.0 / k if expected_id in retrieved_ids[:k] else 0.0


def recall_at_k(retrieved_ids: List[str], expected_id: str, k: int = 3) -> float:
    return 1.0 if expected_id in retrieved_ids[:k] else 0.0


def reciprocal_rank(retrieved_ids: List[str], expected_id: str) -> float:
    for i, doc_id in enumerate(retrieved_ids, start=1):
        if doc_id == expected_id:
            return 1.0 / i
    return 0.0


def ndcg_at_k(retrieved_ids: List[str], expected_id: str, k: int = 5) -> float:
    for i, doc_id in enumerate(retrieved_ids[:k], start=1):
        if doc_id == expected_id:
            return 1.0 / math.log2(i + 1)
    return 0.0


def evaluate_prediction(pred: Dict, expected: Dict, k: int = 5) -> Dict[str, float]:
    retrieved_ids = pred.get("retrieved_ids", []) or []
    expected_id = expected["expected_doc_id"]
    rule = pred.get("generated_rule", "")
    expected_rule = expected.get("expected_rule", "")
    family_ok = float(pred.get("attack_family") == expected.get("expected_attack_family"))
    type_ok = float(pred.get("attack_type") == expected.get("expected_attack_type"))
    protocol_ok = float(str(pred.get("protocol")) == str(expected.get("expected_protocol")))
    port_ok = float(str(pred.get("destination_port")) == str(expected.get("expected_destination_port")))
    syntax_ok = float(valid_snort_syntax(rule))
    supported = float(bool(retrieved_ids))
    # Proxy: hallucination risk is high when the generated answer is not grounded
    # (no retrieved evidence), has invalid syntax, or predicts the wrong family.
    hallucination_flag = float((not syntax_ok) or (not supported) or family_ok == 0.0)
    return {
        "precision_at_3": precision_at_k(retrieved_ids, expected_id, 3),
        "recall_at_3": recall_at_k(retrieved_ids, expected_id, 3),
        "recall_at_5": recall_at_k(retrieved_ids, expected_id, 5),
        "mrr": reciprocal_rank(retrieved_ids, expected_id),
        "ndcg_at_5": ndcg_at_k(retrieved_ids, expected_id, 5),
        "family_accuracy": family_ok,
        "type_accuracy": type_ok,
        "protocol_accuracy": protocol_ok,
        "port_accuracy": port_ok,
        "snort_syntax_valid": syntax_ok,
        "rule_token_jaccard": jaccard(rule, expected_rule),
        "hallucination_flag": hallucination_flag,
    }
