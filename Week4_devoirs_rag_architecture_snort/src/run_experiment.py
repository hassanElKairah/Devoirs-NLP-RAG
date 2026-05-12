from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

import pandas as pd

from src.data_generator import save_dataset
from src.metrics import evaluate_prediction
from src.rag_snort import SnortRAGEngine

ARCHITECTURES = [
    "baseline", "rag_classic", "rag_rerank", "rag_hybrid", "multi_hop", "graph_rag", "agentic_rag"
]


def run(base_dir: str | Path = ".") -> None:
    base = Path(base_dir)
    data_dir = base / "data"
    outputs_dir = base / "outputs"
    outputs_dir.mkdir(parents=True, exist_ok=True)
    if not (data_dir / "snort_knowledge_base.csv").exists():
        save_dataset(data_dir, n_rows=160, n_queries=32)
    kb = pd.read_csv(data_dir / "snort_knowledge_base.csv")
    queries = pd.read_csv(data_dir / "snort_test_queries.csv")
    engine = SnortRAGEngine(kb)
    rows = []
    predictions = []
    for _, qrow in queries.iterrows():
        expected = qrow.to_dict()
        for arch in ARCHITECTURES:
            pred = engine.run_architecture(arch, qrow["query"], k=5)
            metrics = evaluate_prediction(pred, expected, k=5)
            row = {
                "query_id": qrow["query_id"],
                "architecture": arch,
                "query": qrow["query"],
                **metrics,
                "expected_doc_id": qrow["expected_doc_id"],
                "retrieved_ids": ";".join(pred.get("retrieved_ids", [])),
                "generated_family": pred.get("attack_family"),
                "expected_family": qrow["expected_attack_family"],
                "generated_type": pred.get("attack_type"),
                "expected_type": qrow["expected_attack_type"],
                "generated_rule": pred.get("generated_rule"),
            }
            rows.append(row)
            predictions.append({
                "query_id": qrow["query_id"],
                "architecture": arch,
                **pred,
            })
    detailed = pd.DataFrame(rows)
    detailed.to_csv(outputs_dir / "detailed_results.csv", index=False)
    summary = detailed.groupby("architecture").agg({
        "precision_at_3": "mean",
        "recall_at_3": "mean",
        "recall_at_5": "mean",
        "mrr": "mean",
        "ndcg_at_5": "mean",
        "family_accuracy": "mean",
        "type_accuracy": "mean",
        "protocol_accuracy": "mean",
        "port_accuracy": "mean",
        "snort_syntax_valid": "mean",
        "rule_token_jaccard": "mean",
        "hallucination_flag": "mean",
    }).reset_index().sort_values(["recall_at_5", "family_accuracy", "rule_token_jaccard"], ascending=False)
    summary.to_csv(outputs_dir / "comparison_summary.csv", index=False)
    with open(outputs_dir / "predictions.json", "w", encoding="utf-8") as f:
        json.dump(predictions, f, indent=2, ensure_ascii=False)
    print("Saved:")
    print(outputs_dir / "detailed_results.csv")
    print(outputs_dir / "comparison_summary.csv")
    print(outputs_dir / "predictions.json")
    print(summary)


if __name__ == "__main__":
    run(Path(__file__).resolve().parents[1])
