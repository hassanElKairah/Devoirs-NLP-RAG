from __future__ import annotations

import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.decomposition import TruncatedSVD
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.preprocessing import normalize

try:
    import faiss  # type: ignore
    HAS_FAISS = True
except Exception:
    faiss = None
    HAS_FAISS = False


SNORT_PROTOCOLS = ["tcp", "udp", "icmp", "ip"]


def simple_tokens(text: str) -> List[str]:
    return re.findall(r"[a-zA-Z0-9_.$:-]+", str(text).lower())


@dataclass
class RetrievedDoc:
    doc_id: str
    score: float
    row: Dict


class BM25Retriever:
    def __init__(self, documents: List[str], k1: float = 1.5, b: float = 0.75):
        self.k1 = k1
        self.b = b
        self.docs_tokens = [simple_tokens(d) for d in documents]
        self.avgdl = sum(len(t) for t in self.docs_tokens) / max(len(self.docs_tokens), 1)
        self.doc_freq = {}
        for toks in self.docs_tokens:
            for tok in set(toks):
                self.doc_freq[tok] = self.doc_freq.get(tok, 0) + 1
        self.N = len(documents)
        self.idf = {tok: math.log(1 + (self.N - df + 0.5) / (df + 0.5)) for tok, df in self.doc_freq.items()}
        self.term_counts = [dict(pd.Series(toks).value_counts()) if toks else {} for toks in self.docs_tokens]

    def scores(self, query: str) -> np.ndarray:
        q_tokens = simple_tokens(query)
        scores = np.zeros(self.N, dtype=float)
        for i, doc_toks in enumerate(self.docs_tokens):
            dl = len(doc_toks) or 1
            counts = self.term_counts[i]
            score = 0.0
            for tok in q_tokens:
                if tok not in counts:
                    continue
                tf = counts[tok]
                idf = self.idf.get(tok, 0.0)
                denom = tf + self.k1 * (1 - self.b + self.b * dl / (self.avgdl or 1.0))
                score += idf * (tf * (self.k1 + 1)) / denom
            scores[i] = score
        return scores


class SnortRAGEngine:
    def __init__(self, kb: pd.DataFrame, dense_components: int = 64):
        self.kb = kb.reset_index(drop=True).copy()
        self.documents = self._build_documents(self.kb)
        self.vectorizer = TfidfVectorizer(ngram_range=(1, 2), min_df=1, max_features=12000)
        self.tfidf = self.vectorizer.fit_transform(self.documents)
        n_features = self.tfidf.shape[1]
        n_components = min(dense_components, max(2, n_features - 1), max(2, self.tfidf.shape[0] - 1))
        self.svd = TruncatedSVD(n_components=n_components, random_state=42)
        self.dense = self.svd.fit_transform(self.tfidf)
        self.dense = normalize(self.dense).astype("float32")
        self.bm25 = BM25Retriever(self.documents)
        self.graph = self._build_graph()
        self.faiss_index = None
        if HAS_FAISS:
            self.faiss_index = faiss.IndexFlatIP(self.dense.shape[1])
            self.faiss_index.add(self.dense)

    def _build_documents(self, df: pd.DataFrame) -> List[str]:
        fields = [
            "attack_description", "attack_family", "attack_type", "protocol", "destination_port",
            "service", "payload_pattern", "log_excerpt", "expected_snort_rule", "rule_explanation",
            "severity", "false_positive_risk", "mitre_technique", "keywords"
        ]
        docs = []
        for _, row in df.iterrows():
            parts = [f"{f}: {row.get(f, '')}" for f in fields]
            docs.append("\n".join(parts))
        return docs

    def _query_dense_vector(self, query: str) -> np.ndarray:
        q = self.vectorizer.transform([query])
        qd = self.svd.transform(q)
        qd = normalize(qd).astype("float32")
        return qd

    def _indices_to_docs(self, indices: Iterable[int], scores: Iterable[float]) -> List[RetrievedDoc]:
        docs = []
        for idx, score in zip(indices, scores):
            if idx < 0 or idx >= len(self.kb):
                continue
            row = self.kb.iloc[int(idx)].to_dict()
            docs.append(RetrievedDoc(doc_id=row["doc_id"], score=float(score), row=row))
        return docs

    def dense_retrieve(self, query: str, k: int = 5) -> List[RetrievedDoc]:
        qd = self._query_dense_vector(query)
        if self.faiss_index is not None:
            scores, indices = self.faiss_index.search(qd, k)
            return self._indices_to_docs(indices[0], scores[0])
        scores = cosine_similarity(qd, self.dense)[0]
        idx = np.argsort(scores)[::-1][:k]
        return self._indices_to_docs(idx, scores[idx])

    def sparse_retrieve(self, query: str, k: int = 5) -> List[RetrievedDoc]:
        q = self.vectorizer.transform([query])
        scores = cosine_similarity(q, self.tfidf)[0]
        idx = np.argsort(scores)[::-1][:k]
        return self._indices_to_docs(idx, scores[idx])

    def bm25_retrieve(self, query: str, k: int = 5) -> List[RetrievedDoc]:
        scores = self.bm25.scores(query)
        idx = np.argsort(scores)[::-1][:k]
        return self._indices_to_docs(idx, scores[idx])

    def hybrid_retrieve(self, query: str, k: int = 5, alpha: float = 0.55) -> List[RetrievedDoc]:
        qd = self._query_dense_vector(query)
        dense_scores = cosine_similarity(qd, self.dense)[0]
        bm25_scores = self.bm25.scores(query)
        # Normalize safely
        dense_norm = (dense_scores - dense_scores.min()) / (dense_scores.max() - dense_scores.min() + 1e-9)
        bm25_norm = (bm25_scores - bm25_scores.min()) / (bm25_scores.max() - bm25_scores.min() + 1e-9)
        scores = alpha * dense_norm + (1 - alpha) * bm25_norm
        idx = np.argsort(scores)[::-1][:k]
        return self._indices_to_docs(idx, scores[idx])

    def rerank(self, query: str, docs: List[RetrievedDoc], k: int = 5) -> List[RetrievedDoc]:
        q_tokens = set(simple_tokens(query))
        reranked = []
        for d in docs:
            row = d.row
            field_text = " ".join(str(row.get(c, "")) for c in ["attack_family", "attack_type", "protocol", "destination_port", "service", "keywords", "payload_pattern"])
            field_tokens = set(simple_tokens(field_text))
            overlap = len(q_tokens & field_tokens) / max(len(q_tokens), 1)
            port_bonus = 0.15 if str(row.get("destination_port")) in query else 0.0
            protocol_bonus = 0.10 if str(row.get("protocol", "")).lower() in query.lower() else 0.0
            score = 0.65 * d.score + 0.25 * overlap + port_bonus + protocol_bonus
            reranked.append(RetrievedDoc(d.doc_id, score, d.row))
        reranked.sort(key=lambda x: x.score, reverse=True)
        return reranked[:k]

    def _build_graph(self) -> Dict[str, set]:
        graph: Dict[str, set] = {}
        for _, row in self.kb.iterrows():
            doc = row["doc_id"]
            nodes = [
                f"family:{row['attack_family']}",
                f"type:{row['attack_type']}",
                f"protocol:{row['protocol']}",
                f"port:{row['destination_port']}",
                f"severity:{row['severity']}",
            ] + [f"kw:{k.strip()}" for k in str(row["keywords"]).split(",")]
            graph.setdefault(doc, set()).update(nodes)
            for n in nodes:
                graph.setdefault(n, set()).add(doc)
        return graph

    def graph_expand(self, seed_docs: List[RetrievedDoc], max_docs: int = 10) -> List[RetrievedDoc]:
        candidate_ids = []
        seen = set()
        for d in seed_docs:
            for node in self.graph.get(d.doc_id, set()):
                for neighbor_doc in self.graph.get(node, set()):
                    if neighbor_doc not in seen:
                        seen.add(neighbor_doc)
                        candidate_ids.append(neighbor_doc)
        rows = []
        for doc_id in candidate_ids[:max_docs]:
            row = self.kb[self.kb["doc_id"] == doc_id].iloc[0].to_dict()
            rows.append(RetrievedDoc(doc_id, 0.5, row))
        return rows

    def construct_prompt(self, query: str, docs: List[RetrievedDoc]) -> str:
        context = []
        for i, d in enumerate(docs, start=1):
            r = d.row
            context.append(
                f"[DOC {i} | {r['doc_id']} | score={d.score:.3f}]\n"
                f"Description: {r['attack_description']}\n"
                f"Family: {r['attack_family']} | Type: {r['attack_type']} | Protocol: {r['protocol']} | Port: {r['destination_port']}\n"
                f"Log: {r['log_excerpt']}\n"
                f"Rule: {r['expected_snort_rule']}\n"
                f"Explanation: {r['rule_explanation']}"
            )
        return (
            "You are a defensive cybersecurity assistant. Generate one valid Snort rule only from the retrieved context.\n"
            "Avoid inventing unsupported ports, protocols, or payloads. Explain the rule briefly.\n\n"
            f"User query:\n{query}\n\nRetrieved context:\n" + "\n\n".join(context)
        )

    def _keyword_baseline_row(self, query: str) -> Dict:
        q = query.lower()
        # simple heuristic: choose best row based on family/type keywords
        scores = []
        for i, row in self.kb.iterrows():
            fields = f"{row['attack_family']} {row['attack_type']} {row['keywords']} {row['payload_pattern']} {row['service']} {row['destination_port']}".lower()
            score = sum(1 for tok in set(simple_tokens(q)) if tok in fields)
            scores.append(score)
        best_idx = int(np.argmax(scores))
        return self.kb.iloc[best_idx].to_dict()

    def generate_from_docs(self, query: str, docs: List[RetrievedDoc], architecture: str) -> Dict:
        if docs:
            top = docs[0].row
            confidence = float(max(0.0, min(1.0, docs[0].score)))
        else:
            top = self._keyword_baseline_row(query)
            confidence = 0.25
        rule = top["expected_snort_rule"]
        explanation = (
            f"Architecture: {architecture}. The answer is grounded in document {top['doc_id']} "
            f"because it matches the requested behavior: {top['attack_type']} / {top['attack_family']}. "
            f"{top['rule_explanation']}"
        )
        return {
            "architecture": architecture,
            "generated_rule": rule,
            "attack_family": top["attack_family"],
            "attack_type": top["attack_type"],
            "protocol": top["protocol"],
            "destination_port": str(top["destination_port"]),
            "explanation": explanation,
            "retrieved_ids": [d.doc_id for d in docs],
            "retrieved_scores": [round(float(d.score), 4) for d in docs],
            "prompt": self.construct_prompt(query, docs) if docs else "No retrieval used in baseline.",
            "confidence": confidence,
        }

    # Architectures required in Devoir 3
    def llm_no_rag(self, query: str) -> Dict:
        row = self._keyword_baseline_row(query)
        return {
            "architecture": "baseline_no_rag",
            "generated_rule": row["expected_snort_rule"],
            "attack_family": row["attack_family"],
            "attack_type": row["attack_type"],
            "protocol": row["protocol"],
            "destination_port": str(row["destination_port"]),
            "explanation": "Baseline without retrieval: simple keyword heuristic, higher hallucination risk.",
            "retrieved_ids": [],
            "retrieved_scores": [],
            "prompt": "No retrieval. Query only.",
            "confidence": 0.25,
        }

    def rag_classic(self, query: str, k: int = 5) -> Dict:
        docs = self.dense_retrieve(query, k=k)
        return self.generate_from_docs(query, docs, "rag_classic")

    def rag_rerank(self, query: str, k: int = 5) -> Dict:
        docs = self.dense_retrieve(query, k=12)
        docs = self.rerank(query, docs, k=k)
        return self.generate_from_docs(query, docs, "rag_rerank")

    def rag_hybrid(self, query: str, k: int = 5) -> Dict:
        docs = self.hybrid_retrieve(query, k=k)
        return self.generate_from_docs(query, docs, "rag_hybrid")

    def multi_hop_rag(self, query: str, k: int = 5) -> Dict:
        first_docs = self.hybrid_retrieve(query, k=3)
        if first_docs:
            seed = first_docs[0].row
            reformulated = f"{query} attack_family {seed['attack_family']} attack_type {seed['attack_type']} protocol {seed['protocol']} port {seed['destination_port']} keywords {seed['keywords']}"
        else:
            reformulated = query
        second_docs = self.hybrid_retrieve(reformulated, k=k)
        pred = self.generate_from_docs(query, second_docs, "multi_hop_rag")
        pred["reformulated_query"] = reformulated
        return pred

    def graph_rag(self, query: str, k: int = 5) -> Dict:
        seed_docs = self.hybrid_retrieve(query, k=3)
        expanded_docs = self.graph_expand(seed_docs, max_docs=20)
        # rerank all seed + graph-expanded docs
        combined = {d.doc_id: d for d in seed_docs + expanded_docs}
        reranked = self.rerank(query, list(combined.values()), k=k)
        pred = self.generate_from_docs(query, reranked, "graph_rag")
        pred["graph_expanded_count"] = len(expanded_docs)
        return pred

    def agentic_rag(self, query: str, k: int = 5) -> Dict:
        # Decision: if query is too short, enrich through multi-hop; otherwise hybrid -> validate -> fallback to rerank.
        if len(simple_tokens(query)) < 8:
            pred = self.multi_hop_rag(query, k=k)
            pred["architecture"] = "agentic_rag"
            pred["agent_decision"] = "query_too_short -> multi_hop"
            return pred
        pred = self.rag_hybrid(query, k=k)
        pred["architecture"] = "agentic_rag"
        valid = self._validate_rule(pred["generated_rule"])
        if not valid:
            pred = self.rag_rerank(query, k=k)
            pred["architecture"] = "agentic_rag"
            pred["agent_decision"] = "hybrid_invalid -> rerank_retry"
        else:
            pred["agent_decision"] = "hybrid_valid"
        return pred

    def _validate_rule(self, rule: str) -> bool:
        rule = str(rule)
        return rule.startswith("alert ") and "sid:" in rule and "rev:" in rule and "msg:" in rule and "(" in rule and ")" in rule

    def run_architecture(self, name: str, query: str, k: int = 5) -> Dict:
        if name == "baseline":
            return self.llm_no_rag(query)
        if name == "rag_classic":
            return self.rag_classic(query, k)
        if name == "rag_rerank":
            return self.rag_rerank(query, k)
        if name == "rag_hybrid":
            return self.rag_hybrid(query, k)
        if name == "multi_hop":
            return self.multi_hop_rag(query, k)
        if name == "graph_rag":
            return self.graph_rag(query, k)
        if name == "agentic_rag":
            return self.agentic_rag(query, k)
        raise ValueError(f"Unknown architecture: {name}")
