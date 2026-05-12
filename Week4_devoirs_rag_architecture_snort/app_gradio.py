from __future__ import annotations

import pandas as pd
import gradio as gr

from src.rag_snort import SnortRAGEngine

kb = pd.read_csv("data/snort_knowledge_base.csv")
engine = SnortRAGEngine(kb)


def answer(query: str, architecture: str, k: int):
    pred = engine.run_architecture(architecture, query, k=int(k))
    retrieved = "\n".join([f"- {doc_id} (score={score})" for doc_id, score in zip(pred.get("retrieved_ids", []), pred.get("retrieved_scores", []))])
    return pred["generated_rule"], pred["explanation"], retrieved, pred.get("prompt", "")

with gr.Blocks(title="SNORT RAG - Devoir 3") as demo:
    gr.Markdown("# SNORT Rule Generation with RAG - Devoir 3")
    gr.Markdown("Prototype local: no external LLM API. Retrieval + grounded template generation.")
    with gr.Row():
        query = gr.Textbox(label="Attack description", lines=4, value="Detect a TCP SYN port scan targeting a web server on port 80")
    with gr.Row():
        architecture = gr.Dropdown(
            ["baseline", "rag_classic", "rag_rerank", "rag_hybrid", "multi_hop", "graph_rag", "agentic_rag"],
            value="rag_hybrid",
            label="Architecture"
        )
        k = gr.Slider(1, 10, value=5, step=1, label="Top-k")
    btn = gr.Button("Generate")
    rule = gr.Code(label="Generated Snort rule", language="text")
    explanation = gr.Textbox(label="Explanation", lines=5)
    retrieved = gr.Textbox(label="Retrieved documents", lines=6)
    prompt = gr.Textbox(label="Constructed prompt", lines=12)
    btn.click(answer, inputs=[query, architecture, k], outputs=[rule, explanation, retrieved, prompt])

if __name__ == "__main__":
    demo.launch()
