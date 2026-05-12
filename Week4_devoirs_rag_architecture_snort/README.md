# Devoir 3 — Implémentation et comparaison des architectures RAG

**Sujet choisi : Génération de règles SNORT**

## Structure

```text
devoir3_snort_rag/

├── data/
│   ├── snort_knowledge_base.csv
│   ├── snort_knowledge_base.json
│   ├── snort_test_queries.csv
│   ├── snort_test_queries.json
│   └── dataset_metadata.json
├── docs/
│   ├── rapport_devoir3.md

│   └── dataset_methodology.md
├── notebooks/
│   └── devoir3_snort_rag_comparison.ipynb
├── outputs/
│   ├── comparison_summary.csv
│   ├── detailed_results.csv
│   ├── predictions.json
│   └── tsne_embeddings.png
├── src/
│   ├── data_generator.py
│   ├── metrics.py
│   ├── rag_snort.py
│   └── run_experiment.py
├── app_gradio.py
└── requirements.txt
```

## Quick start

```bash
pip install -r requirements.txt
python -m src.run_experiment
jupyter notebook notebooks/devoir3_snort_rag_comparison.ipynb
```

To run the interface:

```bash
python app_gradio.py
```

