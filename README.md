# Devoirs-NLP-RAG
# NLP RAG Project Repository

This repository contains a multi-week project on Natural Language Processing (NLP) and Retrieval-Augmented Generation (RAG) systems, focusing on Arabic language processing and the Snort knowledge base for Week 4.

---

## Project Overview

The project is structured over four weeks, each focusing on different aspects of NLP and RAG architectures. The goal is to build pipelines for text processing, knowledge retrieval, and generation, including experiments and evaluations.

### Objectives

* Process and analyze Arabic language datasets.
* Implement and experiment with RAG architectures.
* Evaluate RAG models on different datasets, including Snort datasets.
* Provide reproducible experiments and results.
* Offer an interactive Gradio app for easy experimentation.

### Technologies & Libraries

* Python 3.10+
* Jupyter Notebooks
* Pandas, NumPy
* PyTorch / Transformers
* Gradio for UI
* Scikit-learn (metrics and evaluation)

---

## Repository Structure

```
nlp/
├─ week1_devoir/
│  └─ nlp_pipeline_arabic.ipynb
├─ week2_devoir/
│  └─ Week2 Devoir_code_de_la_route_1.ipynb
├─ Week3_RAG_nlp/
│  ├─ Devoir 2 RAG nlp & devoir 1.ipynb
│  └─ export_final.csv
├─ Week4_devoirs_rag_architecture_snort/
│  ├─ app_gradio.py
│  ├─ README.md
│  ├─ requirements.txt
│  ├─ data/
│  │  ├─ dataset_metadata.json
│  │  ├─ snort_knowledge_base.csv
│  │  ├─ snort_knowledge_base.json
│  │  ├─ snort_test_queries.csv
│  │  └─ snort_test_queries.json
│  ├─ docs/
│  │  ├─ dataset_methodology.md
│  │  └─ rapport_devoir3.md
│  ├─ notebooks/
│  │  └─ devoir3_snort_rag_comparison.ipynb
│  ├─ outputs/
│  │  ├─ comparison_summary.csv
│  │  ├─ detailed_results.csv
│  │  ├─ predictions.json
│  │  └─ tsne_embeddings.png
│  └─ src/
│     ├─ data_generator.py
│     ├─ metrics.py
│     ├─ rag_snort.py
│     ├─ run_experiment.py
│     └─ __init__.py
```

### Folder Details

* **week1_devoir/** : Arabic NLP pipeline experiments.
* **week2_devoir/** : Devoir on route coding and NLP processing.
* **Week3_RAG_nlp/** : Experiments with RAG for NLP tasks.
* **Week4_devoirs_rag_architecture_snort/** : Snort-based RAG architecture, full pipeline, Gradio app, notebooks, data, outputs.

---

## Installation

1. Clone the repository:

```bash
git clone <repository_url>
cd nlp/Week4_devoirs_rag_architecture_snort
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. (Optional) If using notebooks, ensure Jupyter is installed:

```bash
pip install jupyter
```

---

## Usage

### Running the Gradio App

```bash
python app_gradio.py
```

* This will launch a local Gradio interface.
* You can interact with the RAG model and test queries.

### Running Notebooks

* Navigate to the week folder, e.g. `week1_devoir` or `Week3_RAG_nlp`.
* Launch Jupyter Notebook:

```bash
jupyter notebook
```

* Open the desired `.ipynb` file and run cells sequentially.

### Running Experiments (Week 4)

```bash
python src/run_experiment.py --config config.yaml
```

* Generates outputs in `outputs/`.
* Computes metrics using `src/metrics.py`.

---

## Data

The `data/` folder contains:

* `dataset_metadata.json` : Metadata describing datasets.
* `snort_knowledge_base.csv/json` : Knowledge base for Snort RAG experiments.
* `snort_test_queries.csv/json` : Test queries for evaluation.

### Outputs

* `outputs/comparison_summary.csv` : Summary of experiment results.
* `outputs/detailed_results.csv` : Detailed predictions.
* `outputs/predictions.json` : Model predictions.
* `outputs/tsne_embeddings.png` : Visualization of embeddings.

---

## Documentation

The `docs/` folder contains:

* `dataset_methodology.md` : Description of datasets and methodology.
* `rapport_devoir3.md` : Report on Snort RAG experiments.

---

## Contributing

* Please create an issue before submitting a PR.
* Follow PEP8 guidelines.
* Ensure notebooks run sequentially without errors.

---

## License

This project is licensed under the MIT License.

---

## Contact

For questions, contact: [hassanElKairah@example.com](mailto:hassanElKairah@example.com)
