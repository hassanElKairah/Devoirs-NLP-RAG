# Rapport — Devoir 3 : Implémentation et comparaison des architectures RAG

## Sujet

Génération de règles SNORT à partir de descriptions en langage naturel de comportements réseau suspects.

## Objectif

Comparer plusieurs architectures RAG sur un même domaine applicatif : la cybersécurité et la génération de règles SNORT.

## Dataset

Le corpus est un dataset personnel synthétique structuré en CSV/JSON. Il contient des scénarios d'attaques réseau, des logs simulés, des labels, des règles SNORT attendues et des explications.

## Architectures implémentées

1. Baseline sans RAG
2. RAG classique
3. RAG avec re-ranking
4. RAG hybride dense + BM25
5. Multi-hop RAG
6. Graph RAG
7. Agentic RAG

## Métriques

- Precision@3
- Recall@3
- Recall@5
- MRR
- nDCG@5
- Accuracy de famille d'attaque
- Accuracy de type d'attaque
- Accuracy de protocole
- Accuracy de port
- Validité syntaxique SNORT
- Similarité Jaccard entre règle générée et règle attendue
- Indicateur proxy d'hallucination

## Analyse critique attendue

### Quelle architecture est la plus performante ?

En général, le RAG hybride et l'Agentic RAG sont les plus performants, car ils combinent la robustesse lexicale de BM25 avec une représentation dense locale.

### Quelle architecture est la plus robuste ?

L'Agentic RAG est le plus robuste, car il valide la règle générée et peut changer de stratégie si la requête est courte ou si le premier résultat semble faible.

### Quelle architecture est la plus adaptée au projet ?

Le RAG hybride est le meilleur choix initial pour le PFM : il est simple, interprétable et efficace pour les règles SNORT, qui contiennent beaucoup de mots-clés techniques, ports et protocoles.

### Quelle architecture produit le plus d'hallucinations ?

La baseline sans RAG est la plus risquée, car elle génère à partir d'une heuristique sans documents récupérés. Le risque est plus faible dans les architectures RAG parce que la génération est ancrée dans des exemples récupérés.

## Limites

- La génération est template-based, pas un LLM réel.
- Les données sont synthétiques.
- Les règles doivent être validées par un expert SNORT avant usage réel.
- Le PFM devra ajouter une vraie interface dashboard et une fonction d'ajout PDF.
