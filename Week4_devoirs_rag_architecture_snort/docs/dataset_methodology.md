# Méthodologie de construction du dataset

## Objectif

Construire une base de connaissances personnelle pour un système RAG capable de générer des règles SNORT à partir d'une description d'attaque réseau.

## Source des données

Le dataset n'est pas téléchargé depuis Kaggle, GitHub ou une base publique prête à l'emploi. Il est généré à partir de modèles manuels conçus pour représenter des scénarios réalistes de cybersécurité.

## Méthode

1. Définition manuelle des familles d'attaques : reconnaissance, DoS/DDoS, attaques web, brute force, C2/malware, DNS, exploitation et violations de politique.
2. Création manuelle de templates pour : descriptions, logs, protocoles, ports, payloads et règles SNORT attendues.
3. Enrichissement synthétique contrôlé : variation du style de description, variation des ports, variation des adresses IP fictives, variation des logs et des formulations.
4. Annotation automatique : famille d'attaque, type d'attaque, protocole, port, sévérité, risque de faux positif, technique MITRE approximative et règle attendue.

## Colonnes principales

- `doc_id`
- `attack_description`
- `attack_family`
- `attack_type`
- `protocol`
- `destination_port`
- `payload_pattern`
- `log_excerpt`
- `expected_snort_rule`
- `rule_explanation`
- `severity`
- `false_positive_risk`
- `mitre_technique`
- `keywords`

## Limites

Le dataset est synthétique. Il est adapté à Devoir 3 pour comparer les architectures RAG, mais le PFM devra enrichir cette base avec plus de scénarios, de validation humaine, et éventuellement des logs internes simulés plus réalistes.
