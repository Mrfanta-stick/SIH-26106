import re
import math
import spacy
from typing import Dict, List, Any
from sentence_transformers import SentenceTransformer, util

from .pattern import *
from . import extractor

# Globals
s_transformer = SentenceTransformer("all-MiniLM-L6-v2")
coercion_prototype_embeddings: Dict[str, Any] = {}
urgency_prototype_embeddings: Dict[str, Any] = {}
categories: List[str] = []

nlp = spacy.blank("en")
nlp.add_pipe("sentencizer")

# Precompute prototype embeddings
for category, examples in COERCION_PROTOTYPES.items():
    embeddings = s_transformer.encode(examples, normalize_embeddings=True)
    coercion_prototype_embeddings[category] = embeddings
    categories.append(category)

for category, examples in URGENCY_FACTOR_SEMANTICS.items():
    embeddings = s_transformer.encode(examples, normalize_embeddings=True)
    urgency_prototype_embeddings[category] = embeddings


def _split_sentences(email_text: str) -> List[str]:
    if not email_text or not email_text.strip():
        return []
    normalized = " ".join(email_text.split())
    doc = nlp(normalized)
    return [sent.text.strip() for sent in doc.sents if len(sent.text.strip()) > 3]


def _similarity_to_probability(similarities: Dict[str, Any], temperature: float = 0.3) -> Dict[str, float]:
    if not similarities:
        return {}

    scores = {}
    for category, similarity in similarities.items():
        sim = max(-1.0, min(1.0, float(similarity)))
        angular_score = 1.0 - (2.0 * math.acos(sim) / math.pi)
        scores[category] = angular_score

    max_score = max(scores.values())
    exp_scores = {
        category: math.exp((score - max_score) / temperature)
        for category, score in scores.items()
    }
    total_score = sum(exp_scores.values()) or 1.0
    return {category: score / total_score for category, score in exp_scores.items()}


def _get_sentence_embedding(email_sentences: List[str]) -> Dict[str, Any]:
    if not email_sentences:
        return {}
    embeddings = s_transformer.encode(email_sentences, normalize_embeddings=True)
    return dict(zip(email_sentences, embeddings))


def _intent_of_each_sentence(
    sentence_embeddings: Dict[str, Any],
    prototype_embeddings: Dict[str, Any] = coercion_prototype_embeddings,
) -> List[Dict[str, Dict[str, float]]]:
    results = []
    if not sentence_embeddings or not prototype_embeddings:
        return results

    for sentence, sentence_embedding in sentence_embeddings.items():
        similarities = {}
        for category, prototypes in prototype_embeddings.items():
            cosine_scores = util.cos_sim(sentence_embedding, prototypes)[0]
            similarities[category] = float(cosine_scores.max().item())

        probabilities = _similarity_to_probability(similarities)
        if not probabilities:
            results.append({sentence: {}})
            continue

        max_prob = max(probabilities.values())
        threshold = max(0.04, max_prob * 0.70)

        filtered_probabilities = {
            cat: prob for cat, prob in probabilities.items() if prob >= threshold
        }

        # Fallback to top category if all were filtered out
        if not filtered_probabilities:
            top_cat = max(probabilities, key=probabilities.get)
            filtered_probabilities = {top_cat: probabilities[top_cat]}

        results.append({sentence: filtered_probabilities})

    return results


def _aggregate_category_probabilities(
    sentence_intent_probabilities: List[Dict[str, Dict[str, float]]],
    support_threshold: float = 0.08,
    beta: float = 0.30,
    lambd: float = 0.70,
) -> Dict[str, float]:
    if not sentence_intent_probabilities:
        return {}

    aggregated_scores = {}
    for category in categories:
        probabilities = []
        for sentence_result in sentence_intent_probabilities:
            for _, category_probs in sentence_result.items():
                if category in category_probs:
                    probabilities.append(category_probs[category])

        if not probabilities:
            aggregated_scores[category] = 0.0
            continue

        p_max = max(probabilities)
        n = sum(1 for p in probabilities if p >= support_threshold)

        if n <= 1:
            final_probability = p_max
        else:
            boost = beta * (1.0 - math.exp(-lambd * (n - 1)))
            final_probability = p_max + (1.0 - p_max) * boost

        aggregated_scores[category] = min(max(final_probability, 0.0), 1.0)

    total = sum(aggregated_scores.values())
    if total == 0:
        return {cat: 0.0 for cat in aggregated_scores}

    return {cat: score / total for cat, score in aggregated_scores.items()}


def _final_intent(aggregated_probability: Dict[str, float], benign_threshold: float = 0.40) -> str:
    if not aggregated_probability:
        return "BENIGN"

    benign_prob = aggregated_probability.get("BENIGN", 0.0)
    if benign_prob >= benign_threshold:
        return "BENIGN"

    fraud_categories = {
        cat: prob for cat, prob in aggregated_probability.items() if cat != "BENIGN"
    }
    if not fraud_categories:
        return "BENIGN"

    return max(fraud_categories, key=fraud_categories.get)


def _find_coercion_cues(category: str, sentence_intent_probabilities: List[Dict[str, Dict[str, float]]]) -> List[str]:
    if category == "BENIGN":
        return []
    cues = []
    for sentence_result in sentence_intent_probabilities:
        for sentence, category_probabilities in sentence_result.items():
            if category in category_probabilities and sentence not in cues:
                cues.append(sentence)
    return cues


def _urgency_score_calculation(
    sentence_embeddings: Dict[str, Any],
    email_text: str,
    urgency_prototype_embeddings: Dict[str, Any] = urgency_prototype_embeddings,
    urgency_weight: Dict[str, float] = URGENCY_WEIGHTS,
    semantic_threshold: float = 0.45,
) -> float:
    if not sentence_embeddings:
        return 0.0

    urgency_semantic_scores = {k: 0.0 for k in urgency_weight}

    # 1. Semantic evaluation across all sentences (peak retention)
    for _, sentence_embedding in sentence_embeddings.items():
        for category, urgency_embeddings in urgency_prototype_embeddings.items():
            similarities = util.cos_sim(sentence_embedding, urgency_embeddings)[0]
            max_sim = float(similarities.max())
            if max_sim >= semantic_threshold:
                prev = urgency_semantic_scores[category]
                urgency_semantic_scores[category] = max(prev, max_sim)

    semantic_component = sum(
        urgency_semantic_scores[cat] * urgency_weight.get(cat, 0.0)
        for cat in urgency_semantic_scores
    )

    # 2. Regex pattern evaluation
    regex_matches = 0
    for pattern in URGENCY_PATTERNS_REGEX:
        if re.search(pattern, email_text, re.IGNORECASE):
            regex_matches += 1

    regex_component = min(regex_matches * 0.25, 1.0)
    combined_urgency = (semantic_component * 0.65) + (regex_component * 0.35)
    return round(max(0.0, min(combined_urgency, 1.0)), 2)


def _get_suspicious_urls(url_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    suspicious_urls = []
    for url in url_results:
        # Check both is_redirector and legacy is_redirect
        is_redirect = url.get("is_redirector") or url.get("is_redirect")
        if (
            url.get("is_mismatch")
            or url.get("has_userinfo")
            or url.get("is_javascript")
            or url.get("is_data")
            or is_redirect
        ):
            suspicious_urls.append({
                "anchor_text": url.get("anchor_text", ""),
                "destination": url.get("destination", ""),
                "is_mismatch": bool(url.get("is_mismatch", False)),
            })
    return suspicious_urls


def _risk_score_calculation(
    number_of_suspicious_urls: int,
    has_invisible_text: bool,
    primary_intent: str,
    urgency_score: float,
    number_of_coercion_cues: int,
) -> float:
    intent_score = intent_risk.get(primary_intent, 0.0)
    url_score = min(number_of_suspicious_urls / 2.0, 1.0)
    coercion_score = min(number_of_coercion_cues / 2.0, 1.0)
    invisible_text_score = 1.0 if has_invisible_text else 0.0
    urgency_score = max(0.0, min(urgency_score, 1.0))

    risk_score = (
        (intent_score * 0.35)
        + (url_score * 0.25)
        + (urgency_score * 0.15)
        + (coercion_score * 0.15)
        + (invisible_text_score * 0.10)
    )
    return round(max(0.0, min(risk_score, 1.0)), 2)


def threat_intent(email_text: str | None, html_content: str | None = None) -> Dict[str, Any]:
    # Fallback to visible HTML text when plaintext email body is missing
    hidden_chunks: List[str] = []
    if html_content:
        visible_html_text, hidden_chunks = extractor.detect_zero_font_obfuscation(html_content)
        if not email_text or not email_text.strip():
            email_text = visible_html_text

    email_text = email_text or ""
    email_sentences = _split_sentences(email_text)
    sentence_embeddings = _get_sentence_embedding(email_sentences)
    sentences_intents = _intent_of_each_sentence(sentence_embeddings)
    aggregated_prob = _aggregate_category_probabilities(sentences_intents)

    intent = _final_intent(aggregated_prob)
    urgency_score = _urgency_score_calculation(sentence_embeddings, email_text)
    coercion_cues = _find_coercion_cues(intent, sentences_intents)

    # Append raw hidden text chunks to flagged coercion cues
    for chunk in hidden_chunks:
        if chunk not in coercion_cues:
            coercion_cues.append(chunk)

    url_results = extractor.extract_and_analyze_urls(html_content or "")
    suspicious_urls = _get_suspicious_urls(url_results)

    risk_score = _risk_score_calculation(
        len(suspicious_urls),
        len(hidden_chunks) > 0,
        intent,
        urgency_score,
        len(coercion_cues),
    )

    return {
        "primary_intent": intent,
        "risk_score": int(round(risk_score * 100)),
        "urgency_score": urgency_score,
        "flagged_coercion_cues": coercion_cues,
        "suspicious_urls": suspicious_urls,
    }
