"""
Email Threat Intent Analysis Module.

This module analyzes email content to identify potential scam or coercion
intent and calculate an overall risk score.

Pipeline:
1. Split the email into sentences.
2. Generate semantic embeddings for each sentence.
3. Compare sentences with scam category prototypes.
4. Convert similarity scores into category probabilities.
5. Aggregate sentence-level probabilities.
6. Determine the primary threat intent.
7. Calculate the urgency score.
8. Find sentences supporting the detected intent.
9. Extract and analyze URLs from HTML content.
10. Detect suspicious URLs and invisible text.
11. Combine all indicators into a final risk score.

The main entry point is threat_intent(), which returns the detected intent,
risk score, urgency score, coercion cues, and suspicious URLs.
"""
import re
import math
import spacy
from typing import Dict, List, Any
from sentence_transformers import SentenceTransformer, util

import pattern
import extractor

# globals
s_transfromer = SentenceTransformer("all-MiniLM-L6-v2")
coercion_prototype_embeddings = {}
urgency_prototype_embeddings = []
categories = []

nlp = spacy.blank("en")          # to be used for spliting email into sentences
nlp.add_pipe("sentencizer")


# basic initialisation
for category, examples in pattern.COERCION_PROTOTYPES.items():
    embeddings = s_transfromer.encode(examples, normalize_embeddings=True)
    coercion_prototype_embeddings[category] = embeddings
    categories.append(category)

for urgency_pattern in pattern.URGENCY_PATTERNS_SEMANTIC:
    urgency_prototype_embeddings.append(s_transfromer.encode(urgency_pattern, normalize_embeddings=True))


# helper functions
def _split_sentences(email_text: str) -> list[str]:
    """
    Split email text into individual sentences
    uses en_core_web_sm model
    """
    if not email_text or not email_text.strip():
        return []

    # Normalize line endings
    email_text = " ".join(email_text.split())

    doc = nlp(email_text)
    return [sent.text.strip() for sent in doc.sents if sent.text.strip()]


def _similarity_to_probability(similarities: Dict[str, Any], temperature: float = 0.3) -> Dict[str, float]:
    """
    Convert cosine similarities into probabilities using
    temperature-scaled softmax.

    Pipeline:
        cosine similarity
            ↓
        angular similarity transformation
            ↓
        temperature-scaled exponential
            ↓
        normalization

    NOTE:
        1) Similarities must be in range [0, 1].
        2) Lower temperature produces sharper probability
           differences between categories.
    """

    if temperature <= 0:
        raise ValueError("temperature must be greater than 0")

    scores = {}
    for category, similarity in similarities.items():
        angular_score = 1- (2 * math.acos(similarity) / math.pi)
        scores[category] = angular_score

    # Numerically stable softmax
    max_score = max(scores.values())
    exp_scores = {
        category: math.exp((score - max_score) / temperature)
        for category, score in scores.items()
    }

    total_score = sum(exp_scores.values())
    probabilities = {
        category: score / total_score
        for category, score in exp_scores.items()
    }

    return probabilities


def _get_sentence_embedding(email_sentences: List[str]) -> Dict[str, Any]:
    """
    calculate embedding of sentences in email and cache them
    """

    if not email_sentences:
        return {}

    embeddings = s_transfromer.encode(email_sentences, normalize_embeddings= True)
    sentence_embeddings = {
        sentence : embedding
        for sentence, embedding in zip(email_sentences, embeddings)
    }

    return sentence_embeddings


def _intent_of_each_sentence(sentence_embeddings: Dict[str, Any],
                             prototype_embeddings: Dict[str, Any] = coercion_prototype_embeddings) -> List[Dict[str, Dict[str, float]]]:
    """
    Determine the top 3 intent/coercion categories of each sentence.

    For each sentence:
        1. Calculate cosine similarity with every prototype
           belonging to every category.
        2. For each category, keep the highest similarity.
        3. Convert the category similarities into probabilities.
        4. Select the 3 categories with the highest probabilities.

    Returns:
        [
            {
                "sentence text": {
                    "CREDENTIAL_PHISHING": 0.42,
                    "ACCOUNT_TAKEOVER": 0.20,
                    "PAYMENT_FRAUD": 0.15
                }
            },
            ...
        ]

    Only the top 3 most likely categories are returned for each sentence.
    """
    results = []
    if not sentence_embeddings or not prototype_embeddings:
        return results

    for sentence, sentence_embedding in sentence_embeddings.items():
        similarities = {}
        # Compare this sentence with every scam/coercion category
        for category, prototypes in prototype_embeddings.items():
            if prototypes is None or len(prototypes) == 0:
                continue
            cosine_scores = util.cos_sim(sentence_embedding, prototypes)[0]
            max_similarity = float(cosine_scores.max().item())
            similarities[category] = max_similarity

        # Convert similarity scores into probabilities
        probabilities = _similarity_to_probability(similarities)

        max_probability = max(probabilities.values())

        absolute_threshold = 0.04
        relative_threshold = max_probability * 0.80
        threshold = max(absolute_threshold, relative_threshold)

        filtered_probabilities = {
            category: probability
            for category, probability in probabilities.items()
            if probability >= threshold
        }

        results.append({
            sentence: filtered_probabilities
        })

    return results


def _aggregate_category_probabilities(sentence_intent_probabilities: List[Dict[str, Dict[str, float]]],
                                      support_threshold: float = 0.08,
                                      beta: float = 0.30,
                                      lambd: float = 0.70) -> Dict[str, float]:
    """
    Aggregate sentence-level category probabilities into one probability
    for each category.

    Formula:
        P_final = P_max + (1 - P_max) * beta * (1 - exp(-lambda * (n - 1)))

    where:
        P_max = highest probability assigned to the category by any sentence
        n     = number of sentences with probability >= support_threshold

    The resulting category scores are normalized so that the final
    probabilities sum to 1.

    Args:
        sentence_intent_probabilities:
            Output of _intent_of_each_sentence()

        support_threshold:
            Minimum sentence probability required to count as supporting
            evidence for a category.

        beta:
            Maximum additional boost provided by repeated evidence.

        lambd:
            Rate at which repeated evidence saturates.

    Returns:
        Dict[str, float]:
            Aggregated probability for every category.
    """

    if not sentence_intent_probabilities:
        return {}

    aggregated_scores = {}
    for category in categories:
        probabilities = []

        # Collect probability of this category from every sentence
        for sentence_result in sentence_intent_probabilities:
            for sentence, category_probs in sentence_result.items():
                if category not in category_probs:
                    continue

                probability = category_probs[category]
                probabilities.append(probability)

        if not probabilities:
            aggregated_scores[category] = 0.0
            continue

        # Strongest evidence from any sentence
        p_max = max(probabilities)

        # Number of sentences that meaningfully support this category
        n = sum(1 for probability in probabilities if probability >= support_threshold)

        if n <= 1:
            final_probability = p_max
        else:
            boost = beta * (1 - math.exp(-lambd * (n - 1)))
            final_probability = (p_max + (1 - p_max) * boost)

        # Numerical safety
        aggregated_scores[category] = min(max(final_probability, 0.0), 1.0)

    # Normalize so that the 26 category probabilities sum to 1
    total = sum(aggregated_scores.values())

    if total == 0:
        return {
            category: 0.0
            for category in aggregated_scores
        }

    return {
        category: score / total
        for category, score in aggregated_scores.items()
    }


def _final_intent(aggregated_probability: Dict[str, float], benign_threshold: float = 0.50) -> str:
    """
    Determine the final intent category.

    If BENIGN probability is greater than or equal to the threshold,
    classify the email as BENIGN.

    Otherwise, return the category with the highest probability.

    Args:
        aggregated_probability:
            Aggregated probability of every category.

        benign_threshold:
            Minimum probability required to classify the email as BENIGN.

    Returns:
        Final intent category.
    """

    if not aggregated_probability:
        return "BENIGN"

    benign_probability = aggregated_probability.get("BENIGN", 0.0)

    # Email is sufficiently likely to be benign
    if benign_probability >= benign_threshold:
        return "BENIGN"

    # Remove BENIGN and find the most likely fraud category
    fraud_categories = {
        category: probability
        for category, probability in aggregated_probability.items()
        if category != "BENIGN"
    }

    if not fraud_categories:
        return "BENIGN"

    return max(fraud_categories, key=fraud_categories.get)


def _find_coercion_cues(category: str, sentence_intent_probabilities: List[Dict[str, Dict[str, float]]]) -> List[str]:
    """
    Find all sentences where the specified category appeared
    among the top predicted categories.

    Args:
        category:
            The category to search for.

        sentence_intent_probabilities:
            Output of _intent_of_each_sentence().

    Returns:
        List of sentences where the category appeared.
    """
    if category == "BENIGN":
        return []

    coercion_cues = []
    for sentence_result in sentence_intent_probabilities:
        for sentence, category_probabilities in sentence_result.items():
            if category in category_probabilities:
                coercion_cues.append(sentence)

    return coercion_cues

def _urgency_score_calculation(sentence_embeddings: Dict[str, Any],
                               urgency_prototype_embeddings: List[Any] = urgency_prototype_embeddings,
                               semantic_threshold: float = 0.62) -> float:
    """
    Calculate the urgency score of an email using semantic and regex-based
    analysis.

    Process:
        1. Compare each sentence against urgency prototypes using cosine similarity.
        2. Ignore sentences below the semantic urgency threshold.
        3. Count regex-based urgency cues in semantically urgent sentences.
        4. Weight cue counts by their semantic similarity.
        5. Accumulate weighted cues from all sentences.
        6. Normalize the result to a score between 0 and 1 using a
           saturating exponential function.

    Returns:
        float: Urgency score in the range [0, 1].
    """
    if not sentence_embeddings or not urgency_prototype_embeddings:
        return 0.0

    total_weighted_urgency_cues = 0
    for sentence, sentence_embedding in sentence_embeddings.items():
        # Semantic urgency detection
        cosine_scores = util.cos_sim(
            sentence_embedding,
            urgency_prototype_embeddings
        )[0]
        max_similarity = float(cosine_scores.max().item())

        # Sentence does not convey an urgent tone
        if max_similarity < semantic_threshold:
            continue

        # Count regex urgency cues
        sentence_cue_count = 0
        for regex_pattern in pattern.URGENCY_PATTERNS_REGEX:
            matches = re.findall(regex_pattern, sentence, flags=re.IGNORECASE)
            sentence_cue_count += len(matches)

        total_weighted_urgency_cues += sentence_cue_count * max_similarity

    # Convert cue count to score
    if total_weighted_urgency_cues == 0:
        return 0.0

    # Saturating function
    urgency_score = 1 - math.exp(-total_weighted_urgency_cues / 3)

    return min(urgency_score, 1.0)


def _risk_score_calculation(number_of_suspicious_urls: int,
                            has_invisible_text: bool,
                            primary_intent: str,
                            urgency_score: float,
                            number_of_coercion_cues: int) -> float:
    """
    Calculate overall email risk score using intent, suspicious URLs,
    urgency, coercion cues, and invisible text.
    """

    # Unknown or benign intent should contribute no significant risk
    intent_score = pattern.intent_risk.get(primary_intent, 0.0)

    # Normalize suspicious URL count.
    # 3 or more suspicious URLs gives maximum URL contribution.
    url_score = min(number_of_suspicious_urls / 3.0, 1.0)

    # Normalize coercion cue count.
    # 4 or more cues gives maximum contribution.
    coercion_score = min(number_of_coercion_cues / 4.0, 1.0)

    # Invisible text is a binary technical indicator.
    invisible_text_score = 1.0 if has_invisible_text else 0.0

    # Ensure urgency score remains valid.
    urgency_score = max(0.0, min(urgency_score, 1.0))

    # Weighted combination
    risk_score = (
        intent_score * 0.35 +
        url_score * 0.25 +
        urgency_score * 0.15 +
        coercion_score * 0.15 +
        invisible_text_score * 0.10
    )

    return round(max(0.0, min(risk_score, 1.0)), 2)


def _get_suspicious_urls(url_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Filter URL analysis results and return only suspicious URLs.
    """
    suspicious_urls = []

    for url in url_results:
        if (url.get("is_mismatch") or url.get("has_userinfo") or url.get("is_javascript") or url.get("is_data") or url.get("is_redirect")):
            suspicious_urls.append({
                "anchor_text": url.get("anchor_text"),
                "destination": url.get("destination"),
                "is_mismatch": url.get("is_mismatch")
            })

    return suspicious_urls


def _has_invisible_text(html_content: str | None) -> bool:
    if not html_content:
        return False
    visible_text, invisible_str_list = extractor.detect_zero_font_obfuscation(html_content)
    return True if len(invisible_str_list) > 0 else False


def threat_intent(email_text: str, html_content: str | None = None) -> Dict[str, Any]:
    """
    Analyze an email and return its threat intent, risk score,
    urgency score, coercion cues, and suspicious URLs.
    """
    email_sentences = _split_sentences(email_text)
    email_sentences_embedding = _get_sentence_embedding(email_sentences)
    sentences_intents = _intent_of_each_sentence(email_sentences_embedding)
    aggregated_category_probability = _aggregate_category_probabilities(sentences_intents)

    # primary intent
    intent = _final_intent(aggregated_category_probability)
    # urgency score
    urgency_score = _urgency_score_calculation(email_sentences_embedding)
    # flagged coercion cues
    coercion_cues = _find_coercion_cues(intent, sentences_intents)

    # suspicious url
    url_results = extractor.extract_and_analyze_urls(html_content)
    suspicious_urls = _get_suspicious_urls(url_results)

    # risk score
    risk_score = _risk_score_calculation(len(suspicious_urls),
                                        _has_invisible_text(html_content),
                                        intent,
                                        urgency_score,
                                        len(coercion_cues))

    return {
        "threat_intent": {
            "primary_intent": intent,
            "risk_score": risk_score * 100,
            "urgency_score": urgency_score * 100,
            "flagged_coercion_cues": coercion_cues,
            "suspicious_urls": suspicious_urls
        }
    }

