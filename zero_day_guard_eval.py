#!/usr/bin/env python3
"""
Hancock 0ai Zero-Day Guard — AUC-ROC Evaluator + Best Threshold Finder
Enhanced with OneClassSVM and hyperparameter optimization
Run on Kali: python zero_day_guard_eval.py
"""
import logging
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.svm import OneClassSVM
from sklearn.metrics import roc_auc_score, roc_curve, auc, precision_recall_curve, f1_score
from sklearn.model_selection import cross_val_score, ParameterGrid
import matplotlib.pyplot as plt
import json
from pathlib import Path
from typing import Dict, Tuple, List
import time

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

np.random.seed(42)

def generate_synthetic_data(n=10000, anomaly_ratio=0.05):
    """Generate synthetic training data for zero-day detection.

    Args:
        n: Total number of samples
        anomaly_ratio: Proportion of anomalous samples

    Returns:
        Tuple of (X, y) feature matrix and labels
    """
    n_normal = int(n * (1 - anomaly_ratio))
    n_anom = n - n_normal
    # Realistic features for LLM prompt anomaly detection
    X_normal = np.random.normal(0.25, 0.12, (n_normal, 5))
    X_anom = np.random.normal(0.75, 0.22, (n_anom, 5))
    X = np.vstack([X_normal, X_anom])
    y = np.array([0] * n_normal + [1] * n_anom)
    return X, y


def optimize_isolation_forest(X: np.ndarray, y: np.ndarray) -> Tuple[IsolationForest, Dict]:
    """Optimize IsolationForest hyperparameters using grid search.

    Args:
        X: Feature matrix
        y: Labels

    Returns:
        Tuple of (best model, best parameters)
    """
    logger.info("🔍 Optimizing IsolationForest hyperparameters...")
    print("🔍 Optimizing IsolationForest hyperparameters...")
    param_grid = {
        'contamination': [0.03, 0.05, 0.07],
        'n_estimators': [100, 200, 300],
        'max_samples': ['auto', 256, 512]
    }

    best_score = -1
    best_params = None
    best_model = None

    for params in ParameterGrid(param_grid):
        model = IsolationForest(random_state=42, n_jobs=-1, **params)
        model.fit(X)
        scores = -model.decision_function(X)
        try:
            score = roc_auc_score(y, scores)
            if score > best_score:
                best_score = score
                best_params = params
                best_model = model
        except (ValueError, RuntimeError) as e:
            # Skip invalid parameter combinations
            logger.debug(f"Skipped params {params}: {e}")
            continue

    print(f"✅ Best IsolationForest AUC: {best_score:.4f}")
    print(f"   Parameters: {best_params}")
    return best_model, best_params


def optimize_one_class_svm(X: np.ndarray, y: np.ndarray) -> Tuple[OneClassSVM, Dict]:
    """Optimize OneClassSVM hyperparameters using grid search.

    Args:
        X: Feature matrix
        y: Labels

    Returns:
        Tuple of (best model, best parameters)
    """
    logger.info("🔍 Optimizing OneClassSVM hyperparameters...")
    print("🔍 Optimizing OneClassSVM hyperparameters...")
    param_grid = {
        'kernel': ['rbf', 'sigmoid'],
        'nu': [0.03, 0.05, 0.07],
        'gamma': ['scale', 'auto', 0.1]
    }

    best_score = -1
    best_params = None
    best_model = None

    for params in ParameterGrid(param_grid):
        try:
            model = OneClassSVM(**params)
            model.fit(X)
            scores = -model.decision_function(X)
            score = roc_auc_score(y, scores)
            if score > best_score:
                best_score = score
                best_params = params
                best_model = model
        except (ValueError, RuntimeError) as e:
            # Skip invalid parameter combinations
            logger.debug(f"Skipped params {params}: {e}")
            continue

    print(f"✅ Best OneClassSVM AUC: {best_score:.4f}")
    print(f"   Parameters: {best_params}")
    return best_model, best_params


def find_optimal_ensemble_weights(
    scores_list: List[np.ndarray],
    y: np.ndarray,
    model_names: List[str]
) -> Tuple[Dict[str, float], float]:
    """Find optimal weights for ensemble combination.

    Args:
        scores_list: List of anomaly scores from different models
        y: True labels
        model_names: Names of the models

    Returns:
        Tuple of (optimal weights dict, best AUC score)
    """
    logger.info("🔍 Optimizing ensemble weights...")
    print("🔍 Optimizing ensemble weights...")
    best_weights = None
    best_auc = -1

    # Grid search over weight combinations
    weight_steps = 11  # 0.0, 0.1, 0.2, ..., 1.0
    for w1 in range(weight_steps):
        for w2 in range(weight_steps):
            for w3 in range(weight_steps):
                weights = np.array([w1, w2, w3]) / 10.0
                if abs(weights.sum() - 1.0) > 0.01:  # Weights must sum to 1
                    continue

                # Compute weighted ensemble score
                ensemble_scores = sum(w * s for w, s in zip(weights, scores_list))
                try:
                    auc = roc_auc_score(y, ensemble_scores)
                    if auc > best_auc:
                        best_auc = auc
                        best_weights = weights
                except (ValueError, RuntimeError) as e:
                    # Skip invalid weight combinations
                    logger.debug(f"Skipped weights {weights}: {e}")
                    continue

    weight_dict = {name: float(w) for name, w in zip(model_names, best_weights)}
    print(f"✅ Best ensemble AUC: {best_auc:.4f}")
    print(f"   Weights: {weight_dict}")
    return weight_dict, best_auc


def evaluate_model_performance(
    scores: np.ndarray,
    y: np.ndarray,
    model_name: str
) -> Dict:
    """Evaluate model performance metrics.

    Args:
        scores: Anomaly scores
        y: True labels
        model_name: Name of the model

    Returns:
        Dictionary of performance metrics
    """
    auc_roc = roc_auc_score(y, scores)
    fpr, tpr, thresholds = roc_curve(y, scores)
    best_idx = np.argmax(tpr - fpr)
    best_thresh = thresholds[best_idx]

    # Calculate F1 score at best threshold
    y_pred = (scores >= best_thresh).astype(int)
    f1 = f1_score(y, y_pred)

    precision, recall, _ = precision_recall_curve(y, scores)
    auc_pr = auc(recall, precision)

    return {
        "model": model_name,
        "auc_roc": float(auc_roc),
        "auc_pr": float(auc_pr),
        "best_threshold": float(best_thresh),
        "tpr_at_best": float(tpr[best_idx]),
        "fpr_at_best": float(fpr[best_idx]),
        "f1_at_best": float(f1)
    }


def main():
    """Main evaluation pipeline with optimization."""
    print("=" * 70)
    print("Hancock 0ai Zero-Day Guard — Enhanced Evaluation Pipeline")
    print("=" * 70)

    start_time = time.time()

    # Generate data
    print("\n📊 Generating synthetic training data...")
    X, y = generate_synthetic_data(n=10000, anomaly_ratio=0.05)
    print(f"   Samples: {len(y)} ({y.sum()} anomalous, {len(y) - y.sum()} normal)")

    # Optimize individual models
    iso_model, iso_params = optimize_isolation_forest(X, y)
    svm_model, svm_params = optimize_one_class_svm(X, y)

    # Train LOF (original baseline)
    print("\n🔍 Training LocalOutlierFactor...")
    lof = LocalOutlierFactor(n_neighbors=20, novelty=True, contamination=0.05, n_jobs=-1)
    lof.fit(X)
    print("✅ LOF trained")

    # Get scores from all models
    scores_iso = -iso_model.decision_function(X)
    scores_svm = -svm_model.decision_function(X)
    scores_lof = -lof.decision_function(X)

    # Find optimal ensemble weights
    model_names = ['IsolationForest', 'OneClassSVM', 'LOF']
    weights, ensemble_auc = find_optimal_ensemble_weights(
        [scores_iso, scores_svm, scores_lof],
        y,
        model_names
    )

    # Compute final ensemble scores
    ensemble_scores = (
        weights['IsolationForest'] * scores_iso +
        weights['OneClassSVM'] * scores_svm +
        weights['LOF'] * scores_lof
    )

    # Evaluate all models
    print("\n📈 Performance Metrics:")
    print("-" * 70)
    results = []
    for scores, name in [(scores_iso, 'IsolationForest'),
                          (scores_svm, 'OneClassSVM'),
                          (scores_lof, 'LOF'),
                          (ensemble_scores, 'Ensemble')]:
        result = evaluate_model_performance(scores, y, name)
        results.append(result)
        print(f"\n{result['model']}:")
        print(f"  AUC-ROC: {result['auc_roc']:.4f}")
        print(f"  AUC-PR:  {result['auc_pr']:.4f}")
        print(f"  F1:      {result['f1_at_best']:.4f}")
        print(f"  TPR:     {result['tpr_at_best']:.4f}")
        print(f"  FPR:     {result['fpr_at_best']:.4f}")

    # Save configuration
    config = {
        "version": "2.0",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "ensemble_performance": results[-1],  # Ensemble results
        "individual_models": results[:-1],
        "ensemble_weights": weights,
        "hyperparameters": {
            "IsolationForest": iso_params,
            "OneClassSVM": svm_params,
            "LOF": {"n_neighbors": 20, "contamination": 0.05}
        }
    }

    config_path = Path("zero_day_guard_config.json")
    config_path.write_text(json.dumps(config, indent=2))
    print(f"\n✅ Enhanced config saved to {config_path}")

    elapsed = time.time() - start_time
    print(f"\n⏱️  Total evaluation time: {elapsed:.2f}s")
    print("=" * 70)


if __name__ == "__main__":
    main()
