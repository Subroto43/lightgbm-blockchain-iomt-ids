"""
intrusion_ml_baselines.py

XGBoost, Random Forest, and SVM intrusion detection
using the same pipeline and data partition.

For each model, the script reports:
- Training time
- Inference time (total and per sample)
- Model size (bytes)
- Approximate inference FLOPs
"""

import time
import pickle

import pandas as pd
import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import classification_report, confusion_matrix

from xgboost import XGBClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC

import matplotlib.pyplot as plt
import seaborn as sns


# =========================
# Data loading / preprocessing
# =========================

def load_and_preprocess(data_path):
    full_df = pd.read_csv(data_path)
    print(f"Loaded dataset shape: {full_df.shape}")

    X = full_df.drop(columns=["label"])
    y = full_df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, stratify=y, random_state=42,
    )
    print(f"Train shape: {X_train.shape}, Test shape: {X_test.shape}")

    label_enc = LabelEncoder()
    y_train_enc = label_enc.fit_transform(y_train)
    y_test_enc = label_enc.transform(y_test)
    print(f"Classes: {label_enc.classes_}")

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    return X_train_scaled, X_test_scaled, y_train_enc, y_test_enc, label_enc


# =========================
# Utility functions
# =========================

def plot_confusion_matrix(y_true, y_pred, class_names, title, save_path=None):
    cm = confusion_matrix(y_true, y_pred)

    fig, ax = plt.subplots(figsize=(16, 13))

    sns.heatmap(
        cm,
        annot=True,
        fmt="d",
        annot_kws={"size": 6},
        cmap="Blues",
        xticklabels=class_names,
        yticklabels=class_names,
        linewidths=0.3,
        linecolor="lightgrey",
        ax=ax,
        cbar=True,
    )

    max_val = cm.max()
    for text_obj, val in zip(ax.texts, cm.flatten()):
        if val > max_val * 0.5:
            text_obj.set_color("white")
        else:
            text_obj.set_color("black")

    ax.set_xlabel("Predicted Class", fontsize=12, labelpad=10)
    ax.set_ylabel("True Class", fontsize=12, labelpad=10)
    ax.set_title(title, fontsize=13, pad=15)

    ax.set_xticklabels(ax.get_xticklabels(), rotation=45,
                       ha="right", fontsize=8)
    ax.set_yticklabels(ax.get_yticklabels(), rotation=0, fontsize=8)

    plt.tight_layout()

    if save_path:
        plt.savefig(save_path, dpi=300, bbox_inches="tight")
        print(f"Saved confusion matrix → {save_path}")

    plt.show()
    plt.close()


def compute_model_size_bytes(model):
    return len(pickle.dumps(model))


def compute_rf_flops(model, n_samples):
    from collections import deque

    depths = []
    for est in model.estimators_:
        tree = est.tree_
        children_left = tree.children_left
        children_right = tree.children_right

        max_depth = 0
        queue = deque([(0, 1)])
        while queue:
            node_id, depth = queue.popleft()
            max_depth = max(max_depth, depth)
            left = children_left[node_id]
            right = children_right[node_id]
            if left != right:
                queue.append((left,  depth + 1))
                queue.append((right, depth + 1))
        depths.append(max_depth)

    avg_depth = float(np.mean(depths)) if depths else 0.0
    flops_per_sample = len(model.estimators_) * avg_depth
    total_flops = flops_per_sample * n_samples
    return flops_per_sample, total_flops


def compute_xgb_flops(model, n_samples):
    params = model.get_params()
    n_estimators = params.get("n_estimators", 0)
    max_depth = params.get("max_depth", 0)
    flops_per_sample = n_estimators * max_depth
    total_flops = flops_per_sample * n_samples
    return flops_per_sample, total_flops


def compute_svm_flops(model, n_features, n_samples):
    """
    Approximate inference FLOPs for a kernel SVM (RBF by default):
      - Per support vector: 2*n_features multiplications + 1 kernel evaluation ≈ 2*n_features FLOPs
      - Per sample: n_sv * (2*n_features) dot-product FLOPs + n_sv additions for the decision score
      - For multiclass (OvO): n_classes*(n_classes-1)/2 binary classifiers, each with its own SVs
    We use the total number of support vectors across all classes as a conservative estimate.
    """
    n_sv = model.support_vectors_.shape[0]          # total SVs across all classes
    # dot product + kernel eval per SV
    flops_per_sample = n_sv * (2 * n_features + 1)
    total_flops = flops_per_sample * n_samples
    return flops_per_sample, total_flops


# =========================
# Models
# =========================

def train_xgboost(X_train, y_train, X_test, y_test, class_names):
    num_classes = len(class_names)

    xgb_clf = XGBClassifier(
        n_estimators=200,
        learning_rate=0.05,
        max_depth=8,
        subsample=0.8,
        colsample_bytree=0.8,
        objective="multi:softprob",
        num_class=num_classes,
        eval_metric="mlogloss",
        tree_method="hist",
        random_state=42,
        n_jobs=-1,
    )

    t0 = time.perf_counter()
    xgb_clf.fit(X_train, y_train)
    train_time = time.perf_counter() - t0

    t0 = time.perf_counter()
    y_pred = xgb_clf.predict(X_test)
    infer_time = time.perf_counter() - t0

    n_test_samples = X_test.shape[0]
    infer_time_per_sample_ms = (infer_time / n_test_samples) * 1000

    print("\n=== XGBoost Classification Report ===")
    print(classification_report(y_test, y_pred, target_names=class_names))

    plot_confusion_matrix(
        y_test, y_pred,
        class_names,
        title="Confusion Matrix of XGBoost Intrusion Detection",
        save_path="confusion_matrix_xgboost.png",
    )

    model_size_bytes = compute_model_size_bytes(xgb_clf)
    flops_per_sample, total_flops = compute_xgb_flops(
        xgb_clf, n_samples=n_test_samples)

    print("\n=== XGBoost Metrics ===")
    print(f"Training time              : {train_time:.3f} s")
    print(
        f"Inference time (total)     : {infer_time:.3f} s (on {n_test_samples} samples)")
    print(f"Inference time (per sample): {infer_time_per_sample_ms:.4f} ms")
    print(
        f"Model size                 : {model_size_bytes / (1024 ** 2):.3f} MB")
    print(f"FLOPs per sample           : {flops_per_sample:.1f} (approx.)")
    print(f"Total FLOPs (test)         : {total_flops:.1f} (approx.)")

    return xgb_clf


def train_random_forest(X_train, y_train, X_test, y_test, class_names):
    rf_clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        min_samples_split=2,
        min_samples_leaf=1,
        max_features="sqrt",
        n_jobs=-1,
        random_state=42,
    )

    t0 = time.perf_counter()
    rf_clf.fit(X_train, y_train)
    train_time = time.perf_counter() - t0

    t0 = time.perf_counter()
    y_pred = rf_clf.predict(X_test)
    infer_time = time.perf_counter() - t0

    n_test_samples = X_test.shape[0]
    infer_time_per_sample_ms = (infer_time / n_test_samples) * 1000

    print("\n=== Random Forest Classification Report ===")
    print(classification_report(y_test, y_pred, target_names=class_names))

    plot_confusion_matrix(
        y_test, y_pred,
        class_names,
        title="Confusion Matrix of Random Forest Intrusion Detection",
        save_path="confusion_matrix_rf.png",
    )

    model_size_bytes = compute_model_size_bytes(rf_clf)
    flops_per_sample, total_flops = compute_rf_flops(
        rf_clf, n_samples=n_test_samples)

    print("\n=== Random Forest Metrics ===")
    print(f"Training time              : {train_time:.3f} s")
    print(
        f"Inference time (total)     : {infer_time:.3f} s (on {n_test_samples} samples)")
    print(f"Inference time (per sample): {infer_time_per_sample_ms:.4f} ms")
    print(
        f"Model size                 : {model_size_bytes / (1024 ** 2):.3f} MB")
    print(f"FLOPs per sample           : {flops_per_sample:.1f} (approx.)")
    print(f"Total FLOPs (test)         : {total_flops:.1f} (approx.)")

    return rf_clf


def train_svm(X_train, y_train, X_test, y_test, class_names):
    """
    SVM with RBF kernel, probability=True for consistency with multiclass output.
    cache_size=2000 MB speeds up training on large datasets.
    decision_function_shape='ovr' gives one-vs-rest scores (still uses OvO internally).
    """
    svm_clf = SVC(
        kernel="rbf",
        C=10.0,
        gamma="scale",
        decision_function_shape="ovr",
        probability=False,   # keep False — predict() is faster without Platt scaling
        cache_size=2000,
        random_state=42,
    )

    t0 = time.perf_counter()
    svm_clf.fit(X_train, y_train)
    train_time = time.perf_counter() - t0

    t0 = time.perf_counter()
    y_pred = svm_clf.predict(X_test)
    infer_time = time.perf_counter() - t0

    n_test_samples = X_test.shape[0]
    n_features = X_test.shape[1]
    infer_time_per_sample_ms = (infer_time / n_test_samples) * 1000

    print("\n=== SVM Classification Report ===")
    print(classification_report(y_test, y_pred, target_names=class_names))

    plot_confusion_matrix(
        y_test, y_pred,
        class_names,
        title="Confusion Matrix of SVM Intrusion Detection",
        save_path="confusion_matrix_svm.png",
    )

    model_size_bytes = compute_model_size_bytes(svm_clf)
    flops_per_sample, total_flops = compute_svm_flops(
        svm_clf, n_features=n_features, n_samples=n_test_samples
    )

    print("\n=== SVM Metrics ===")
    print(f"Training time              : {train_time:.3f} s")
    print(
        f"Inference time (total)     : {infer_time:.3f} s (on {n_test_samples} samples)")
    print(f"Inference time (per sample): {infer_time_per_sample_ms:.4f} ms")
    print(
        f"Model size                 : {model_size_bytes / (1024 ** 2):.3f} MB")
    print(f"FLOPs per sample           : {flops_per_sample:.1f} (approx.)")
    print(f"Total FLOPs (test)         : {total_flops:.1f} (approx.)")
    print(f"Support vectors (total)    : {svm_clf.support_vectors_.shape[0]}")
    print(f"Support vectors per class  : {svm_clf.n_support_}")

    return svm_clf


# =========================
# Main
# =========================

if __name__ == "__main__":
    data_path = r"D:\Intensive Period\Journal\archive (1)/CIC_IoMT_2024_WiFi_MQTT_test.csv"

    X_train_scaled, X_test_scaled, y_train_enc, y_test_enc, label_enc = load_and_preprocess(
        data_path
    )

    class_names = list(label_enc.classes_)

    xgb_model = train_xgboost(
        X_train_scaled, y_train_enc, X_test_scaled, y_test_enc, class_names
    )

    rf_model = train_random_forest(
        X_train_scaled, y_train_enc, X_test_scaled, y_test_enc, class_names
    )

    svm_model = train_svm(
        X_train_scaled, y_train_enc, X_test_scaled, y_test_enc, class_names
    )
