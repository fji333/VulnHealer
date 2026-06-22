"""
False Positive Filter
ML-based false positive detection with feedback learning.
Uses sentence embeddings + classifier to predict false positives.
"""

import json
import pickle
from pathlib import Path
from typing import Tuple, Dict, Any, Optional
import logging
import sqlite3

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

logger = logging.getLogger(__name__)


class FalsePositiveFilter:
    """
    Machine learning false positive filter.

    Features used:
    - Severity (CRITICAL=4, HIGH=3, MEDIUM=2, LOW=1, INFO=0)
    - Confidence score (from scanner)
    - Rule category (encoded)
    - Code snippet length
    - Context availability
    - Scanner type
    - CWE category
    - Message length
    - Historical feedback (learned)

    Training:
    - Collect user feedback on findings (TP/FP)
    - Retrain model periodically
    - Feedback stored in SQLite DB
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.threshold = config.get('threshold', 0.7)
        self.model_path = config.get('model_path', './data/fp_model.pkl')
        self.db_path = config.get('db_path', './data/fp_feedback.db')

        # Initialize model
        self.model = None
        self.is_trained = False
        self._init_db()
        self._load_model()

    def _init_db(self):
        """Initialize feedback database."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id TEXT NOT NULL,
                rule_name TEXT,
                severity TEXT,
                code_snippet TEXT,
                message TEXT,
                scanner TEXT,
                is_true_positive BOOLEAN,
                timestamp TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        conn.close()

    def _load_model(self):
        """Load trained model if available."""
        model_file = Path(self.model_path)
        if model_file.exists():
            try:
                with open(model_file, 'rb') as f:
                    self.model = pickle.load(f)
                self.is_trained = True
                logger.info("Loaded FP filter model from %s", self.model_path)
            except Exception as e:
                logger.warning("Failed to load FP model: %s", e)

    def predict(self, finding) -> Tuple[bool, float]:
        """
        Predict if a finding is a false positive.

        Returns:
            (is_fp: bool, confidence: float)
        """
        if not self.is_trained or not self.model:
            # Fallback to heuristic-based filtering
            return self._heuristic_predict(finding)

        features = self._extract_features(finding)
        features_array = np.array([features])

        try:
            proba = self.model.predict_proba(features_array)[0]
            fp_prob = proba[1]  # Probability of FP class
            is_fp = fp_prob > self.threshold
            return is_fp, fp_prob
        except Exception as e:
            logger.warning("Model prediction failed: %s", e)
            return self._heuristic_predict(finding)

    def _heuristic_predict(self, finding) -> Tuple[bool, float]:
        """Fallback heuristic-based false positive detection."""
        score = 0.0

        # High confidence findings are less likely to be FP
        if finding.confidence >= 0.9:
            score -= 0.3
        elif finding.confidence <= 0.5:
            score += 0.3

        # CRITICAL severity less likely FP
        if finding.severity == 'CRITICAL':
            score -= 0.4
        elif finding.severity == 'INFO':
            score += 0.4

        # Certain rule patterns commonly produce FPs
        fp_prone_rules = ['eval', 'exec', 'pickle', 'assert', 'TODO']
        if any(r in finding.rule_name.lower() for r in fp_prone_rules):
            score += 0.2

        # Short code snippets may be context-free FPs
        if len(finding.code_snippet) < 30:
            score += 0.15

        # Multiple scanner confirmation reduces FP likelihood
        if 'fusion' in finding.scanner:
            score -= 0.25

        fp_prob = min(1.0, max(0.0, 0.5 + score))
        is_fp = fp_prob > self.threshold

        return is_fp, fp_prob

    def _extract_features(self, finding) -> list:
        """Extract numerical features from finding."""
        severity_map = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0}
        scanner_map = {'semgrep': 0, 'bandit': 1, 'codeql': 2, 'fusion': 3}

        features = [
            severity_map.get(finding.severity, 2),
            finding.confidence,
            len(finding.code_snippet),
            len(finding.message),
            len(finding.context_before) > 0,
            len(finding.context_after) > 0,
            scanner_map.get(finding.scanner.split('(')[0], 0),
            1 if 'cwe' in str(finding.cwe_id).lower() else 0,
            finding.line_end - finding.line_start + 1,
        ]
        return features

    def learn(self, finding_id: str, is_true_positive: bool):
        """
        Learn from user feedback.

        Args:
            finding_id: Unique finding ID
            is_true_positive: True if validated as real vulnerability
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE feedback
            SET is_true_positive = ?
            WHERE finding_id = ?
        ''', (is_true_positive, finding_id))
        conn.commit()
        conn.close()

        logger.info("Learned: %s is %s", finding_id, "TP" if is_true_positive else "FP")

    def record_feedback(self, finding, is_true_positive: bool):
        """Record new finding feedback for future training."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO feedback
            (finding_id, rule_name, severity, code_snippet, message, scanner, is_true_positive)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            finding.id,
            finding.rule_name,
            finding.severity,
            finding.code_snippet,
            finding.message,
            finding.scanner,
            is_true_positive
        ))
        conn.commit()
        conn.close()

    def train(self) -> Dict[str, Any]:
        """Retrain the FP filter model from feedback database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT severity, code_snippet, message, scanner, is_true_positive
            FROM feedback
            WHERE is_true_positive IS NOT NULL
        ''')
        rows = cursor.fetchall()
        conn.close()

        if len(rows) < 50:
            logger.warning("Not enough feedback samples for training (%d/50)", len(rows))
            return {'status': 'insufficient_data', 'samples': len(rows)}

        # Build feature matrix and labels
        X = []
        y = []

        for row in rows:
            # Create a mock finding object
            class MockFinding:
                pass
            mock = MockFinding()
            mock.severity = row[0]
            mock.code_snippet = row[1] or ''
            mock.message = row[2] or ''
            mock.scanner = row[3]
            mock.confidence = 0.7  # Default
            mock.context_before = ''
            mock.context_after = ''
            mock.cwe_id = ''
            mock.rule_name = ''
            mock.line_start = 0
            mock.line_end = 0

            features = self._extract_features(mock)
            X.append(features)
            y.append(0 if row[4] else 1)  # 0=TP, 1=FP

        X = np.array(X)
        y = np.array(y)

        # Split and train
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X_train, y_train)

        # Evaluate
        y_pred = model.predict(X_test)
        report = classification_report(y_test, y_pred, output_dict=True)

        # Save model
        Path(self.model_path).parent.mkdir(parents=True, exist_ok=True)
        with open(self.model_path, 'wb') as f:
            pickle.dump(model, f)

        self.model = model
        self.is_trained = True

        logger.info("FP filter model trained. Accuracy: %.2f%%", report['accuracy'] * 100)

        return {
            'status': 'trained',
            'samples': len(rows),
            'accuracy': report['accuracy'],
            'precision': report['weighted avg']['precision'],
            'recall': report['weighted avg']['recall']
        }

    def get_feedback_stats(self) -> Dict[str, Any]:
        """Get feedback collection statistics."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN is_true_positive = 1 THEN 1 ELSE 0 END) as tp,
                SUM(CASE WHEN is_true_positive = 0 THEN 1 ELSE 0 END) as fp,
                SUM(CASE WHEN is_true_positive IS NULL THEN 1 ELSE 0 END) as pending
            FROM feedback
        ''')
        row = cursor.fetchone()
        conn.close()

        return {
            'total_samples': row[0],
            'true_positives': row[1] or 0,
            'false_positives': row[2] or 0,
            'pending': row[3] or 0,
            'model_trained': self.is_trained
        }
