"""
Fusion Engine
Merges and deduplicates findings from multiple scanners.
Uses multiple similarity signals for accurate deduplication.
"""

import hashlib
from typing import List, Dict, Any, Set, Tuple
from dataclasses import dataclass
import difflib


@dataclass
class DeduplicationCluster:
    """A cluster of duplicate findings."""
    representative: Any
    duplicates: List[Any]
    merged_finding: Any


class FusionEngine:
    """
    Multi-scanner result fusion engine.

    Deduplication strategy:
    1. Exact file:line:rule match (high confidence same finding)
    2. File + overlapping line range + similar message (same vuln, different scanners)
    3. Code snippet similarity > 0.85 (same code pattern)
    """

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.location_threshold = self.config.get('location_threshold', 3)  # lines
        self.similarity_threshold = self.config.get('similarity_threshold', 0.75)

    def deduplicate(self, findings: List[Any]) -> List[Any]:
        """
        Deduplicate findings from multiple scanners.

        Strategy:
        1. Group by file path
        2. Within each file, cluster by line proximity and content similarity
        3. Merge clusters, taking highest severity and confidence
        """
        if not findings:
            return []

        # Group by file path
        file_groups: Dict[str, List[Any]] = {}
        for f in findings:
            fp = getattr(f, 'file_path', '') or str(f)
            file_groups.setdefault(fp, []).append(f)

        # Deduplicate each file group
        deduplicated = []
        for file_path, file_findings in file_groups.items():
            clusters = self._cluster_findings(file_findings)
            for cluster in clusters:
                merged = self._merge_cluster(cluster)
                deduplicated.append(merged)

        return deduplicated

    def _cluster_findings(self, findings: List[Any]) -> List[DeduplicationCluster]:
        """Cluster findings by proximity and similarity."""
        if not findings:
            return []

        clusters: List[DeduplicationCluster] = []
        unassigned = list(findings)

        while unassigned:
            # Start new cluster with first unassigned finding
            representative = unassigned.pop(0)
            cluster_duplicates = []
            remaining = []

            for candidate in unassigned:
                if self._is_duplicate(representative, candidate):
                    cluster_duplicates.append(candidate)
                else:
                    remaining.append(candidate)

            clusters.append(DeduplicationCluster(
                representative=representative,
                duplicates=cluster_duplicates,
                merged_finding=None
            ))
            unassigned = remaining

        return clusters

    def _is_duplicate(self, a: Any, b: Any) -> bool:
        """Check if two findings are duplicates."""
        # Check file path match
        if getattr(a, 'file_path', '') != getattr(b, 'file_path', ''):
            return False

        # Check line proximity
        line_a = getattr(a, 'line_start', 0)
        line_b = getattr(b, 'line_start', 0)
        if abs(line_a - line_b) > self.location_threshold:
            # Lines are far apart, check code snippet similarity
            code_a = getattr(a, 'code_snippet', '') or ''
            code_b = getattr(b, 'code_snippet', '') or ''
            if len(code_a) > 10 and len(code_b) > 10:
                similarity = self._code_similarity(code_a, code_b)
                if similarity < self.similarity_threshold:
                    return False
            else:
                return False

        # Check rule similarity (same CWE or similar rule name)
        cwe_a = getattr(a, 'cwe_id', '') or ''
        cwe_b = getattr(b, 'cwe_id', '') or ''
        if cwe_a and cwe_b and cwe_a == cwe_b:
            return True

        # Check message similarity
        msg_a = getattr(a, 'message', '') or ''
        msg_b = getattr(b, 'message', '') or ''
        if msg_a and msg_b:
            similarity = self._text_similarity(msg_a, msg_b)
            if similarity > 0.7:
                return True

        # Check code snippet similarity as fallback
        code_a = getattr(a, 'code_snippet', '') or ''
        code_b = getattr(b, 'code_snippet', '') or ''
        if code_a and code_b:
            similarity = self._code_similarity(code_a, code_b)
            return similarity >= 0.85

        return False

    def _merge_cluster(self, cluster: DeduplicationCluster) -> Any:
        """Merge findings in a cluster into one representative finding."""
        rep = cluster.representative
        all_findings = [rep] + cluster.duplicates

        # Use representative as base
        merged = rep

        # Take highest severity
        severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0}
        max_severity = max(
            all_findings,
            key=lambda f: severity_order.get(getattr(f, 'severity', 'LOW'), 0)
        )
        merged.severity = max_severity.severity

        # Take highest confidence
        max_confidence = max(
            all_findings,
            key=lambda f: getattr(f, 'confidence', 0)
        )
        merged.confidence = max_confidence.confidence

        # Combine messages if different
        messages = set()
        for f in all_findings:
            msg = getattr(f, 'message', '')
            if msg:
                messages.add(msg)
        if len(messages) > 1:
            merged.message = getattr(rep, 'message', '') + f"\n\n[Also detected: {'; '.join(messages - {getattr(rep, 'message', '')})}]"

        # Mark as fusion result
        scanners = set()
        for f in all_findings:
            scanners.add(getattr(f, 'scanner', 'unknown'))
        merged.scanner = f"fusion({','.join(scanners)})"

        # Store original scanners in metadata
        if not hasattr(merged, 'metadata'):
            merged.metadata = {}
        merged.metadata['original_scanners'] = list(scanners)
        merged.metadata['duplicate_count'] = len(cluster.duplicates)

        return merged

    def _text_similarity(self, a: str, b: str) -> float:
        """Calculate text similarity using difflib."""
        return difflib.SequenceMatcher(None, a.lower(), b.lower()).ratio()

    def _code_similarity(self, a: str, b: str) -> float:
        """Calculate code similarity (strip whitespace, compare structure)."""
        # Normalize: strip extra whitespace, lowercase
        normalized_a = ' '.join(a.lower().split())
        normalized_b = ' '.join(b.lower().split())

        if not normalized_a or not normalized_b:
            return 0.0

        return difflib.SequenceMatcher(None, normalized_a, normalized_b).ratio()

    def cross_validate(self, findings: List[Any]) -> Tuple[List[Any], List[Any]]:
        """
        Cross-validate findings across scanners.
        Returns (validated_findings, unconfirmed_findings).
        """
        validated = []
        unconfirmed = []

        for f in findings:
            scanners = getattr(f, 'metadata', {}).get('original_scanners', [getattr(f, 'scanner', '')])
            if len(scanners) >= 2:
                # Finding confirmed by multiple scanners - higher confidence
                f.confidence = min(1.0, f.confidence + 0.1)
                validated.append(f)
            else:
                unconfirmed.append(f)

        return validated, unconfirmed
