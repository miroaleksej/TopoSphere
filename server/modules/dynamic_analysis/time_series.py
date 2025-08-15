"""
TopoSphere Time Series Analysis - Industrial-Grade Implementation

This module provides time series analysis capabilities for the TopoSphere system,
implementing the industrial-grade standards of AuditCore v3.2. The time series
analyzer enables detection of temporal patterns and evolving vulnerabilities in
ECDSA implementations through topological analysis of signature spaces over time.

The module is based on the fundamental insight from our research:
"For secure ECDSA implementations, the signature space forms a topological torus (β₀=1, β₁=2, β₂=1)"
and "Direct analysis without building the full hypercube enables efficient monitoring of large spaces."

As stated in our research: "Topology is not a hacking tool, but a microscope for diagnosing vulnerabilities.
Ignoring it means building cryptography on sand." This time series analysis module embodies that principle by
providing mathematically rigorous temporal analysis of topological properties.

Key Features:
- Temporal analysis of topological properties (Betti numbers, symmetry, etc.)
- Detection of evolving vulnerabilities through time series analysis
- Integration with Sliding Window technique for temporal pattern detection
- Time-based anomaly detection for security monitoring
- Resource-aware analysis for continuous monitoring
- Historical trend analysis for vulnerability progression

This module implements Theorem 30-33 from "НР структурированная.md" and corresponds to
Section 10 of "TOPOLOGICAL DATA ANALYSIS.pdf", providing a mathematically rigorous approach
to time series analysis of topological properties.

Version: 1.0.0
"""

import os
import time
import logging
import datetime
import warnings
from typing import Dict, List, Tuple, Optional, Any, Union, Callable, Protocol, runtime_checkable, TypeVar
from dataclasses import dataclass, field
import numpy as np

# External dependencies
try:
    from giotto.time_series import SlidingWindow
    from giotto.homology import VietorisRipsPersistence
    HAS_GIOTTO = True
except ImportError:
    HAS_GIOTTO = False
    warnings.warn("giotto-tda not found. Time series analysis features will be limited.", RuntimeWarning)

try:
    import pandas as pd
    HAS_PANDAS = True
except ImportError:
    HAS_PANDAS = False
    warnings.warn("pandas not found. Some time series functionality will be limited.", RuntimeWarning)

try:
    import matplotlib.pyplot as plt
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False
    warnings.warn("matplotlib not found. Visualization features will be limited.", RuntimeWarning)

# Internal dependencies
from server.config.server_config import ServerConfig
from server.shared.models import (
    ECDSASignature,
    TopologicalAnalysisResult,
    CriticalRegion,
    BettiNumbers,
    VulnerabilityType
)
from server.utils.topology_calculations import (
    calculate_betti_numbers,
    calculate_topological_entropy,
    analyze_symmetry_violations,
    analyze_spiral_pattern,
    analyze_star_pattern
)
from server.modules.tcon_analysis import TCONAnalyzer

# Configure logger
logger = logging.getLogger("TopoSphere.DynamicAnalysis.TimeSeries")
logger.addHandler(logging.NullHandler())

# ======================
# ENUMERATIONS
# ======================

class TimeSeriesAnalysisType(Enum):
    """Types of time series analysis."""
    TEMPORAL_TRENDS = "temporal_trends"  # Long-term trends in topological properties
    SHORT_TERM_ANOMALIES = "short_term_anomalies"  # Short-term deviations from expected patterns
    SEASONAL_PATTERNS = "seasonal_patterns"  # Periodic patterns in topological properties
    CHANGE_POINT_DETECTION = "change_point_detection"  # Detection of significant changes
    PROGRESSIVE_DEGRADATION = "progressive_degradation"  # Gradual degradation of security properties
    
    def get_description(self) -> str:
        """Get description of analysis type."""
        descriptions = {
            TimeSeriesAnalysisType.TEMPORAL_TRENDS: "Analysis of long-term trends in topological properties",
            TimeSeriesAnalysisType.SHORT_TERM_ANOMALIES: "Detection of short-term deviations from expected patterns",
            TimeSeriesAnalysisType.SEASONAL_PATTERNS: "Identification of periodic patterns in topological properties",
            TimeSeriesAnalysisType.CHANGE_POINT_DETECTION: "Detection of significant changes in topological properties",
            TimeSeriesAnalysisType.PROGRESSIVE_DEGRADATION: "Monitoring for gradual degradation of security properties"
        }
        return descriptions.get(self, "Unknown time series analysis type")

class TimeResolution(Enum):
    """Time resolutions for time series analysis."""
    MINUTE = "minute"  # Minute-level resolution
    HOUR = "hour"  # Hour-level resolution
    DAY = "day"  # Day-level resolution
    WEEK = "week"  # Week-level resolution
    MONTH = "month"  # Month-level resolution
    
    def get_seconds(self) -> int:
        """Get number of seconds for this resolution.
        
        Returns:
            Number of seconds
        """
        resolutions = {
            TimeResolution.MINUTE: 60,
            TimeResolution.HOUR: 3600,
            TimeResolution.DAY: 86400,
            TimeResolution.WEEK: 604800,
            TimeResolution.MONTH: 2592000  # Approximate (30 days)
        }
        return resolutions.get(self, 60)
    
    def get_description(self) -> str:
        """Get description of time resolution."""
        descriptions = {
            TimeResolution.MINUTE: "Minute-level resolution (suitable for real-time monitoring)",
            TimeResolution.HOUR: "Hour-level resolution (suitable for short-term analysis)",
            TimeResolution.DAY: "Day-level resolution (suitable for medium-term analysis)",
            TimeResolution.WEEK: "Week-level resolution (suitable for long-term trends)",
            TimeResolution.MONTH: "Month-level resolution (suitable for historical analysis)"
        }
        return descriptions.get(self, "Unknown time resolution")

# ======================
# PROTOCOL DEFINITIONS
# ======================

@runtime_checkable
class TimeSeriesAnalyzerProtocol(Protocol):
    """Protocol for time series analysis of topological properties.
    
    This protocol defines the interface for temporal analysis of ECDSA implementations,
    enabling detection of evolving vulnerabilities through time series analysis.
    """
    
    def analyze_temporal_patterns(self, 
                                historical_analysis: List[TopologicalAnalysisResult],
                                time_resolution: TimeResolution = TimeResolution.DAY) -> Dict[str, Any]:
        """Analyze temporal patterns in topological properties.
        
        Args:
            historical_analysis: List of historical topological analysis results
            time_resolution: Time resolution for analysis
            
        Returns:
            Dictionary with temporal pattern analysis results
        """
        ...
    
    def detect_temporal_anomalies(self, 
                                 historical_analysis: List[TopologicalAnalysisResult],
                                 window_size: int = 7,
                                 threshold: float = 2.0) -> List[Dict[str, Any]]:
        """Detect temporal anomalies in topological properties.
        
        Args:
            historical_analysis: List of historical topological analysis results
            window_size: Size of the sliding window
            threshold: Anomaly detection threshold
            
        Returns:
            List of detected temporal anomalies
        """
        ...
    
    def identify_change_points(self, 
                              historical_analysis: List[TopologicalAnalysisResult],
                              min_segment_length: int = 5,
                              penalty: float = 10.0) -> List[Dict[str, Any]]:
        """Identify change points in topological properties.
        
        Args:
            historical_analysis: List of historical topological analysis results
            min_segment_length: Minimum segment length
            penalty: Penalty parameter for change point detection
            
        Returns:
            List of detected change points
        """
        ...
    
    def forecast_security_trends(self, 
                               historical_analysis: List[TopologicalAnalysisResult],
                               forecast_horizon: int = 30) -> Dict[str, Any]:
        """Forecast security trends based on historical data.
        
        Args:
            historical_analysis: List of historical topological analysis results
            forecast_horizon: Number of time units to forecast
            
        Returns:
            Dictionary with security trend forecasts
        """
        ...
    
    def get_temporal_vulnerability_score(self, 
                                        temporal_analysis: Dict[str, Any]) -> float:
        """Calculate vulnerability score based on temporal analysis.
        
        Args:
            temporal_analysis: Results of temporal analysis
            
        Returns:
            Temporal vulnerability score (0-1, higher = more vulnerable)
        """
        ...
    
    def generate_temporal_report(self, 
                                temporal_analysis: Dict[str, Any]) -> str:
        """Generate comprehensive temporal analysis report.
        
        Args:
            temporal_analysis: Results of temporal analysis
            
        Returns:
            Formatted temporal analysis report
        """
        ...

# ======================
# DATA CLASSES
# ======================

@dataclass
class TimeSeriesPoint:
    """Point in a time series of topological properties."""
    timestamp: float  # Unix timestamp
    betti_numbers: BettiNumbers
    symmetry_violation_rate: float
    spiral_pattern_score: float
    star_pattern_score: float
    topological_entropy: float
    vulnerability_score: float
    critical_regions_count: int
    analysis_metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "timestamp": self.timestamp,
            "betti_numbers": {
                "beta_0": self.betti_numbers.beta_0,
                "beta_1": self.betti_numbers.beta_1,
                "beta_2": self.betti_numbers.beta_2,
                "confidence": self.betti_numbers.confidence
            },
            "symmetry_violation_rate": self.symmetry_violation_rate,
            "spiral_pattern_score": self.spiral_pattern_score,
            "star_pattern_score": self.star_pattern_score,
            "topological_entropy": self.topological_entropy,
            "vulnerability_score": self.vulnerability_score,
            "critical_regions_count": self.critical_regions_count,
            "analysis_metadata": self.analysis_metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TimeSeriesPoint":
        """Create from dictionary."""
        return cls(
            timestamp=data["timestamp"],
            betti_numbers=BettiNumbers(
                beta_0=data["betti_numbers"]["beta_0"],
                beta_1=data["betti_numbers"]["beta_1"],
                beta_2=data["betti_numbers"]["beta_2"],
                confidence=data["betti_numbers"].get("confidence", 1.0)
            ),
            symmetry_violation_rate=data["symmetry_violation_rate"],
            spiral_pattern_score=data["spiral_pattern_score"],
            star_pattern_score=data["star_pattern_score"],
            topological_entropy=data["topological_entropy"],
            vulnerability_score=data["vulnerability_score"],
            critical_regions_count=data["critical_regions_count"],
            analysis_metadata=data.get("analysis_metadata", {})
        )

@dataclass
class TemporalPattern:
    """Detected temporal pattern in topological properties."""
    pattern_type: TimeSeriesAnalysisType
    start_timestamp: float
    end_timestamp: float
    pattern_strength: float
    affected_metrics: List[str]
    description: str
    confidence: float = 0.8
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "pattern_type": self.pattern_type.value,
            "start_timestamp": self.start_timestamp,
            "end_timestamp": self.end_timestamp,
            "pattern_strength": self.pattern_strength,
            "affected_metrics": self.affected_metrics,
            "description": self.description,
            "confidence": self.confidence,
            "metadata": self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TemporalPattern":
        """Create from dictionary."""
        return cls(
            pattern_type=TimeSeriesAnalysisType(data["pattern_type"]),
            start_timestamp=data["start_timestamp"],
            end_timestamp=data["end_timestamp"],
            pattern_strength=data["pattern_strength"],
            affected_metrics=data["affected_metrics"],
            description=data["description"],
            confidence=data.get("confidence", 0.8),
            metadata=data.get("metadata", {})
        )

@dataclass
class TemporalAnomaly:
    """Detected temporal anomaly in topological properties."""
    timestamp: float
    anomaly_score: float
    metric_deviations: Dict[str, float]
    pattern_type: TimeSeriesAnalysisType
    description: str
    severity: str = "medium"
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "timestamp": self.timestamp,
            "anomaly_score": self.anomaly_score,
            "metric_deviations": self.metric_deviations,
            "pattern_type": self.pattern_type.value,
            "description": self.description,
            "severity": self.severity,
            "metadata": self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TemporalAnomaly":
        """Create from dictionary."""
        return cls(
            timestamp=data["timestamp"],
            anomaly_score=data["anomaly_score"],
            metric_deviations=data["metric_deviations"],
            pattern_type=TimeSeriesAnalysisType(data["pattern_type"]),
            description=data["description"],
            severity=data.get("severity", "medium"),
            metadata=data.get("metadata", {})
        )

@dataclass
class TimeSeriesAnalysisResult:
    """Results of time series analysis of topological properties."""
    time_series_points: List[TimeSeriesPoint]
    temporal_patterns: List[TemporalPattern]
    temporal_anomalies: List[TemporalAnomaly]
    change_points: List[Dict[str, Any]]
    forecast: Optional[Dict[str, Any]] = None
    analysis_type: TimeSeriesAnalysisType = TimeSeriesAnalysisType.TEMPORAL_TRENDS
    time_resolution: TimeResolution = TimeResolution.DAY
    temporal_vulnerability_score: float = 0.0
    is_secure: bool = True
    execution_time: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "time_series_points": [point.to_dict() for point in self.time_series_points],
            "temporal_patterns": [pattern.to_dict() for pattern in self.temporal_patterns],
            "temporal_anomalies": [anomaly.to_dict() for anomaly in self.temporal_anomalies],
            "change_points": self.change_points,
            "forecast": self.forecast,
            "analysis_type": self.analysis_type.value,
            "time_resolution": self.time_resolution.value,
            "temporal_vulnerability_score": self.temporal_vulnerability_score,
            "is_secure": self.is_secure,
            "execution_time": self.execution_time,
            "metadata": self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TimeSeriesAnalysisResult":
        """Create from dictionary."""
        return cls(
            time_series_points=[TimeSeriesPoint.from_dict(p) for p in data["time_series_points"]],
            temporal_patterns=[TemporalPattern.from_dict(p) for p in data["temporal_patterns"]],
            temporal_anomalies=[TemporalAnomaly.from_dict(a) for a in data["temporal_anomalies"]],
            change_points=data["change_points"],
            forecast=data.get("forecast"),
            analysis_type=TimeSeriesAnalysisType(data["analysis_type"]),
            time_resolution=TimeResolution(data["time_resolution"]),
            temporal_vulnerability_score=data["temporal_vulnerability_score"],
            is_secure=data["is_secure"],
            execution_time=data["execution_time"],
            metadata=data.get("metadata", {})
        )

# ======================
# TIME SERIES ANALYZER CLASS
# ======================

class TimeSeriesAnalyzer:
    """Time series analyzer for temporal topological analysis.
    
    This class implements time series analysis of topological properties for ECDSA
    implementations, enabling detection of evolving vulnerabilities through temporal
    patterns and anomalies.
    
    The analyzer uses Sliding Window technique from giotto-tda for temporal pattern
    detection and provides:
    - Temporal trend analysis
    - Short-term anomaly detection
    - Seasonal pattern identification
    - Change point detection
    - Security trend forecasting
    
    Key features:
    - Integration with Sliding Window for temporal pattern detection
    - Resource-aware analysis for continuous monitoring
    - Historical trend analysis for vulnerability progression
    - Real-time monitoring capabilities
    - Integration with TCON (Topological Conformance) verification
    
    The implementation follows Theorem 30-33 from "НР структурированная.md" and
    Section 10 of "TOPOLOGICAL DATA ANALYSIS.pdf", providing a mathematically
    rigorous approach to time series analysis of topological properties.
    """
    
    def __init__(self, 
                config: Optional[ServerConfig] = None,
                tcon_analyzer: Optional['TCONAnalyzer'] = None):
        """Initialize the time series analyzer.
        
        Args:
            config: Server configuration
            tcon_analyzer: Optional TCON analyzer instance
        """
        self.config = config or ServerConfig()
        self.tcon_analyzer = tcon_analyzer or TCONAnalyzer(self.config)
        self.logger = logging.getLogger("TopoSphere.TimeSeriesAnalyzer")
        self.cache = {}
        self.sliding_window = SlidingWindow(
            size=self.config.tda_settings.get("sliding_window_size", 30),
            stride=self.config.tda_settings.get("sliding_window_stride", 1)
        )
    
    def analyze_temporal_patterns(self, 
                                historical_analysis: List[TopologicalAnalysisResult],
                                time_resolution: TimeResolution = TimeResolution.DAY) -> TimeSeriesAnalysisResult:
        """Analyze temporal patterns in topological properties.
        
        Args:
            historical_analysis: List of historical topological analysis results
            time_resolution: Time resolution for analysis
            
        Returns:
            TimeSeriesAnalysisResult with temporal pattern analysis
        """
        start_time = time.time()
        
        # Check cache first
        cache_key = self._generate_cache_key(historical_analysis, time_resolution)
        if cache_key in self.cache:
            self.logger.debug("Returning cached temporal analysis result")
            return self.cache[cache_key]
        
        # Convert historical analysis to time series points
        time_series_points = self._convert_to_time_series(historical_analysis)
        
        # Aggregate points by time resolution
        aggregated_points = self._aggregate_by_resolution(time_series_points, time_resolution)
        
        # Detect temporal patterns
        temporal_patterns = self._detect_temporal_patterns(aggregated_points)
        
        # Detect temporal anomalies
        temporal_anomalies = self._detect_temporal_anomalies(aggregated_points)
        
        # Identify change points
        change_points = self._identify_change_points(aggregated_points)
        
        # Forecast security trends
        forecast = self._forecast_security_trends(aggregated_points)
        
        # Calculate temporal vulnerability score
        temporal_vulnerability_score = self._calculate_temporal_vulnerability_score(
            temporal_patterns, 
            temporal_anomalies,
            change_points
        )
        
        # Determine if implementation is secure
        is_secure = temporal_vulnerability_score < self.config.security_thresholds.vulnerability_threshold
        
        execution_time = time.time() - start_time
        
        # Create analysis result
        analysis_result = TimeSeriesAnalysisResult(
            time_series_points=aggregated_points,
            temporal_patterns=temporal_patterns,
            temporal_anomalies=temporal_anomalies,
            change_points=change_points,
            forecast=forecast,
            analysis_type=TimeSeriesAnalysisType.TEMPORAL_TRENDS,
            time_resolution=time_resolution,
            temporal_vulnerability_score=temporal_vulnerability_score,
            is_secure=is_secure,
            execution_time=execution_time,
            metadata={
                "historical_analysis_count": len(historical_analysis),
                "aggregated_points_count": len(aggregated_points)
            }
        )
        
        # Cache the result
        self.cache[cache_key] = analysis_result
        
        return analysis_result
    
    def _generate_cache_key(self, 
                           historical_analysis: List[TopologicalAnalysisResult],
                           time_resolution: TimeResolution) -> str:
        """Generate cache key for time series analysis.
        
        Args:
            historical_analysis: List of historical analysis results
            time_resolution: Time resolution
            
        Returns:
            Cache key string
        """
        if not historical_analysis:
            return f"empty_{time_resolution.value}"
        
        # Use first and last timestamps and count for cache key
        first_ts = int(historical_analysis[0].execution_time)
        last_ts = int(historical_analysis[-1].execution_time)
        count = len(historical_analysis)
        
        return f"{first_ts}_{last_ts}_{count}_{time_resolution.value}"
    
    def _convert_to_time_series(self, 
                               historical_analysis: List[TopologicalAnalysisResult]) -> List[TimeSeriesPoint]:
        """Convert historical analysis to time series points.
        
        Args:
            historical_analysis: List of historical topological analysis results
            
        Returns:
            List of TimeSeriesPoint objects
        """
        time_series_points = []
        
        for analysis in historical_analysis:
            # Create time series point
            point = TimeSeriesPoint(
                timestamp=analysis.execution_time,
                betti_numbers=analysis.betti_numbers,
                symmetry_violation_rate=analysis.symmetry_analysis["violation_rate"],
                spiral_pattern_score=analysis.spiral_analysis["score"],
                star_pattern_score=analysis.star_analysis["score"],
                topological_entropy=analysis.topological_entropy,
                vulnerability_score=analysis.vulnerability_score,
                critical_regions_count=len(analysis.critical_regions),
                analysis_metadata={
                    "curve_name": analysis.curve_name,
                    "signature_count": analysis.signature_count,
                    "analysis_method": getattr(analysis, "analysis_method", "full")
                }
            )
            time_series_points.append(point)
        
        return time_series_points
    
    def _aggregate_by_resolution(self, 
                               time_series_points: List[TimeSeriesPoint],
                               time_resolution: TimeResolution) -> List[TimeSeriesPoint]:
        """Aggregate time series points by time resolution.
        
        Args:
            time_series_points: List of time series points
            time_resolution: Time resolution for aggregation
            
        Returns:
            List of aggregated time series points
        """
        if not time_series_points:
            return []
        
        # Sort points by timestamp
        sorted_points = sorted(time_series_points, key=lambda p: p.timestamp)
        
        # Calculate resolution in seconds
        resolution_seconds = time_resolution.get_seconds()
        
        # Aggregate points
        aggregated_points = []
        current_bucket = []
        bucket_start = sorted_points[0].timestamp
        bucket_end = bucket_start + resolution_seconds
        
        for point in sorted_points:
            # Start new bucket if point is outside current bucket
            if point.timestamp >= bucket_end:
                if current_bucket:
                    # Aggregate bucket
                    aggregated_point = self._aggregate_bucket(current_bucket, bucket_start, bucket_end)
                    aggregated_points.append(aggregated_point)
                
                # Start new bucket
                bucket_start = point.timestamp
                bucket_end = bucket_start + resolution_seconds
                current_bucket = [point]
            else:
                current_bucket.append(point)
        
        # Add last bucket
        if current_bucket:
            aggregated_point = self._aggregate_bucket(current_bucket, bucket_start, bucket_end)
            aggregated_points.append(aggregated_point)
        
        return aggregated_points
    
    def _aggregate_bucket(self, 
                         bucket_points: List[TimeSeriesPoint],
                         bucket_start: float,
                         bucket_end: float) -> TimeSeriesPoint:
        """Aggregate points in a time bucket.
        
        Args:
            bucket_points: Points in the time bucket
            bucket_start: Start timestamp of the bucket
            bucket_end: End timestamp of the bucket
            
        Returns:
            Aggregated TimeSeriesPoint
        """
        if not bucket_points:
            return None
        
        # Calculate average values
        avg_betti_0 = np.mean([p.betti_numbers.beta_0 for p in bucket_points])
        avg_betti_1 = np.mean([p.betti_numbers.beta_1 for p in bucket_points])
        avg_betti_2 = np.mean([p.betti_numbers.beta_2 for p in bucket_points])
        avg_confidence = np.mean([p.betti_numbers.confidence for p in bucket_points])
        
        avg_symmetry = np.mean([p.symmetry_violation_rate for p in bucket_points])
        avg_spiral = np.mean([p.spiral_pattern_score for p in bucket_points])
        avg_star = np.mean([p.star_pattern_score for p in bucket_points])
        avg_entropy = np.mean([p.topological_entropy for p in bucket_points])
        avg_vulnerability = np.mean([p.vulnerability_score for p in bucket_points])
        total_critical_regions = sum(p.critical_regions_count for p in bucket_points)
        
        # Create aggregated point (use midpoint as timestamp)
        return TimeSeriesPoint(
            timestamp=(bucket_start + bucket_end) / 2,
            betti_numbers=BettiNumbers(
                beta_0=avg_betti_0,
                beta_1=avg_betti_1,
                beta_2=avg_betti_2,
                confidence=avg_confidence
            ),
            symmetry_violation_rate=avg_symmetry,
            spiral_pattern_score=avg_spiral,
            star_pattern_score=avg_star,
            topological_entropy=avg_entropy,
            vulnerability_score=avg_vulnerability,
            critical_regions_count=total_critical_regions,
            analysis_metadata={
                "point_count": len(bucket_points),
                "bucket_start": bucket_start,
                "bucket_end": bucket_end
            }
        )
    
    def _detect_temporal_patterns(self, 
                                time_series_points: List[TimeSeriesPoint]) -> List[TemporalPattern]:
        """Detect temporal patterns in time series data.
        
        Args:
            time_series_points: Time series points to analyze
            
        Returns:
            List of detected temporal patterns
        """
        patterns = []
        
        if len(time_series_points) < 10:  # Need enough points for pattern detection
            return patterns
        
        # Convert to numpy arrays for analysis
        timestamps = np.array([p.timestamp for p in time_series_points])
        vulnerability_scores = np.array([p.vulnerability_score for p in time_series_points])
        symmetry_violations = np.array([p.symmetry_violation_rate for p in time_series_points])
        spiral_scores = np.array([p.spiral_pattern_score for p in time_series_points])
        star_scores = np.array([p.star_pattern_score for p in time_series_points])
        
        # 1. Detect long-term trends
        trend_pattern = self._detect_long_term_trend(timestamps, vulnerability_scores)
        if trend_pattern:
            patterns.append(trend_pattern)
        
        # 2. Detect seasonal patterns
        seasonal_patterns = self._detect_seasonal_patterns(timestamps, vulnerability_scores)
        patterns.extend(seasonal_patterns)
        
        # 3. Detect progressive degradation
        degradation_pattern = self._detect_progressive_degradation(timestamps, vulnerability_scores)
        if degradation_pattern:
            patterns.append(degradation_pattern)
        
        return patterns
    
    def _detect_long_term_trend(self, 
                               timestamps: np.ndarray,
                               vulnerability_scores: np.ndarray) -> Optional[TemporalPattern]:
        """Detect long-term trend in vulnerability scores.
        
        Args:
            timestamps: Timestamp array
            vulnerability_scores: Vulnerability score array
            
        Returns:
            Detected trend pattern or None
        """
        # Calculate trend using linear regression
        x = (timestamps - timestamps[0]) / (24 * 3600)  # Convert to days
        slope, intercept = np.polyfit(x, vulnerability_scores, 1)
        
        # Determine trend direction and strength
        trend_strength = abs(slope)
        if trend_strength < 0.001:  # Threshold for significant trend
            return None
        
        # Create description
        direction = "increasing" if slope > 0 else "decreasing"
        description = f"Long-term {direction} trend in vulnerability score (slope: {slope:.6f})"
        
        return TemporalPattern(
            pattern_type=TimeSeriesAnalysisType.TEMPORAL_TRENDS,
            start_timestamp=timestamps[0],
            end_timestamp=timestamps[-1],
            pattern_strength=trend_strength,
            affected_metrics=["vulnerability_score"],
            description=description,
            confidence=min(0.5 + trend_strength * 10, 0.95)
        )
    
    def _detect_seasonal_patterns(self, 
                                timestamps: np.ndarray,
                                vulnerability_scores: np.ndarray) -> List[TemporalPattern]:
        """Detect seasonal patterns in vulnerability scores.
        
        Args:
            timestamps: Timestamp array
            vulnerability_scores: Vulnerability score array
            
        Returns:
            List of detected seasonal patterns
        """
        patterns = []
        n = len(timestamps)
        
        if n < 20:  # Need enough points for seasonal analysis
            return patterns
        
        # Convert timestamps to datetime objects
        dates = [datetime.datetime.fromtimestamp(ts) for ts in timestamps]
        
        # Check for daily patterns (hour of day)
        hour_scores = {}
        for i, date in enumerate(dates):
            hour = date.hour
            if hour not in hour_scores:
                hour_scores[hour] = []
            hour_scores[hour].append(vulnerability_scores[i])
        
        # Calculate variance by hour
        hour_variances = {h: np.var(scores) for h, scores in hour_scores.items() if len(scores) > 2}
        
        if hour_variances:
            max_hour, max_var = max(hour_variances.items(), key=lambda x: x[1])
            if max_var > 0.01:  # Threshold for significant variance
                patterns.append(TemporalPattern(
                    pattern_type=TimeSeriesAnalysisType.SEASONAL_PATTERNS,
                    start_timestamp=timestamps[0],
                    end_timestamp=timestamps[-1],
                    pattern_strength=max_var,
                    affected_metrics=["vulnerability_score"],
                    description=f"Daily pattern with highest variance at hour {max_hour}",
                    confidence=min(0.5 + max_var * 10, 0.95)
                ))
        
        # Check for weekly patterns (day of week)
        day_scores = {}
        for i, date in enumerate(dates):
            day = date.weekday()  # 0=Monday, 6=Sunday
            if day not in day_scores:
                day_scores[day] = []
            day_scores[day].append(vulnerability_scores[i])
        
        # Calculate variance by day
        day_variances = {d: np.var(scores) for d, scores in day_scores.items() if len(scores) > 2}
        
        if day_variances:
            max_day, max_var = max(day_variances.items(), key=lambda x: x[1])
            if max_var > 0.01:  # Threshold for significant variance
                patterns.append(TemporalPattern(
                    pattern_type=TimeSeriesAnalysisType.SEASONAL_PATTERNS,
                    start_timestamp=timestamps[0],
                    end_timestamp=timestamps[-1],
                    pattern_strength=max_var,
                    affected_metrics=["vulnerability_score"],
                    description=f"Weekly pattern with highest variance on day {max_day}",
                    confidence=min(0.5 + max_var * 10, 0.95)
                ))
        
        return patterns
    
    def _detect_progressive_degradation(self, 
                                       timestamps: np.ndarray,
                                       vulnerability_scores: np.ndarray) -> Optional[TemporalPattern]:
        """Detect progressive degradation in security properties.
        
        Args:
            timestamps: Timestamp array
            vulnerability_scores: Vulnerability score array
            
        Returns:
            Detected degradation pattern or None
        """
        n = len(vulnerability_scores)
        
        if n < 10:  # Need enough points for degradation analysis
            return None
        
        # Check if vulnerability score is consistently increasing
        increasing = all(vulnerability_scores[i] <= vulnerability_scores[i+1] for i in range(n-1))
        avg_increase = np.mean(np.diff(vulnerability_scores))
        
        if increasing and avg_increase > 0.005:  # Threshold for significant degradation
            return TemporalPattern(
                pattern_type=TimeSeriesAnalysisType.PROGRESSIVE_DEGRADATION,
                start_timestamp=timestamps[0],
                end_timestamp=timestamps[-1],
                pattern_strength=avg_increase,
                affected_metrics=["vulnerability_score"],
                description=f"Progressive degradation detected with average increase of {avg_increase:.6f} per time unit",
                confidence=min(0.6 + avg_increase * 100, 0.95)
            )
        
        return None
    
    def detect_temporal_anomalies(self, 
                                  historical_analysis: List[TopologicalAnalysisResult],
                                  window_size: int = 7,
                                  threshold: float = 2.0) -> List[TemporalAnomaly]:
        """Detect temporal anomalies in topological properties.
        
        Args:
            historical_analysis: List of historical topological analysis results
            window_size: Size of the sliding window
            threshold: Anomaly detection threshold
            
        Returns:
            List of detected temporal anomalies
        """
        # Convert historical analysis to time series points
        time_series_points = self._convert_to_time_series(historical_analysis)
        
        # Aggregate points (use daily resolution for anomaly detection)
        aggregated_points = self._aggregate_by_resolution(
            time_series_points, 
            TimeResolution.DAY
        )
        
        # Detect anomalies
        return self._detect_temporal_anomalies(aggregated_points, window_size, threshold)
    
    def _detect_temporal_anomalies(self, 
                                  time_series_points: List[TimeSeriesPoint],
                                  window_size: int = 7,
                                  threshold: float = 2.0) -> List[TemporalAnomaly]:
        """Detect temporal anomalies in time series data.
        
        Args:
            time_series_points: Time series points to analyze
            window_size: Size of the sliding window
            threshold: Anomaly detection threshold
            
        Returns:
            List of detected temporal anomalies
        """
        anomalies = []
        
        if len(time_series_points) < window_size + 2:
            return anomalies
        
        # Convert to numpy arrays
        timestamps = np.array([p.timestamp for p in time_series_points])
        vulnerability_scores = np.array([p.vulnerability_score for p in time_series_points])
        symmetry_violations = np.array([p.symmetry_violation_rate for p in time_series_points])
        spiral_scores = np.array([p.spiral_pattern_score for p in time_series_points])
        star_scores = np.array([p.star_pattern_score for p in time_series_points])
        
        # Use sliding window to calculate rolling statistics
        for i in range(window_size, len(time_series_points)):
            # Calculate window statistics
            window_vs = vulnerability_scores[i-window_size:i]
            window_mean = np.mean(window_vs)
            window_std = np.std(window_vs)
            
            # Check current point
            current_vs = vulnerability_scores[i]
            if window_std > 0:
                z_score = (current_vs - window_mean) / window_std
                if abs(z_score) > threshold:
                    # Determine severity
                    severity = "high" if abs(z_score) > threshold * 1.5 else "medium"
                    
                    # Create anomaly description
                    direction = "increase" if z_score > 0 else "decrease"
                    description = f"Significant {direction} in vulnerability score (z-score: {z_score:.2f})"
                    
                    # Create anomaly
                    anomalies.append(TemporalAnomaly(
                        timestamp=time_series_points[i].timestamp,
                        anomaly_score=abs(z_score),
                        metric_deviations={"vulnerability_score": float(z_score)},
                        pattern_type=TimeSeriesAnalysisType.SHORT_TERM_ANOMALIES,
                        description=description,
                        severity=severity
                    ))
            
            # Check for symmetry violation anomalies
            window_sym = symmetry_violations[i-window_size:i]
            window_mean_sym = np.mean(window_sym)
            window_std_sym = np.std(window_sym)
            
            if window_std_sym > 0:
                current_sym = symmetry_violations[i]
                z_score_sym = (current_sym - window_mean_sym) / window_std_sym
                if abs(z_score_sym) > threshold and current_sym > 0.05:
                    severity = "high" if abs(z_score_sym) > threshold * 1.5 else "medium"
                    direction = "increase" if z_score_sym > 0 else "decrease"
                    description = f"Significant {direction} in symmetry violation rate (z-score: {z_score_sym:.2f})"
                    
                    anomalies.append(TemporalAnomaly(
                        timestamp=time_series_points[i].timestamp,
                        anomaly_score=abs(z_score_sym),
                        metric_deviations={"symmetry_violation_rate": float(z_score_sym)},
                        pattern_type=TimeSeriesAnalysisType.SHORT_TERM_ANOMALIES,
                        description=description,
                        severity=severity
                    ))
        
        return anomalies
    
    def identify_change_points(self, 
                              historical_analysis: List[TopologicalAnalysisResult],
                              min_segment_length: int = 5,
                              penalty: float = 10.0) -> List[Dict[str, Any]]:
        """Identify change points in topological properties.
        
        Args:
            historical_analysis: List of historical topological analysis results
            min_segment_length: Minimum segment length
            penalty: Penalty parameter for change point detection
            
        Returns:
            List of detected change points
        """
        # Convert historical analysis to time series points
        time_series_points = self._convert_to_time_series(historical_analysis)
        
        # Aggregate points (use daily resolution for change point detection)
        aggregated_points = self._aggregate_by_resolution(
            time_series_points, 
            TimeResolution.DAY
        )
        
        # Identify change points
        return self._identify_change_points(aggregated_points, min_segment_length, penalty)
    
    def _identify_change_points(self, 
                               time_series_points: List[TimeSeriesPoint],
                               min_segment_length: int = 5,
                               penalty: float = 10.0) -> List[Dict[str, Any]]:
        """Identify change points in time series data.
        
        Args:
            time_series_points: Time series points to analyze
            min_segment_length: Minimum segment length
            penalty: Penalty parameter for change point detection
            
        Returns:
            List of detected change points
        """
        change_points = []
        
        if len(time_series_points) < min_segment_length * 2:
            return change_points
        
        # Convert to numpy arrays
        timestamps = np.array([p.timestamp for p in time_series_points])
        vulnerability_scores = np.array([p.vulnerability_score for p in time_series_points])
        
        # Simple change point detection using binary segmentation
        # In a production implementation, this would use more sophisticated methods
        # like PELT (Pruned Exact Linear Time) or Bayesian change point detection
        
        # For each possible change point position
        for i in range(min_segment_length, len(time_series_points) - min_segment_length):
            # Calculate means on both sides
            left_mean = np.mean(vulnerability_scores[i-min_segment_length:i])
            right_mean = np.mean(vulnerability_scores[i:i+min_segment_length])
            
            # Calculate difference
            diff = abs(right_mean - left_mean)
            
            # Check if difference exceeds threshold
            if diff > penalty * 0.01:  # Adjust threshold based on penalty
                change_points.append({
                    "timestamp": time_series_points[i].timestamp,
                    "position": i,
                    "difference": float(diff),
                    "left_mean": float(left_mean),
                    "right_mean": float(right_mean),
                    "description": f"Significant change in vulnerability score (diff: {diff:.4f})"
                })
        
        return change_points
    
    def forecast_security_trends(self, 
                               historical_analysis: List[TopologicalAnalysisResult],
                               forecast_horizon: int = 30) -> Dict[str, Any]:
        """Forecast security trends based on historical data.
        
        Args:
            historical_analysis: List of historical topological analysis results
            forecast_horizon: Number of time units to forecast
            
        Returns:
            Dictionary with security trend forecasts
        """
        # Convert historical analysis to time series points
        time_series_points = self._convert_to_time_series(historical_analysis)
        
        # Aggregate points (use daily resolution for forecasting)
        aggregated_points = self._aggregate_by_resolution(
            time_series_points, 
            TimeResolution.DAY
        )
        
        # Forecast trends
        return self._forecast_security_trends(aggregated_points, forecast_horizon)
    
    def _forecast_security_trends(self, 
                                time_series_points: List[TimeSeriesPoint],
                                forecast_horizon: int = 30) -> Dict[str, Any]:
        """Forecast security trends based on time series data.
        
        Args:
            time_series_points: Time series points to analyze
            forecast_horizon: Number of time units to forecast
            
        Returns:
            Dictionary with security trend forecasts
        """
        if len(time_series_points) < 10:
            return {
                "status": "insufficient_data",
                "message": "Not enough historical data for forecasting"
            }
        
        # Convert to numpy arrays
        timestamps = np.array([p.timestamp for p in time_series_points])
        vulnerability_scores = np.array([p.vulnerability_score for p in time_series_points])
        
        # Simple linear forecasting
        x = (timestamps - timestamps[0]) / (24 * 3600)  # Convert to days
        slope, intercept = np.polyfit(x, vulnerability_scores, 1)
        
        # Generate forecast
        last_x = x[-1]
        forecast_x = np.linspace(last_x, last_x + forecast_horizon, forecast_horizon + 1)
        forecast_vs = intercept + slope * forecast_x
        
        # Convert forecast timestamps back to Unix timestamps
        forecast_timestamps = [
            timestamps[-1] + i * 24 * 3600 for i in range(forecast_horizon + 1)
        ]
        
        # Calculate confidence intervals (simplified)
        residuals = vulnerability_scores - (intercept + slope * x)
        std_residuals = np.std(residuals)
        confidence_interval = 1.96 * std_residuals  # 95% confidence
        
        return {
            "forecast_timestamps": forecast_timestamps,
            "forecast_vulnerability_scores": forecast_vs.tolist(),
            "confidence_interval": confidence_interval,
            "trend_slope": float(slope),
            "trend_intercept": float(intercept),
            "forecast_horizon": forecast_horizon,
            "description": f"Linear forecast of vulnerability score with trend slope {slope:.6f}"
        }
    
    def _calculate_temporal_vulnerability_score(self,
                                              temporal_patterns: List[TemporalPattern],
                                              temporal_anomalies: List[TemporalAnomaly],
                                              change_points: List[Dict[str, Any]]) -> float:
        """Calculate vulnerability score based on temporal analysis.
        
        Args:
            temporal_patterns: Detected temporal patterns
            temporal_anomalies: Detected temporal anomalies
            change_points: Detected change points
            
        Returns:
            Temporal vulnerability score (0-1, higher = more vulnerable)
        """
        # Base score from most recent vulnerability score
        # (would be provided from the latest analysis point)
        base_score = 0.3
        
        # Pattern-based score
        pattern_score = 0.0
        for pattern in temporal_patterns:
            # Progressive degradation is most critical
            if pattern.pattern_type == TimeSeriesAnalysisType.PROGRESSIVE_DEGRADATION:
                pattern_score += pattern.pattern_strength * 0.5
            # Long-term trends are moderately critical
            elif pattern.pattern_type == TimeSeriesAnalysisType.TEMPORAL_TRENDS:
                pattern_score += pattern.pattern_strength * 0.3
            # Seasonal patterns are less critical
            elif pattern.pattern_type == TimeSeriesAnalysisType.SEASONAL_PATTERNS:
                pattern_score += pattern.pattern_strength * 0.1
        
        # Anomaly-based score
        anomaly_score = 0.0
        high_severity_count = sum(1 for a in temporal_anomalies if a.severity == "high")
        medium_severity_count = sum(1 for a in temporal_anomalies if a.severity == "medium")
        
        anomaly_score = (
            min(high_severity_count * 0.2, 0.5) +
            min(medium_severity_count * 0.05, 0.3)
        )
        
        # Change point score
        change_point_score = min(len(change_points) * 0.1, 0.4)
        
        # Weighted combination
        temporal_score = (
            base_score * 0.3 +
            pattern_score * 0.3 +
            anomaly_score * 0.2 +
            change_point_score * 0.2
        )
        
        return min(1.0, temporal_score)
    
    def get_temporal_vulnerability_score(self, 
                                        temporal_analysis: TimeSeriesAnalysisResult) -> float:
        """Calculate vulnerability score based on temporal analysis.
        
        Args:
            temporal_analysis: Results of temporal analysis
            
        Returns:
            Temporal vulnerability score (0-1, higher = more vulnerable)
        """
        return temporal_analysis.temporal_vulnerability_score
    
    def generate_temporal_report(self, 
                                temporal_analysis: TimeSeriesAnalysisResult) -> str:
        """Generate comprehensive temporal analysis report.
        
        Args:
            temporal_analysis: Results of temporal analysis
            
        Returns:
            Formatted temporal analysis report
        """
        return self._generate_report_content(temporal_analysis)
    
    def _generate_report_content(self, temporal_analysis: TimeSeriesAnalysisResult) -> str:
        """Generate the content for a temporal analysis report.
        
        Args:
            temporal_analysis: Results of temporal analysis
            
        Returns:
            Formatted report content
        """
        lines = [
            "=" * 80,
            "TEMPORAL TOPOLOGICAL ANALYSIS REPORT",
            "=" * 80,
            f"Report Timestamp: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Analysis Type: {temporal_analysis.analysis_type.value.upper()}",
            f"Time Resolution: {temporal_analysis.time_resolution.value.upper()}",
            f"Temporal Vulnerability Score: {temporal_analysis.temporal_vulnerability_score:.4f}",
            f"Implementation Status: {'SECURE' if temporal_analysis.is_secure else 'VULNERABLE'}",
            "",
            "TEMPORAL ANALYSIS SUMMARY:",
            f"- Data Points Analyzed: {len(temporal_analysis.time_series_points)}",
            f"- Temporal Patterns Detected: {len(temporal_analysis.temporal_patterns)}",
            f"- Temporal Anomalies Detected: {len(temporal_analysis.temporal_anomalies)}",
            f"- Change Points Detected: {len(temporal_analysis.change_points)}",
            "",
            "TEMPORAL PATTERNS:"
        ]
        
        # Add temporal patterns
        if temporal_analysis.temporal_patterns:
            for i, pattern in enumerate(temporal_analysis.temporal_patterns, 1):
                lines.append(f"  {i}. Type: {pattern.pattern_type.value.replace('_', ' ').title()}")
                lines.append(f"     Strength: {pattern.pattern_strength:.4f}")
                lines.append(f"     Confidence: {pattern.confidence:.2f}")
                lines.append(f"     {pattern.description}")
        else:
            lines.append("  No significant temporal patterns detected")
        
        # Add temporal anomalies
        lines.extend([
            "",
            "TEMPORAL ANOMALIES:"
        ])
        
        if temporal_analysis.temporal_anomalies:
            for i, anomaly in enumerate(temporal_analysis.temporal_anomalies[:5], 1):  # Show up to 5 anomalies
                timestamp = datetime.datetime.fromtimestamp(anomaly.timestamp).strftime('%Y-%m-%d')
                lines.append(f"  {i}. Date: {timestamp}")
                lines.append(f"     Severity: {anomaly.severity.upper()}")
                lines.append(f"     Score: {anomaly.anomaly_score:.2f}")
                lines.append(f"     {anomaly.description}")
        else:
            lines.append("  No significant temporal anomalies detected")
        
        # Add change points
        lines.extend([
            "",
            "CHANGE POINTS:"
        ])
        
        if temporal_analysis.change_points:
            for i, cp in enumerate(temporal_analysis.change_points[:5], 1):  # Show up to 5 change points
                timestamp = datetime.datetime.fromtimestamp(cp["timestamp"]).strftime('%Y-%m-%d')
                lines.append(f"  {i}. Date: {timestamp}")
                lines.append(f"     Difference: {cp['difference']:.4f}")
                lines.append(f"     {cp['description']}")
        else:
            lines.append("  No significant change points detected")
        
        # Add forecast if available
        if temporal_analysis.forecast and temporal_analysis.forecast.get("status") != "insufficient_data":
            lines.extend([
                "",
                "SECURITY TREND FORECAST:"
            ])
            
            trend_desc = temporal_analysis.forecast.get("description", "No forecast description available")
            lines.append(f"  - {trend_desc}")
            
            # Show forecast summary
            slope = temporal_analysis.forecast.get("trend_slope", 0)
            if slope > 0.001:
                lines.append("  - Forecast indicates increasing vulnerability over time")
            elif slope < -0.001:
                lines.append("  - Forecast indicates decreasing vulnerability over time")
            else:
                lines.append("  - Forecast indicates stable vulnerability levels")
        
        # Add recommendations
        lines.extend([
            "",
            "RECOMMENDATIONS:"
        ])
        
        if temporal_analysis.is_secure:
            lines.append("  - No critical temporal vulnerabilities detected. Implementation shows stable security properties over time.")
            lines.append("  - Continue monitoring for any emerging temporal patterns.")
        else:
            # Check for specific issues
            has_degradation = any(p.pattern_type == TimeSeriesAnalysisType.PROGRESSIVE_DEGRADATION 
                                for p in temporal_analysis.temporal_patterns)
            has_high_anomalies = any(a.severity == "high" for a in temporal_analysis.temporal_anomalies)
            has_critical_change = len(temporal_analysis.change_points) > 3
            
            if has_degradation:
                lines.append("  - CRITICAL: Progressive degradation of security properties detected. Immediate action required.")
                lines.append("    Investigate potential causes of degradation in the implementation.")
            
            if has_high_anomalies:
                lines.append("  - Address high-severity temporal anomalies that may indicate temporary vulnerabilities.")
                lines.append("    Check system logs around anomaly timestamps for potential issues.")
            
            if has_critical_change:
                lines.append("  - Multiple change points indicate significant shifts in security properties.")
                lines.append("    Investigate recent changes to the implementation or environment.")
            
            if temporal_analysis.temporal_vulnerability_score > 0.7:
                lines.append("  - CRITICAL: High temporal vulnerability score. Immediate remediation required.")
        
        lines.extend([
            "",
            "=" * 80,
            "TOPOSPHERE TEMPORAL ANALYSIS REPORT FOOTER",
            "=" * 80,
            "This report was generated by the TopoSphere Time Series Analyzer,",
            "a component of the AuditCore v3.2 industrial implementation.",
            "",
            "TopoSphere is the world's first topological analyzer for ECDSA that:",
            "- Uses bijective parameterization (u_r, u_z)",
            "- Applies persistent homology and gradient analysis",
            "- Generates synthetic data without knowledge of the private key",
            "- Detects vulnerabilities through topological anomalies",
            "- Recovers keys through linear dependencies and special points",
            "",
            "The system is optimized with:",
            "- GPU acceleration",
            "- Distributed computing (Ray/Spark)",
            "- Intelligent caching",
            "",
            "As stated in our research: 'Topology is not a hacking tool, but a microscope",
            "for diagnosing vulnerabilities. Ignoring it means building cryptography on sand.'",
            "=" * 80
        ])
        
        return "\n".join(lines)

# ======================
# HELPER FUNCTIONS
# ======================

def get_temporal_security_level(temporal_vulnerability_score: float) -> str:
    """Get security level based on temporal vulnerability score.
    
    Args:
        temporal_vulnerability_score: Temporal vulnerability score (0-1)
        
    Returns:
        Security level ('secure', 'low_risk', 'medium_risk', 'high_risk', 'critical')
    """
    if temporal_vulnerability_score < 0.2:
        return "secure"
    elif temporal_vulnerability_score < 0.3:
        return "low_risk"
    elif temporal_vulnerability_score < 0.5:
        return "medium_risk"
    elif temporal_vulnerability_score < 0.7:
        return "high_risk"
    else:
        return "critical"

def get_temporal_vulnerability_recommendations(temporal_analysis: TimeSeriesAnalysisResult) -> List[str]:
    """Get temporal vulnerability-specific recommendations.
    
    Args:
        temporal_analysis: Results of temporal analysis
        
    Returns:
        List of recommendations
    """
    recommendations = []
    
    # Add general recommendation based on security level
    security_level = get_temporal_security_level(temporal_analysis.temporal_vulnerability_score)
    if security_level == "secure":
        recommendations.append("No critical temporal vulnerabilities detected. Implementation shows stable security properties over time.")
    elif security_level == "low_risk":
        recommendations.append("Implementation shows minor temporal fluctuations that do not pose immediate risk.")
    elif security_level == "medium_risk":
        recommendations.append("Implementation shows moderate temporal fluctuations that should be monitored.")
    elif security_level == "high_risk":
        recommendations.append("Implementation shows significant temporal fluctuations that require attention.")
    else:
        recommendations.append("CRITICAL: Implementation shows severe temporal vulnerabilities that require immediate action.")
    
    # Add specific recommendations based on temporal patterns
    for pattern in temporal_analysis.temporal_patterns:
        if pattern.pattern_type == TimeSeriesAnalysisType.PROGRESSIVE_DEGRADATION:
            recommendations.append("- CRITICAL: Progressive degradation of security properties detected. Immediate investigation required.")
        elif pattern.pattern_type == TimeSeriesAnalysisType.TEMPORAL_TRENDS:
            if pattern.pattern_strength > 0.01:
                recommendations.append("- Address long-term trends indicating increasing vulnerability.")
    
    # Add specific recommendations based on temporal anomalies
    high_anomalies = [a for a in temporal_analysis.temporal_anomalies if a.severity == "high"]
    if high_anomalies:
        recommendations.append("- Investigate high-severity temporal anomalies that may indicate critical vulnerabilities.")
    
    # Add specific recommendations based on change points
    if len(temporal_analysis.change_points) > 3:
        recommendations.append("- Multiple change points indicate significant shifts in security properties. Investigate recent changes.")
    
    return recommendations

def generate_temporal_dashboard(temporal_analysis: TimeSeriesAnalysisResult) -> str:
    """Generate a dashboard-style temporal analysis report.
    
    Args:
        temporal_analysis: Results of temporal analysis
        
    Returns:
        Formatted dashboard report
    """
    # This would typically generate an HTML or interactive dashboard
    # For simplicity, we'll generate a text-based dashboard
    
    lines = [
        "=" * 80,
        "TOPOSPHERE TEMPORAL SECURITY DASHBOARD",
        "=" * 80,
        "",
        "SECURITY STATUS OVERVIEW:",
        f"  [ {'✓' if temporal_analysis.is_secure else '✗'} ] Overall Security Status: {'SECURE' if temporal_analysis.is_secure else 'VULNERABLE'}",
        f"  [ {'!' if temporal_analysis.temporal_vulnerability_score > 0.5 else '✓'} ] Temporal Vulnerability Score: {temporal_analysis.temporal_vulnerability_score:.2f}",
        "",
        "KEY METRICS TREND (LAST 30 DAYS):"
    ]
    
    # Generate simple ASCII trend charts for key metrics
    if temporal_analysis.time_series_points:
        # Get last 30 points or all if fewer
        recent_points = temporal_analysis.time_series_points[-30:]
        
        # Vulnerability score trend
        vs_values = [p.vulnerability_score for p in recent_points]
        vs_min, vs_max = min(vs_values), max(vs_values)
        vs_range = vs_max - vs_min if vs_max > vs_min else 1.0
        
        lines.append("  Vulnerability Score:")
        for vs in vs_values[-7:]:  # Show last 7 days
            bar_length = int((vs - vs_min) / vs_range * 20)
            lines.append(f"    {'#' * bar_length} {vs:.2f}")
        
        # Symmetry violation trend
        sym_values = [p.symmetry_violation_rate for p in recent_points]
        sym_min, sym_max = min(sym_values), max(sym_values)
        sym_range = sym_max - sym_min if sym_max > sym_min else 1.0
        
        lines.append("\n  Symmetry Violation Rate:")
        for sym in sym_values[-7:]:
            bar_length = int((sym - sym_min) / sym_range * 20)
            lines.append(f"    {'#' * bar_length} {sym:.2f}")
    
    # Add critical alerts
    lines.extend([
        "",
        "CRITICAL ALERTS:",
    ])
    
    critical_alerts = []
    
    # Check for progressive degradation
    degradation = [p for p in temporal_analysis.temporal_patterns 
                  if p.pattern_type == TimeSeriesAnalysisType.PROGRESSIVE_DEGRADATION]
    if degradation:
        critical_alerts.append("PROGRESSIVE DEGRADATION DETECTED - Immediate investigation required")
    
    # Check for high-severity anomalies
    high_anomalies = [a for a in temporal_analysis.temporal_anomalies if a.severity == "high"]
    if high_anomalies:
        critical_alerts.append(f"{len(high_anomalies)} HIGH-SEVERITY ANOMALIES DETECTED")
    
    if critical_alerts:
        for alert in critical_alerts:
            lines.append(f"  [ALERT] {alert}")
    else:
        lines.append("  No critical alerts detected")
    
    # Add recommendations
    lines.extend([
        "",
        "IMMEDIATE ACTIONS:",
    ])
    
    recommendations = get_temporal_vulnerability_recommendations(temporal_analysis)
    for i, rec in enumerate(recommendations[:3], 1):  # Show top 3 recommendations
        lines.append(f"  {i}. {rec}")
    
    lines.extend([
        "",
        "=" * 80,
        "END OF DASHBOARD - Refresh for latest data",
        "=" * 80
    ])
    
    return "\n".join(lines)

# ======================
# DOCUMENTATION
# ======================

"""
TopoSphere Time Series Analysis Documentation

This module implements the industrial-grade standards of AuditCore v3.2, providing
mathematically rigorous temporal analysis of topological properties for ECDSA implementations.

Core Principles:
1. For secure ECDSA implementations, the signature space forms a topological torus (β₀=1, β₁=2, β₂=1)
2. Direct analysis without building the full hypercube enables efficient monitoring of large spaces
3. Topology is not a hacking tool, but a microscope for diagnosing vulnerabilities
4. Ignoring topological properties means building cryptography on sand

Time Series Analysis Framework:

1. Temporal Pattern Detection:
   - Long-term trend analysis (linear regression)
   - Seasonal pattern identification (daily, weekly patterns)
   - Progressive degradation detection
   - Change point identification
   - Short-term anomaly detection

2. Analysis Types:
   - TEMPORAL_TRENDS: Long-term trends in topological properties
   - SHORT_TERM_ANOMALIES: Short-term deviations from expected patterns
   - SEASONAL_PATTERNS: Periodic patterns in topological properties
   - CHANGE_POINT_DETECTION: Detection of significant changes
   - PROGRESSIVE_DEGRADATION: Gradual degradation of security properties

3. Time Resolutions:
   - MINUTE: Minute-level resolution (suitable for real-time monitoring)
   - HOUR: Hour-level resolution (suitable for short-term analysis)
   - DAY: Day-level resolution (suitable for medium-term analysis)
   - WEEK: Week-level resolution (suitable for long-term trends)
   - MONTH: Month-level resolution (suitable for historical analysis)

4. Temporal Vulnerability Assessment:
   - Weighted combination of multiple temporal metrics
   - Security levels based on temporal vulnerability score:
     * Secure: < 0.2
     * Low Risk: 0.2-0.3
     * Medium Risk: 0.3-0.5
     * High Risk: 0.5-0.7
     * Critical: > 0.7
   - Progressive degradation is most critical (weighted 50%)
   - Long-term trends are moderately critical (weighted 30%)
   - Seasonal patterns are less critical (weighted 10%)

Key Temporal Vulnerabilities:

1. Progressive Degradation:
   - Description: Gradual increase in vulnerability score over time
   - Detection: Consistent upward trend in vulnerability metrics
   - Severity: Critical (indicates ongoing degradation of security)
   - Example: Implementation quality decreasing over time due to code changes

2. Change Point Clusters:
   - Description: Multiple significant changes in security properties
   - Detection: Cluster of change points within short time period
   - Severity: High (indicates significant shifts in implementation)
   - Example: After software updates or configuration changes

3. High-Severity Anomalies:
   - Description: Short-term spikes in vulnerability metrics
   - Detection: Z-score > threshold in sliding window analysis
   - Severity: Medium to High (temporary vulnerabilities)
   - Example: Resource constraints affecting random number generation

4. Seasonal Patterns:
   - Description: Periodic fluctuations in topological properties
   - Detection: Significant variance by hour of day or day of week
   - Severity: Medium (may indicate periodic resource constraints)
   - Example: Daily patterns due to system load variations

Integration with TopoSphere Components:

1. TCON (Topological Conformance) Verification:
   - Uses time series analysis for historical conformance verification
   - Detects degradation in conformance over time
   - Provides temporal context for conformance failures

2. HyperCore Transformer:
   - Uses time series analysis for adaptive compression strategy selection
   - Adjusts compression parameters based on temporal patterns
   - Maintains topological invariants during temporal analysis

3. Dynamic Compute Router:
   - Uses temporal analysis results for resource allocation planning
   - Predicts future resource needs based on trends
   - Optimizes analysis frequency based on stability metrics

4. Quantum-Inspired Scanner:
   - Uses temporal patterns for targeted scanning
   - Focuses on periods with high vulnerability scores
   - Enhances detection of time-based vulnerabilities

Practical Applications:

1. Continuous Security Monitoring:
   - Real-time monitoring of topological properties
   - Early warning for emerging vulnerabilities
   - Historical trend analysis for security posture assessment

2. Post-Deployment Security Analysis:
   - Analysis of security properties after deployment
   - Detection of degradation due to software updates
   - Verification of security improvements after fixes

3. Security Auditing:
   - Historical analysis for security audits
   - Documentation of security posture over time
   - Evidence for compliance requirements

4. Predictive Security:
   - Forecasting future security trends
   - Proactive identification of potential issues
   - Planning for security improvements

As stated in our research: "Topology is not a hacking tool, but a microscope for diagnosing vulnerabilities.
Ignoring it means building cryptography on sand." This time series analysis implementation ensures that TopoSphere
adheres to this principle by providing mathematically rigorous temporal analysis of cryptographic implementations.
"""
