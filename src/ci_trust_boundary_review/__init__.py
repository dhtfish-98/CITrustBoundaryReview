"""CITrustBoundaryReview: finite offline workflow trust-boundary analysis."""

from .contracts import Limits
from .review import RULES, review

__all__ = ["Limits", "RULES", "review"]
__version__ = "0.1.2"
