"""szl-eclipse: mutation-testing for receipt verifiers."""

from .eclipse import MUTATIONS, eclipse_run, golden_chain

__all__ = ["MUTATIONS", "eclipse_run", "golden_chain"]
__version__ = "0.1.0"
