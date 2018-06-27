
import logging

from .base import SimSootStmt

l = logging.getLogger(name=__name__)


class SimSootStmt_Invoke(SimSootStmt):
    def _execute(self):
        invoke_expr = self._translate_expr(self.stmt.invoke_expr)
        self._add_invoke_target(invoke_expr)
