from .base import SimSootExpr
from .paramref import SimSootExpr_ParamRef
from .arrayref import SimSootExpr_ArrayRef


class SimSootExpr_Length(SimSootExpr):
    def _execute(self):
        operand = self._translate_expr(self.expr.value)
        self.expr = operand.expr.size
