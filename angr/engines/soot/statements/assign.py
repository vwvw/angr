
<<<<<<< 6834cbf7956e38068d30e8d5a29519443b4ef06e
import logging

from ..expressions.invoke import InvokeBase
from .base import SimSootStmt

l = logging.getLogger('angr.engines.soot.statements.assign')


class SimSootStmt_Assign(SimSootStmt):
    def _execute(self):
        dst = self._translate_value(self.stmt.left_op)
        src_expr = self._translate_expr(self.stmt.right_op)
        if isinstance(src_expr, InvokeBase):
            # right hand side of the the assignment is an invocation
            # => The assumption is that if the src_expr contains an invoke, it
            #    is always just that invoke. In other words, the only possible
            #    form of "invoke in assignment" is: reg = invoke.
            #    This requirement *should* be enforced by the lifting to Soot IR.
            # => We deal with the invoke assignment, by
            #    1) saving the destination variable
            #    2) executing the function
            #    3) assign the return value to the destination variables
            #       after the function returns
            self._add_invoke_target(invoke_expr=src_expr, ret_var=dst)
            # exit prematurely
            return
        src_val = src_expr.expr
        l.debug("Assign %r := %r", dst, src_val)
=======
from .base import SimSootStmt
from ..expressions import SimSootExpr_NewArray
from ..values import SimSootValue_ArrayRef
import logging


l = logging.getLogger('angr.engines.soot.statements.assign')

class SimSootStmt_Assign(SimSootStmt):
    def __init__(self, stmt, state):
        super(SimSootStmt_Assign, self).__init__(stmt, state)

    def _execute(self):
        dst = self._translate_value(self.stmt.left_op)
        src_expr = self._translate_expr(self.stmt.right_op)
        # The assumption here is that if src_expr contains an invoke, src_expr is just that invoke.
        # In other words, the only possible form of "invoke in assignment" is: reg = invoke
        if self.state.scratch.invoke:
            # what we do in case of invoke is that we deal with this assignment when we the engine applies
            # a special cases for invokes
            # local_var = Invoke(args)
            self.state.scratch.invoke_return_variable = dst
            # exits prematurely
            return

        src_val = src_expr.expr
        l.debug("Assigning %s to %s" % (src_val, dst))
>>>>>>> Preliminary Java support.
        self.state.memory.store(dst, src_val)
