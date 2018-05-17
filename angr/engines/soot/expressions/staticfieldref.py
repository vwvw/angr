
import logging
from .base import SimSootExpr

<<<<<<< 9619df3880c8f031cbdc56139e47ab078e34c3b2
=======
l = logging.getLogger('angr.engines.soot.expressions.staticfieldref')

class SimSootExpr_StaticFieldRef(SimSootExpr):
    def __init__(self, expr, state):
        super(SimSootExpr_StaticFieldRef, self).__init__(expr, state)
>>>>>>> Add staticfieldref loading

class SimSootExpr_StaticFieldRef(SimSootExpr):
    def _execute(self):
<<<<<<< 9619df3880c8f031cbdc56139e47ab078e34c3b2
        field_ref = self._translate_value(self.expr)
        self.expr = self.state.memory.load(field_ref, none_if_missing=True)
=======
        static_ref = self._translate_value(self.expr)
        value = self.state.memory.load(static_ref)
        if value is not None:
            self.expr = value
        else:
            l.warning("Trying to get a Static Field not loaded (%r)", static_ref)
>>>>>>> Add staticfieldref loading
