
from .base import SimSootExpr


class SimSootExpr_Unsupported(SimSootExpr):
<<<<<<< 6834cbf7956e38068d30e8d5a29519443b4ef06e
=======
    def __init__(self, expr, state):
        super(SimSootExpr_Unsupported, self).__init__(expr, state)

>>>>>>> Preliminary Java support.
    def _execute(self):
        pass
