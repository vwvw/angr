<<<<<<< ba64bfe24a66aede49b3b9ac8738964ad2b41c1b

from ..java import JavaSimProcedure

=======
from ..java import JavaSimProcedure
from angr.engines.soot.values.thisref import SimSootValue_ThisRef
from angr.engines.soot.values.instancefieldref import SimSootValue_InstanceFieldRef
import logging

import claripy
>>>>>>> Add sim procedure for Random.nextInt

class NextInt(JavaSimProcedure):

    __provides__ = (
        ("java.util.Random", "nextInt(int)"),
    )

<<<<<<< ba64bfe24a66aede49b3b9ac8738964ad2b41c1b
    def run(self, obj, bound): # pylint: disable=arguments-differ,unused-argument
=======
    def run(self, obj, bound):
>>>>>>> Add sim procedure for Random.nextInt
        rand = self.state.solver.BVS('rand', 32)
        self.state.solver.add(rand.UGE(0))
        self.state.solver.add(rand.ULT(bound))
        return rand
