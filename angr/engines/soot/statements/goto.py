
import logging

from .base import SimSootStmt

l = logging.getLogger(name=__name__)


class SimSootStmt_Goto(SimSootStmt):
    def _execute(self):
        jmp_target = self._get_bb_addr_from_instr(instr=self.stmt.target)
        self._add_jmp_target(target=jmp_target,
                             condition=self.state.solver.true)
