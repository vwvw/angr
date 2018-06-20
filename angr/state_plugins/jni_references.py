
import logging

from ..sim_state import SimState
from .plugin import SimStatePlugin

l = logging.getLogger("angr.state_plugins.jni_references")


class SimStateJNIReferences(SimStatePlugin):
    """
    Management of the mapping between opaque JNI references and the
    corresponding Java objects.
    """

<<<<<<< f6ceaa1c1e88e0e79b084a7078e01fff0200bbea
    def __init__(self, local_refs=None, global_refs=None):
        super(SimStateJNIReferences, self).__init__()
        self.local_refs = local_refs if local_refs else {}
        self.global_refs = global_refs if global_refs else {}
=======
    def __init__(self, local_refs={}, global_refs={}):
        super(SimStateJNIReferences, self).__init__()
        self.local_refs = local_refs
        self.global_refs = global_refs
>>>>>>> Add support for global jni references

    def lookup(self, opaque_ref):
        """
        Lookups the object that was used for creating the reference.
        """
        opaque_ref_value = self._get_reference_value(opaque_ref)
<<<<<<< f6ceaa1c1e88e0e79b084a7078e01fff0200bbea
        # check local refs
        if opaque_ref_value in self.local_refs:
            return self.local_refs[opaque_ref_value]
        # check global refs
        if opaque_ref_value in self.global_refs:
            return self.global_refs[opaque_ref_value]
        raise KeyError("Unknown JNI reference %d. Local references: %s Global references: %s"
                       % (opaque_ref_value, self.local_refs, self.global_refs))

    def create_new_reference(self, obj, global_ref=False):
        """
        Create a new reference thats maps to the given object.

        :param obj:              Object which gets referenced.
        :param bool global_ref:  Whether a local or global reference is created.
        """
        # get an unique address
        opaque_ref = self.state.project.loader.extern_object.allocate()
        # map the object to that address
        l.debug("Map %s to opaque reference 0x%x", obj, opaque_ref)
        if global_ref:
            self.global_refs[opaque_ref] = obj
        else:
            self.local_refs[opaque_ref] = obj
        return opaque_ref

    def clear_local_references(self):
        """
        Clear all local references.
        """
        self.local_refs = {}

    def delete_reference(self, opaque_ref, global_ref=False):
        """
        Delete the stored mapping of a reference.

        :param opaque_ref:       Reference which should be removed.
        :param bool global_ref:  Whether opaque_ref is a local or global
                                 reference.
        """
=======
        if opaque_ref_value in self.local_refs:
            return self.local_refs[opaque_ref_value]
        if opaque_ref_value in self.global_refs:
            return self.global_refs[opaque_ref_value]
        raise KeyError("Unknown jni reference %d. Local references: %s Global references: %s"
                       "" % (opaque_ref_value, self.local_refs, self.global_refs))

    def create_new_reference(self, java_ref, global_ref=False):
        opaque_ref = self.state.project.loader.extern_object.allocate()
        if global_ref:
            self.global_refs[opaque_ref] = java_ref
        else:
            self.local_refs[opaque_ref] = java_ref
        l.debug("Map %s to opaque reference %s" % (str(java_ref), hex(opaque_ref)))
        return opaque_ref

    def delete_reference(self, opaque_ref, global_ref=False):
>>>>>>> Add support for global jni references
        opaque_ref_value = self._get_reference_value(opaque_ref)
        if global_ref:
            del self.global_refs[opaque_ref_value]
        else:
            del self.local_refs[opaque_ref_value]

    def _get_reference_value(self, opaque_ref):
        if self.state.solver.symbolic(opaque_ref):
            raise NotImplementedError("Opaque reference %s is symbolic." % opaque_ref.to_claripy())
        return self.state.solver.eval(opaque_ref)

    def clear_local_references(self):
        self.local_refs = {}

    @SimStatePlugin.memo
<<<<<<< f6ceaa1c1e88e0e79b084a7078e01fff0200bbea
    def copy(self, memo): # pylint: disable=unused-argument
        return SimStateJNIReferences(local_refs=self.local_refs,
                                     global_refs=self.global_refs)

    def merge(self, others, merge_conditions, common_ancestor=None): # pylint: disable=unused-argument
        l.warning("Merging is not implemented for JNI references!")
        return False
=======
    def copy(self, memo):
        return SimStateJNIReferences(local_refs=self.local_refs,
                                     global_refs=self.global_refs)
>>>>>>> Add support for global jni references

    def widen(self, others): # pylint: disable=unused-argument
        l.warning("Widening is not implemented for JNI references!")
        return False

# TODO use a default JavaVM preset
#      see for reference: angr/engines/__init__.py
SimState.register_default('jni_references', SimStateJNIReferences)
