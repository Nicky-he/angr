import logging
import claripy

l = logging.getLogger("angr.state_plugins.history")

from .plugin import SimStatePlugin
class SimStateHistory(SimStatePlugin):
    """
    This class keeps track of historically-relevant information for paths.
    """

    __slots__ = (
        'parent', 'merged_from', 'merge_conditions', 'length',
        'extra_length', '_addrs', '_runstr', '_target', '_guard',
        '_jumpkind', '_events', '_jump_source', '_jump_avoidable',
        '_all_constraints', '_fresh_constraints', '_satisfiable',
        '_state_strong_ref', '_state_weak_ref', '__weakref__'
    )

    def __init__(self, parent=None):
        SimStatePlugin.__init__(self)

        self.parent = parent
        self.merged_from = [ ]
        self.merge_conditions = [ ]
        self._runstr = None
        self._target = None
        self._jump_source = None
        self._jump_avoidable = None
        self._guard = None
        self._jumpkind = None
        self._events = None
        self._addrs = ()

        self.length = 0 if parent is None else parent.length + 1
        self.extra_length = 0 if parent is None else parent.extra_length

        self.executed_block_count = 0 # the number of blocks that was executed here
        self.executed_syscall_count = 0 # the number of system calls that was executed here
        self.executed_instruction_count = -1 # the number of instructions that was executed

        # satness stuff
        self._all_constraints = ()
        self._fresh_constraints = ()
        self._satisfiable = None

    def merge(self, others, merge_conditions, common_ancestor=None):
        raise Exception('TODO')

    def widen(self, others):
        raise Exception('TODO')

    def copy(self):
        c = SimStateHistory()
        c.parent = self.parent
        c.merged_from = list(self.merged_from)
        c.merge_conditions = list(self.merge_conditions)
        c._runstr = self._runstr
        c._target = self._target
        c._jump_source = self._jump_source
        c._jump_avoidable = self._jump_avoidable
        c._guard = self._guard
        c._jumpkind = self._jumpkind
        c._events = self._events
        c._addrs = self._addrs

        c.length = self.length
        c.extra_length = self.extra_length

        c._all_constraints = list(self._all_constraints)
        c._fresh_constraints = list(self._fresh_constraints)
        c._satisfiable = self._satisfiable

        c.executed_block_count = self.executed_block_count
        c.executed_syscall_count = self.executed_syscall_count
        c.executed_instruction_count = self.executed_instruction_count

        return c

    def __getstate__(self):
        return [
            (k, getattr(self, k)) for k in self.__slots__ if k not in
            ('__weakref__', '_state_weak_ref')
        ]

    def __setstate__(self, state):
        for k,v in state:
            setattr(self, k, v)

    #def _record_state(self, state, strong_reference=True):
    #   self._jumpkind = state.scratch.jumpkind
    #   self._jump_source = state.scratch.source
    #   self._jump_avoidable = state.scratch.avoidable
    #   self._target = state.scratch.target
    #   self._guard = state.scratch.guard
    #
    #   if state.scratch.bbl_addr_list is not None:
    #       self._addrs = state.scratch.bbl_addr_list
    #   elif state.scratch.bbl_addr is not None:
    #       self._addrs = [ state.scratch.bbl_addr ]
    #   else:
    #       # state.scratch.bbl_addr may not be initialized as final states from the "flat_successors" list. We need to get
    #       # the value from _target in that case.
    #       if self.addr is None and not self._target.symbolic:
    #           self._addrs = [ self._target._model_concrete.value ]
    #       else:
    #           # FIXME: redesign so this does not happen
    #           l.warning("Encountered a path to a SimProcedure with a symbolic target address.")
    #
    #   if o.UNICORN in state.options:
    #       self.extra_length += state.scratch.executed_block_count - 1
    #
    #   if o.TRACK_ACTION_HISTORY in state.options:
    #       self._events = state.history.events
    #
    #   # record constraints, added constraints, and satisfiability
    #   self._all_constraints = state.se.constraints
    #   self._fresh_constraints = state.history.fresh_constraints
    #
    #   if isinstance(state.se._solver, claripy.frontend_mixins.SatCacheMixin):
    #       self._satisfiable = state.se._solver._cached_satness
    #   else:
    #       self._satisfiable = None
    #
    #   # record the state as a weak reference
    #   self._state_weak_ref = weakref.ref(state)
    #
    #   # and as a strong ref
    #   if strong_reference:
    #       self._state_strong_ref = state

    def demote(self):
        """
        Demotes this PathHistory node, causing it to convert references to the state
        to weakrefs.
        """
        print "TODO: demote", self

    def reachable(self):
        if self._satisfiable is not None:
            pass
        elif self.state is not None:
            self._satisfiable = self.state.se.satisfiable()
        else:
            solver = claripy.Solver()
            solver.add(self._all_constraints)
            self._satisfiable = solver.satisfiable()

        return self._satisfiable

    #
    # Log handling
    #

    def add_event(self, event_type, **kwargs):
        new_event = SimEvent(self.state, event_type, **kwargs)
        self._events.append(new_event)

    def add_action(self, action):
        self._events.append(action)

    def extend_actions(self, new_actions):
        self._events.extend(new_actions)

    #
    # Convenient accessors
    #

    @property
    def last_events(self):
        return ( ev for ev in self._events )
    @property
    def last_actions(self):
        return ( ev for ev in self.last_events if isinstance(ev, SimAction) )
    @property
    def last_jumpkind(self):
        return self._jumpkind
    @property
    def last_guard(self):
        return self._guard
    @property
    def last_target(self):
        return self._target
    @property
    def last_description(self):
        return self._runstr
    @property
    def last_addr(self):
        return self._addrs[0]
    @last_addr.setter
    def last_addr(self, v):
        self._addrs = [ v ]
    @property
    def last_addrs(self):
        return self._addrs

    @property
    def parents(self):
        return HistoryIter(self)
    @property
    def events(self):
        return EventIter(self)
    @property
    def actions(self):
        return ActionIter(self)
    @property
    def jumpkinds(self):
        return JumpkindIter(self)
    @property
    def guards(self):
        return GuardIter(self)
    @property
    def targets(self):
        return TargetIter(self)
    @property
    def descriptions(self):
        return RunstrIter(self)
    @property
    def addrs(self):
        return AddrIter(self)

    #
    # Merging support
    #

    def closest_common_ancestor(self, other):
        """
        Find the common ancestor between this PathHistory and 'other'.

        :param other:    the PathHistory to find a common ancestor with.
        :return:        the common ancestor PathHistory, or None if there isn't one
        """
        our_history_iter = reversed(HistoryIter(self))
        their_history_iter = reversed(HistoryIter(other))
        sofar = set()

        while True:
            our_done = False
            their_done = False

            try:
                our_next = next(our_history_iter)
                if our_next in sofar:
                    # we found it!
                    return our_next
                sofar.add(our_next)
            except StopIteration:
                # we ran out of items during iteration
                our_done = True

            try:
                their_next = next(their_history_iter)
                if their_next in sofar:
                    # we found it!
                    return their_next
                sofar.add(their_next)
            except StopIteration:
                # we ran out of items during iteration
                their_done = True

            # if we ran out of both lists, there's no common ancestor
            if our_done and their_done:
                return None

    def constraints_since(self, other):
        """
        Returns the constraints that have been accumulated since `other`.

        :param other: a prior PathHistory object
        :returns: a list of constraints
        """

        constraints = [ ]
        cur = self
        while cur is not other and cur is not None:
            constraints.extend(cur._fresh_constraints)
            cur = cur.parent
        return constraints

class TreeIter(object):
    def __init__(self, start, end=None):
        self._start = start
        self._end = end

    def _iter_nodes(self):
        n = self._start
        while n is not self._end:
            yield n
            n = n.parent

    def __iter__(self):
        for i in self.hardcopy:
            yield i

    def __reversed__(self):
        raise NotImplementedError("Why are you using this class")

    @property
    def hardcopy(self):
        # lmao
        return list(reversed(tuple(reversed(self))))

    def __len__(self):
        return self._start.length

    def __getitem__(self, k):
        if isinstance(k, slice):
            raise ValueError("Please use .hardcopy to use slices")
        if k >= 0:
            raise ValueError("Please use .hardcopy to use nonnegative indexes")
        i = 0
        for item in reversed(self):
            i -= 1
            if i == k:
                return item
        raise IndexError(k)

    def count(self, v):
        """
        Count occurrences of value v in the entire history. Note that the subclass must implement the __reversed__
        method, otherwise an exception will be thrown.
        :param object v: The value to look for
        :return: The number of occurrences
        :rtype: int
        """
        ctr = 0
        for item in reversed(self):
            if item == v:
                ctr += 1
        return ctr

class HistoryIter(TreeIter):
    def __reversed__(self):
        for hist in self._iter_nodes():
            yield hist

class AddrIter(TreeIter):
    def __reversed__(self):
        for hist in self._iter_nodes():
            for a in reversed(hist._addrs):
                yield a

class RunstrIter(TreeIter):
    def __reversed__(self):
        for hist in self._iter_nodes():
            if hist._runstr is not None:
                yield hist._runstr

class TargetIter(TreeIter):
    def __reversed__(self):
        for hist in self._iter_nodes():
            if hist._target is not None:
                yield hist._target

class GuardIter(TreeIter):
    def __reversed__(self):
        for hist in self._iter_nodes():
            if hist._guard is not None:
                yield hist._guard

class JumpkindIter(TreeIter):
    def __reversed__(self):
        for hist in self._iter_nodes():
            if hist._jumpkind is not None:
                yield hist._jumpkind

class EventIter(TreeIter):
    def __reversed__(self):
        for hist in self._iter_nodes():
            for ev in reversed(hist.events):
                yield ev

class ActionIter(TreeIter):
    def __reversed__(self):
        for hist in self._iter_nodes():
            for ev in reversed(hist.actions):
                yield ev

SimStateHistory.register_default('history', SimStateHistory)
from .sim_action import SimAction
from .sim_event import SimEvent
