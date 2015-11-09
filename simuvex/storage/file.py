from ..plugins.plugin import SimStatePlugin
from ..s_action_object import SimActionObject

import claripy
import logging
l = logging.getLogger("simuvex.storage.file")

# TODO: symbolic file positions
import itertools
file_counter = itertools.count()
dialogue_counter = itertools.count()

class Flags: # pylint: disable=W0232,
    O_RDONLY = 0
    O_WRTONLY = 1
    O_RDWR = 2
    O_APPEND = 4096
    O_ASYNC = 64
    O_CLOEXEC = 512
    # TODO mode for this flag
    O_CREAT = 256
    O_DIRECT = 262144
    O_DIRECTORY = 2097152
    O_EXCL = 2048
    O_LARGEFILE = 1048576
    O_NOATIME = 16777216
    O_NOCTTY = 1024
    O_NOFOLLOW = 4194304
    O_NONBLOCK = 8192
    O_NODELAY = 8192
    O_SYNC = 67174400
    O_TRUNC = 1024


def _deps_unpack(a):
    if isinstance(a, SimActionObject):
        return a.ast, a.reg_deps, a.tmp_deps
    else:
        return a, None, None


class SimFile(SimStatePlugin):
    # Creates a SimFile
    def __init__(self, name, mode, pos=0, content=None, size=None):
        super(SimFile, self).__init__()
        self.name = name
        self.mode = mode

        self.pos = pos

        self.size = size

        self.content = SimSymbolicMemory(memory_id="file_%s_%d" % (name, file_counter.next())) if content is None else content

    @property
    def read_pos(self):
        return self.pos

    @read_pos.setter
    def read_pos(self, val):
        self.pos = val

    @property
    def write_pos(self):
        return self.pos

    @write_pos.setter
    def write_pos(self, val):
        self.pos = val

    def set_state(self, st):
        super(SimFile, self).set_state(st)

        if isinstance(self.pos, (int, long)):
            self.pos = claripy.BVV(self.pos, st.arch.bits)

        if isinstance(self.size, (int, long)):
            self.size = claripy.BVV(self.size, st.arch.bits)

        self.content.set_state(st)

    def read(self, dst_addr, length):
        '''
        Reads some data from the current (or provided) position of the file.
        If dst_addr is specified, write it to that address.
        '''

        read_length = length
        if self.size is not None:
            remaining = self.size - self.pos
            read_length = self.state.se.If(remaining < length, remaining, length)

        self.content.copy_contents(dst_addr, self.pos, read_length , dst_memory=self.state.memory)

        self.read_pos += _deps_unpack(read_length)[0]
        return read_length

    def read_from(self, length):

        read_length = length
        if self.size is not None:
            remaining = self.size - self.pos
            read_length = self.state.se.If(remaining < length, remaining, length)

        data = self.content.load(self.pos, read_length)
        self.read_pos += _deps_unpack(read_length)[0]
        return data

    # Writes some data to the current position of the file.
    def write(self, content, length):
        # TODO: something about length
        self.content.store(self.pos, content)
        self.write_pos += _deps_unpack(length)[0]
        return length

    # Seeks to a position in the file.
    def seek(self, where):
        if isinstance(where, (int, long)):
            where = self.state.se.BVV(where, self.state.arch.bits)
        self.pos = where

    # Copies the SimFile object.
    def copy(self):
        return SimFile(self.name, self.mode, pos=self.pos, content=self.content.copy(), size=self.size)

    def all_bytes(self):
        indexes = self.content.mem.keys()
        if len(indexes) == 0:
            raise SimFileError('no content in file %s' % self.name)

        min_idx = min(indexes)
        max_idx = max(indexes)
        buff = [ ]
        for i in range(min_idx, max_idx+1):
            buff.append(self.content.load(i, 1))
        return self.state.se.Concat(*buff)

    # Merges the SimFile object with others
    def merge(self, others, merge_flag, flag_values):
        if not all(isinstance(oth, SimFile) for oth in others):
            raise SimMergeError("merging files of different types is not supported")

        all_files = list(others) + [ self ]

        if len(set(o.pos for o in all_files)) > 1:
            l.warning("Cheap HACK to support multiple file positions in a merge.")
            # self.pos = max(o.pos for o in all_files)
            # max cannot be used as file positions might be symbolic.
            max_pos = None
            for o in all_files:
                if max_pos is not None:
                    comp = self.state.se.simplify(max_pos >= o.pos)
                    if self.state.se.symbolic(comp):
                        import ipdb; ipdb.set_trace()
                        raise SimMergeError("merging file positions with symbolic max position is not ye supported (TODO)")

                    max_pos = o.pos if self.state.se.is_false(comp) else max_pos
                else:
                    max_pos = o.pos
            self.pos = max_pos

        #if len(set(o.name for o in all_files)) > 1:
        #   raise SimMergeError("merging file names is not yet supported (TODO)")

        #if len(set(o.mode for o in all_files)) > 1:
        #   raise SimMergeError("merging modes is not yet supported (TODO)")

        return self.content.merge([ o.content for o in others ], merge_flag, flag_values)

class SimDialogue(SimFile):
    '''
    Emulates a dialogue with a program. Enables us to perform concrete short reads.
    '''

    def __init__(self, name, dialogue_entries=None):
        super(SimDialogue, self).__init__(name, "r") # TODO: only read is supported, support writing

        # index into the dialog
        self.dialogue_pos = 0

        self.dialogue_entries = [ ] if dialogue_entries is None else dialogue_entries

    def set_state(self, st):
        super(SimDialogue, self).set_state(st)

        if isinstance(self.pos, (int, long)):
            self.pos = claripy.BVV(self.pos, st.arch.bits)

        if isinstance(self.size, (int, long)):
            self.size = claripy.BVV(self.size, st.arch.bits)

        self.content.set_state(st)
        for entry in self.dialogue_entries:
            entry.content.set_state(st)

    def add_dialogue_entry(self, dialogue_len):
        '''
        add a new dialogue piece to the end of the dialogue
        '''

        self.dialogue_entries.append(SimDialogueEntry(dialogue_len, self.name, self.state))

    def read(self, dst_addr, length):
        '''
        Reads some data from current dialogue entry, emulates short reads.
        '''

        # make sure there is a current dialogue
        try:
            entry = self.dialogue_entries.pop(0)
        except IndexError:
            return 0

        # this should always be a concrete value
        remaining = entry.length

        # two things can happen here:
        #  * we have a less than or equal amount of concrete content than the request read length
        #  * we have more concrete content than what was requested

        # we assume the length passed to read can always be concretized to a single value
        # because our dialogue entries will always be preconstrained
        lengths = self.state.se.any_n_int(length, 2)
        if len(lengths) > 1:
            raise ValueError("read called with a symbolic length which can be more than a single value")
        length_c = lengths[0]

        if remaining <= length_c:
            entry.content.copy_contents(dst_addr, 0, remaining, dst_memory=self.state.memory)
            return_length = remaining

        else:
            entry.content.copy_contents(dst_addr, 0, length_c, dst_memory=self.state.memory)
            return_length = length_c

            # now add the remaining content as a new dialogue on top of the dialogue list
            leftovers = entry.content.load(length_c, remaining - length_c)
            content = SimSymbolicMemory(memory_id='file_%s_dialogue_%d' % (entry.filename, dialogue_counter.next()))
            content.set_state(entry.content.state)
            content.store(0, leftovers)

            new_entry = SimDialogueEntry(remaining - length_c, entry.filename, content=content)
            self.dialogue_entries.insert(0, new_entry)

        return return_length

    def read_from(self, length):
        raise NotImplementedError

    # Copies the SimDialogue object.
    def copy(self):
        new_dialogue_entries = [entry.copy() for entry in self.dialogue_entries]
        return SimDialogue(self.name, dialogue_entries=new_dialogue_entries)

class SimDialogueEntry(object):
    '''
    one member of a dialogue
    '''

    def __init__(self, length, filename, state=None, content=None):

        self.length = length
        self.filename = filename
        self.content = SimSymbolicMemory(memory_id='file_%s_dialogue_%d' % (filename, dialogue_counter.next())) if content is None else content
        if not state is None:
            self.content.set_state(state)

    def copy(self):
        return SimDialogueEntry(self.length, self.filename, content=self.content.copy())



from ..plugins.symbolic_memory import SimSymbolicMemory
from ..s_errors import SimMergeError, SimFileError
