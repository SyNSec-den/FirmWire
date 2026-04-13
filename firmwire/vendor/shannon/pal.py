import struct

PALMsg_pattern = "<HHHH"
MSG_HEADER_SIZE = struct.calcsize(PALMsg_pattern)


class PALQueue:
    QUEUE_STRUCT_SIZE = 4 + 4 + 1 + (3) + 4 + 4
    QUEUE_NAME_PTR_OFFSET = 0x0
    QUEUE_QTYPE_OFFSET = 0x8
    QUEUE_ALIAS_OR_CALLBACK_OFFSET = 0xC

    QTYPE_NAMES = {
        0x1: "QTYPE_STANDARD",
        0x2: "QTYPE_CALLBACK_BIOS",
        0x3: "QTYPE_CALLBACK",
        0x4: "QTYPE_ALIAS",
        0x5: "QTYPE_WAKEUP",
    }

    def __init__(
        self,
        qid: int = 0,
        name: str = "",
        qtype: int = 0,
        type_name: str = "",
        queue_alias_or_callback: int = 0,
    ):
        self._qid = qid
        self._name = name
        self._qtype = qtype
        self._type_name = type_name
        self._queue_alias_or_callback = queue_alias_or_callback

    @property
    def qid(self):
        return self._qid

    @property
    def name(self):
        return self._name


class PALMsg:
    def __init__(
        self,
        src: PALQueue,
        dst: PALQueue,
        size: int,
        msg_id: int,
        data: bytes,
        msg_type: int,
    ):
        self._src_queue = src
        self._dst_queue = dst
        self._size = size
        self._msg_id = msg_id
        self._data = data
        self._msg_type = msg_type

    @property
    def src_queue(self):
        return self._src_queue

    @property
    def dst_queue(self):
        return self._dst_queue

    @property
    def size(self):
        return self._size

    @property
    def msg_id(self):
        return self._msg_id

    @property
    def data(self):
        return self._data

    def __repr__(self):
        return "PALMsg(%d)<0x%04x, %s (%x) -> %s (%x), %d bytes>" % (
            self._msg_type,
            self._msg_id,
            self._src_queue.name,
            self._src_queue.qid,
            self._dst_queue.name,
            self._dst_queue.qid,
            self._size,
        )
