#include <afl.h>
#include <shannon.h>

const char TASK_NAME[] = "LORIS\0";

/*  Loris fuzzer input is a Rust `LorisInput` (see fuzzer/src/input) serialized
 *  with bincode in little-endian, fixed-int mode. That encoding means:
 *    - every enum is prefixed by a 4-byte (u32) variant tag,
 *    - every Vec/String is prefixed by an 8-byte (u64) element/byte count,
 *    - the whole VendorInput blob is prefixed by a 4-byte (u32) length.
 *  The macros below decode exactly this wire format field by field.
 *
 *  Top-level layout (offsets are byte offsets into the work buffer):
 *      |----------------------------|
 * 0x00 | u32 size                   |  length of the blob == total - 4
 *      |----------------------------|
 * 0x04 | u32 VendorInput tag        |  0 = ShannonInput
 *      |----------------------------|
 * 0x08 | u32 ShannonInput tag       |  0 = Sael3Input, 1 = NasotInput
 *      |----------------------------|
 * 0x0c | u64 sequence length        |  number of messages in the Vec
 *      |----------------------------|
 * 0x14 | message[0 .. seq_len]      |  QItem (SAEL3) or SmpfEvent (NASOT)
 *      |----------------------------|
 *
 *  A SAEL3 message is a Rust `QItem` (header + payload):
 *      |----------------------------|
 * 0x00 | u32 QItemOperand tag       |  0 = Op, 1 = MBox, 2 = MBoxName
 *      |----------------------------|
 *      | operand (tag-dependent)    |  u32 op | {u16 src,u16 dst} | 2 strings
 *      |----------------------------|
 *      | u16 size                   |  payload size in bytes
 *      |----------------------------|
 *      | u16 message_group          |
 *      |----------------------------|
 *      | u64 payload field count    |  Vec<QItemPDU> length
 *      |----------------------------|
 *      | payload fields ...         |
 *      |----------------------------|
 */

void set_pre_state();

#define QUEUE_NAME_SZ 64

/* Primitive little-endian stream readers. Each reads one value from the cursor
 * `p`, advances `p` past it, and subtracts the consumed byte count from the
 * remaining-bytes counter `r`; if `r` is too small they run `handle` (usually
 * `return <errcode>`) before touching the stream.
 *
 * STREAM_TO_BYTE: read 1 byte -> u8 (consumes 1). */
#define STREAM_TO_BYTE(u8, p, r, handle)                          \
do {                                                              \
    if ((r) < 1) { handle; }                                      \
    (u8) = (uint8_t)(*(p));                                       \
    (p) += 1;                                                     \
    (r) -= 1;                                                     \
} while (0)

/* Read 2 LE bytes -> u16 (consumes 2). */
#define STREAM_TO_UINT16(u16, p, r, handle)                       \
do {                                                              \
    if ((r) < 2) { handle; }                                      \
    (u16) = ((uint16_t)(*(p)) + (((uint16_t)(*((p) + 1))) << 8)); \
    (p) += 2;                                                     \
    (r) -= 2;                                                     \
} while (0)

/* Read 4 LE bytes -> u32 (consumes 4). */
#define STREAM_TO_UINT32(u32, p, r, handle)                           \
do {                                                                  \
    if ((r) < 4) { handle; }                                          \
    (u32) = (((uint32_t)(*(p))) + ((((uint32_t)(*((p) + 1)))) << 8) + \
             ((((uint32_t)(*((p) + 2)))) << 16) +                     \
             ((((uint32_t)(*((p) + 3)))) << 24));                     \
    (p) += 4;                                                         \
    (r) -= 4;                                                         \
} while (0)

/* Read a bincode fixint u64: consumes 8 bytes but keeps only the low 32 bits
 * (used for Vec/String lengths, which never exceed 32 bits here; the upper 4
 * bytes are assumed zero and discarded). */
#define STREAM_TO_UINT64(u32, p, r, handle)                           \
do {                                                                  \
    if ((r) < 8) { handle; }                                          \
    (u32) = (((uint32_t)(*(p))) + ((((uint32_t)(*((p) + 1)))) << 8) + \
             ((((uint32_t)(*((p) + 2)))) << 16) +                     \
             ((((uint32_t)(*((p) + 3)))) << 24));                     \
    (p) += 8;                                                         \
    (r) -= 8;                                                         \
} while (0)

/* Copy `len` raw bytes verbatim from the stream into `arr` (consumes `len`). */
#define STREAM_TO_ARRAY(arr, p, len, r, handle)                        \
do {                                                                   \
    if ((r) < (len)) { handle; }                                       \
    unsigned int ijk;                                                  \
    for (ijk = 0; ijk < (len); ijk++) ((uint8_t*)(arr))[ijk] = *(p)++; \
    (r) -= (len);                                                      \
} while (0)

/* Decode a bincode String (u64 length prefix + `length` name bytes, rejected
 * if longer than QUEUE_NAME_SZ), NUL-terminate it, resolve it to a queue id via
 * queuename2id(), and store that in `qid`. Decodes a Rust QItemOperand::MBoxName
 * operand string.
 * NOTE: the macro ends with `return 0;`, so it returns from the *enclosing*
 * function on success. In STREAM_TO_QITEM_HEADER's MBoxName case this means
 * only the first (src) name is ever decoded before control leaves send_qitems. */
#define STREAM_MBOX_NAME_TO_QID(qid, p, r)                           \
do {                                                                 \
    uint32_t length = 0;                                             \
    char name[QUEUE_NAME_SZ + 1] = {0};                              \
                                                                     \
    STREAM_TO_UINT64(length, p, r, return 1);                        \
    if (length > QUEUE_NAME_SZ) { return 1; }                        \
    STREAM_TO_ARRAY(name, p, length, r, return 1);                   \
    name[length] = 0;                                                \
    qid = queuename2id(name); /* TODO: check if qid is invalid */    \
    return 0;                                                        \
} while(0)

/* Decode a Rust `QItemHeader` from the stream into `header`:
 *   u32 QItemOperand tag: 0 = Op       -> u32 op
 *                         1 = MBox     -> u16 src_qid, u16 dst_qid
 *                         2 = MBoxName -> two bincode strings -> src/dst qids
 *   u16 size            (payload byte count that follows the header)
 *   u16 message_group
 * Returns 1 from the enclosing function on a short read or unknown tag. */
#define STREAM_TO_QITEM_HEADER(header, p, r)                 \
do {                                                         \
    uint32_t op_type = 0;                                    \
    STREAM_TO_UINT32(op_type, p, r, return 1);               \
    switch (op_type)                                         \
    {                                                        \
    case 0 /* op */:                                         \
        STREAM_TO_UINT32((header).op, p, r, return 1);       \
        break;                                               \
    case 1 /* mbox */:                                       \
        STREAM_TO_UINT16((header).src_qid, p, r, return 1);  \
        STREAM_TO_UINT16((header).dst_qid, p, r, return 1);  \
        break;                                               \
    case 2 /* mbox name */:                                  \
        STREAM_MBOX_NAME_TO_QID((header).src_qid, p, r);     \
        STREAM_MBOX_NAME_TO_QID((header).dst_qid, p, r);     \
        break;                                               \
    default:                                                 \
        return 1;                                            \
    }                                                        \
    STREAM_TO_UINT16((header).size, p, r, return 1);         \
    STREAM_TO_UINT16((header).msg_group, p, r, return 1);    \
} while (0)

/* Decode a Rust `QItemPayload` (Vec<QItemPDU>) into the `payload` buffer, which
 * is `pl_size` bytes long. Reads a u64 field count, then for each field:
 *   u32 QItemPDU tag:   0 = Array, 1 = IndirU32
 *   u32 QItemField tag: 0 = BytesInput, 1 = GrammarInput  (read but unused at
 *                       run time -- grammar fields are already lowered to bytes)
 *   u64 length
 * Array:    copies `length` bytes inline into the payload at the write cursor,
 *           advancing the cursor by `length`.
 * IndirU32: writes `length` as a u32 into the payload, mallocs a `length`-byte
 *           buffer, copies the bytes into it, then writes the buffer address as
 *           a u32 -- i.e. an out-of-line {u32 len, u32 ptr} pair (8 bytes) that
 *           the modem dereferences later.
 * Rejects length > 0xffff and any write that would exceed `pl_size`. Returns
 * nonzero (codes 1-11) from the enclosing function on error. */
#define STREAM_TO_PAYLOAD(payload, pl_size, p, r)                       \
do {                                                                    \
    uint32_t pl_idx = 0, pdu_type = 0, field_type = 0;                  \
    uint32_t num_fields = 0, length = 0;                                \
    STREAM_TO_UINT64(num_fields, p, r, return 2);                       \
    for (uint32_t i = 0; i < num_fields; ++i) {                         \
        STREAM_TO_UINT32(pdu_type, p, r, return 3);                     \
        switch (pdu_type)                                               \
        {                                                               \
        case 0 /* array */:                                             \
            STREAM_TO_UINT32(field_type, p, r, return 1);               \
            STREAM_TO_UINT64(length, p, r, return 4);                   \
            MODEM_LOG("payload.field[%d].length=%d", i, length);        \
            if (length > 0xffff) { return 5; }                          \
            STREAM_TO_ARRAY(payload + pl_idx, p, length, r, return 6);  \
            pl_idx += (uint32_t)length;                                 \
            break;                                                      \
        case 1 /* indir_u32 */:                                         \
            STREAM_TO_UINT32(field_type, p, r, return 1);               \
            STREAM_TO_UINT64(length, p, r, return 7);                   \
            MODEM_LOG("payload.field::<type=%d>[%d].length=%d", field_type, i, length);  \
            if (length > 0xffff) { return 8; }                          \
            *(uint32_t *)(payload + pl_idx) = (uint32_t)length;         \
            pl_idx += (uint32_t)4;                                      \
            uint8_t *buffer = MALLOC((uint32_t)length);                 \
            STREAM_TO_ARRAY(buffer, p, length, r, return 9);            \
            *(uint32_t *)(payload + pl_idx) = (uint32_t)buffer;         \
            pl_idx += 4;                                                \
            break;                                                      \
        default:                                                        \
            return 10;                                                  \
        }                                                               \
        if (pl_idx > pl_size) { return 11; }                            \
    }                                                                   \
} while (0)

/* In-memory queue-item header the modem expects. Mirrors the decoded Rust
 * QItemHeader: `op` is either a raw 32-bit opcode or a {src_qid, dst_qid}
 * mailbox pair (overlaid via the union), followed by the payload `size` and the
 * `msg_group` selector. */
typedef struct {
    union {
        struct {
            uint16_t src_qid;
            uint16_t dst_qid;
        };
        uint32_t op;
    };
    uint16_t size;
    uint16_t msg_group;
} QItemHeader;

/* A queue item as posted into a task's mailbox: fixed header immediately
 * followed by its `header.size` bytes of decoded payload. */
typedef struct {
    QItemHeader header;
    uint8_t payload[0];
} QItem;

/* One tracked memory variable: `size` bytes (1/2/4) at `addr` holding `value`.
 * PACKED to 12 bytes so the array maps directly onto the wire layout produced
 * by the analyzer/fuzzer (pre-condition and post-memory variable lists). */
typedef struct PACKED {
    uint8_t *addr;
    uint32_t size;
    uint32_t value;
} StateValue;

typedef int error_t;

/* Cached SAEL3 queue id, plus the two variable lists parsed from the fuzzer:
 * pre-condition ("Ensure") vars written before the run. `vars_type` holds the
 * tag of the list most recently parsed by parse_var_list(). */
static uint32_t sael3_qid = 0;
static StateValue *p_pre_cond_vars;
static uint32_t num_pre_cond_vars = 0;
static uint8_t vars_type = 0;

/* Top-level decoder + injector for one serialized VendorInput blob (`buf`,
 * `size` bytes total). Checks the leading u32 length (must equal size - 4),
 * reads the VendorInput tag (only 0 = ShannonInput is accepted) and then the
 * ShannonInput tag:
 *   Sael3Input (0): reads a u64 QItem count, and for each one decodes a header
 *                   + payload into a freshly pal_MemAlloc'd QItem and posts it
 *                   to `dst_qid` via pal_MsgSendTo.
 *   NasotInput (1): reads a u64 SmpfEvent count, and for each one decodes the
 *                   event header (u32 msg_id, u32 obj_id, u8 domain_s, u8
 *                   domain_d, u16 routing, then 6 filler bytes that cover the
 *                   rest of Rust's u32 routing and the payload enum tag) plus a
 *                   u64-prefixed payload, builds an NrmmData MM_RRC_DATA_IND
 *                   message, and drives it through fake_test.
 * Returns 0 on success, or a nonzero error code identifying the failed field. */
error_t send_qitems(uint8_t *buf, uint32_t size, uint32_t dst_qid)
{
    if (size < 4) {
        return __LINE__;
    }

    uint32_t num_bytes = 0, remaining_bytes = 4;
    uart_dump_hex(buf, 4);
    STREAM_TO_UINT32(num_bytes, buf, remaining_bytes, return __LINE__);
    MODEM_LOG("read_messages::num_bytes=0x%x, buf=0x%08x", num_bytes, (uint32_t)buf);
    if (num_bytes + 4 != size) { return __LINE__; }
    remaining_bytes = num_bytes;

    uint32_t vendor_input_type = 0;
    uart_dump_hex(buf, 4);
    STREAM_TO_UINT32(vendor_input_type, buf, remaining_bytes, return __LINE__);
    MODEM_LOG("read_messages::vendor_input_type=0x%x, buf=0x%08x", vendor_input_type, (uint32_t)buf);
    switch (vendor_input_type)
    {
    case 0 /* ShannonInput */: ;
        uint32_t shannon_input_type = 0;
        uart_dump_hex(buf, 4);
        STREAM_TO_UINT32(shannon_input_type, buf, remaining_bytes, return __LINE__);
        MODEM_LOG("read_messages::shannon_input_type=0x%x, buf=0x%08x", shannon_input_type, (uint32_t)buf);
        switch (shannon_input_type)
        {
        case 0 /* Sael3Input */: ;
            uint32_t seq_len = 0;
            uart_dump_hex(buf, 8);
            STREAM_TO_UINT64(seq_len, buf, remaining_bytes, return __LINE__);
            MODEM_LOG("read_messages::seq_len=0x%x, buf=0x%08x", seq_len, (uint32_t)buf);
            for (uint32_t i = 0; i < seq_len; ++i) {
                QItemHeader header;
                STREAM_TO_QITEM_HEADER(header, buf, remaining_bytes);
                if (remaining_bytes < header.size) { return __LINE__; }
                // if (header.msg_group == 0x3c7b) uart_dump_hex(buf, remaining_bytes);
                QItem *item = pal_MemAlloc(4, sizeof(header) + header.size, __FILE__, __LINE__);
                MODEM_LOG("sizeof(header)=0x%x, header.size=0x%x,", sizeof(header), header.size);
                MODEM_LOG("item=0x%08x, item->payload=0x%x,", item, item->payload);
                memcpy(item, (void *)&header, sizeof(header));
                memset(item->payload, 0, header.size);
                STREAM_TO_PAYLOAD(item->payload, (uint32_t)(header.size), buf, remaining_bytes);

                pal_MsgSendTo(dst_qid, item, 2);
            }
            break;

        case 1 /* NasotInput */: ;
            // NOT IMPLEMENTED
            break;

        default:
            return __LINE__;
        }
        break;

    default:
        return __LINE__;
    }

    return 0;
}

/* Deserialize a variable list supplied by the fuzzer (via getPreVariables /
 * getVariables). Layout:
 *   u32 byte count   (must equal the number of bytes remaining after it)
 *   u32 list type    (0 = Observe -> post-memory list, 1 = Ensure -> pre-cond)
 *   u64 variable count
 *   count * StateValue  (12 packed bytes each: u32 addr, u32 size, u32 value)
 * Points the matching global pointer/count at the StateValue array in place
 * (no copy). Returns 0, or a nonzero code on malformed input. */
error_t parse_var_list(uint8_t *p_buf, uint32_t buf_size)
{
    uint32_t num_bytes, remaining_bytes = buf_size;
    STREAM_TO_UINT32(num_bytes, p_buf, remaining_bytes, return __LINE__);
    if (num_bytes != remaining_bytes) { return __LINE__; }
    STREAM_TO_UINT32(vars_type, p_buf, remaining_bytes, return __LINE__);
    switch (vars_type)
    {
    case 0 /* Observe */:
        // NOT IMPLEMENTED
        break;
    case 1 /* Ensure */:
        STREAM_TO_UINT64(num_pre_cond_vars, p_buf, remaining_bytes, return __LINE__);
        if (remaining_bytes != num_pre_cond_vars * sizeof (StateValue)) { return __LINE__; }
        p_pre_cond_vars = (StateValue *)p_buf;
        break;
    default:
        return __LINE__;
    }

    return 0;
}

/* Store `val` into `*addr` as a 1/2/4-byte write selected by `size`. */
void set_single_var(uint8_t *addr, uint32_t val, uint32_t size)
{
    switch (size)
    {
    case 1:
        *addr = (uint8_t)val;
        MODEM_LOG("%p <- 0x%02x", addr, val);
        break;
    case 2:
        *(uint16_t *)addr = (uint16_t)val;
        MODEM_LOG("%p <- 0x%04x", addr, val);
        break;
    case 4:
        *(uint32_t *)addr = val;
        MODEM_LOG("%p <- 0x%08x", addr, val);
        break;
    default:
        MODEM_LOG("WARN: unkonwn size (%d) at %p", size, addr);
    }
}

/* Apply every pre-condition ("Ensure") variable by writing its value into
 * memory, establishing the machine state the analyzer required to reach the
 * target before the fuzzed message is processed. */
void set_pre_state()
{
    uint32_t i = 0;
    StateValue *l = p_pre_cond_vars;
    MODEM_LOG("%s: Observation list(%d):", __func__, num_pre_cond_vars);
    for (i = 0; i < num_pre_cond_vars; ++i) {
        set_single_var(l[i].addr, l[i].value, l[i].size);
    }
    return;
}

/* Read a 1/2/4-byte value at `addr` (selected by `size`) and return it
 * zero-extended to 32 bits. */
uint32_t read_single_var(uint8_t *addr, uint32_t size)
{
    uint32_t val = 0;
    switch (size)
    {
    case 1:
        val = (uint32_t)*addr;
        break;
    case 2:
        val = (uint32_t)*(uint16_t *)addr;
        break;
    case 4:
        val = *(uint32_t *)addr;
        break;
    default:
        MODEM_LOG("WARN: unkonwn size (%d) at %p", size, addr);
    }
    return val;
}

/* Log the current 1/2/4-byte value at `addr` (width chosen by `size`). */
void log_single_var(uint8_t *addr, uint32_t size)
{
    uint32_t val = read_single_var(addr, size);
    switch (size)
    {
    case 1:
        MODEM_LOG("%p = 0x%02x", addr, val);
        break;
    case 2:
        MODEM_LOG("%p = 0x%04x", addr, val);
        break;
    case 4:
        MODEM_LOG("%p = 0x%08x", addr, val);
        break;
    default:
        MODEM_LOG("WARN: unkonwn size (%d) at %p", size, addr);
    }
}

/* Log the current in-memory value of each of the `num_vars` tracked variables. */
void log_vars(StateValue *p_vars, uint32_t num_vars)
{
    uint32_t i = 0;
    MODEM_LOG("%s: Observation list(%d):", __func__, num_vars);
    for (i = 0; i < num_vars; ++i) {
        log_single_var(p_vars[i].addr, p_vars[i].size);
    }
    return;
}

/* Fetch and parse variable lists from the fuzzer: the pre-condition
 * ("Ensure") list, which is immediately applied via set_pre_state() */
error_t var_observer_setup()
{
    uint32_t buf_size;
    uint8_t *p_buf;
    error_t err;

    p_buf = getPreVariables(&buf_size);
    MODEM_LOG("pre-condition variables %d", buf_size);
    uart_dump_hex(p_buf, buf_size > 0x100 ? 0x100 : buf_size);
    err = parse_var_list(p_buf, buf_size);
    if (err != 0) {
        MODEM_LOG("Error deserializing pre-condition variables: %d", err);
        return err;
    }
    set_pre_state();

    return 0;
}

int fuzz_single_setup()
{
    if (sael3_qid == 0)
        sael3_qid = queuename2id("SAEL3");

    return 1;
}

void fuzz_single()
{
    uint32_t input_size;
    error_t err;

    MODEM_LOG("Getting variables");
    err = var_observer_setup();
    if (err != 0) {
        MODEM_LOG("Error getting variables: %d", err);
    }

    MODEM_LOG("Getting work");
    char *buf = getWork(&input_size);
    MODEM_LOG("Received 0x%x bytes (buf=0x%08x): ", input_size, (uint32_t)buf);

    MODEM_LOG("Sending QItems");
    startWork(0, 0xffffffff);
    log_vars(p_pre_cond_vars, num_pre_cond_vars);
    err = send_qitems((uint8_t *)buf, input_size, sael3_qid);
    if (err != 0) {
        MODEM_LOG("Error deserializing qitems: %d", err);
    }
    doneWork(0);
}
