#include <afl.h>
#include <shannon.h>
#include <nasot.h>

const char TASK_NAME[] = "AFL_NASOT\0";

typedef struct PACKED {
  uint8_t payload[10];
} Payload_MMC_NRMM_INIT_REQ;

typedef struct PACKED {
  struct qitem_header header;
  Payload_MMC_NRMM_INIT_REQ pl;  
} QItem_MMC_NRMM_INIT_REQ;

//oriole-ap2a.240905.003.f1 qitem analyis

//op1 = qid:
        //                      MmcMsgDescStruct_4014be34                       XREF[1]:     4014cf24(*)  
        // 4014be34 00 20 0a        MmcMsgDe
        //          00 32 01 
        //          00 00 00 
        //    4014be34 00 20           ushort    2000h                   msg_id                            XREF[1]:     4014cf24(*)  
        //    4014be36 0a 00           ushort    Ah                      size
        //    4014be38 32 01 00 00     uint      132h                    qid
        //    4014be3c 00              ??        00h                     field3_0x8
        //    4014be3d 00              ??        00h                     field4_0x9
        //    4014be3e 00              ??        00h                     field5_0xa
        //    4014be3f 00              ??        00h                     field6_0xb
        //    4014be40 36 6a 70 41     char *    s_GMC_==>_NRMM__[INIT_  log_msg       = "GMC ==> NRMM_ [
        //    4014be44 d5 73 47 45     char *    s_MMC_NRMM_INIT_REQ_45  msg_name      = "MMC_NRMM_INIT_R
        //    4014be48 e7 73 47 45     char *    s_Mmc_NrInitReq_t_4547  func_name     = "Mmc_NrInitReq_t"

//Descriptor struct stored in
        //                      MmcMsgDesc_ARRAY_4014cf20                       XREF[1]:     Mmc_InitNrMsgDesc:425bdb74(R)  
        // 4014cf20 01 90 00        MmcMsgDe
        //          00 34 be 
        //          14 40 02 
        //    4014cf20 01 90 00 00 34  MmcMsgDesc                        [0]                               XREF[1]:     Mmc_InitNrMsgDesc:425bdb74(R)  
        //             be 14 40
        //       4014cf20 01 90 00 00     uint      9001h                   field0_0x0                        XREF[1]:     Mmc_InitNrMsgDesc:425bdb74(R)  
        //       4014cf24 34 be 14 40     MmcMsgDe  MmcMsgDescStruct_4014b  field1_0x4

// Descriptor address calulated from

    // if (param_1 < 0x900f) {
    //   pMVar1 = (MmcMsgDescStruct *)0x0;
    //   if ((*(MmcMsgDescStruct **)(&DAT_40104f1c + param_1 * 8))->qid != 0) {
    //     pMVar1 = *(MmcMsgDescStruct **)(&DAT_40104f1c + param_1 * 8);
    //   }
    //   return pMVar1;
    // }

// in func: Mmc_GetNrTxMsgDesc


//op2 in gmc_CreateMsg:

    // if ((local_14 != (MmcMsg_NrInitReq *)0x0) && (uVar1 != 0xfff8)) {
    //   (local_14->header).src_qid = 0xbb;
    //   (local_14->header).dst_qid = (ushort)param_1->qid;
    //   (local_14->header).msg_id = param_1->msg_id;
    //   (local_14->header).pl_size = param_1->size;
    //   return local_14;
    // }

void send_MMC_NRMM_INIT_REQ() // Implementing func: gmc_CreateMsg & Mmc_SendNrInitReq
{
  QItem_MMC_NRMM_INIT_REQ *item = (QItem_MMC_NRMM_INIT_REQ*) pal_MemAlloc(4, sizeof(QItem_MMC_NRMM_INIT_REQ), __FILE__, __LINE__);
  if (!item) {
    MODEM_LOG("ALLOC FAILED");
    return;
  }
  item->header.op1 = 0xbb;
  item->header.op2 = 0x132;
  item->header.size = sizeof(QItem_MMC_NRMM_INIT_REQ) - sizeof(struct qitem_header);
  item->header.msgGroup = 0x2000;
  memset(&item->pl, 0, sizeof(item->pl));
  item->pl.payload[0] = 0;

  pal_MsgSendTo(0x132, item, 2);
}

int fuzz_single_setup()
{
  do {
    pal_Sleep(2);
  } while (*SMPF_TASK_CREATED == 0);
  
  send_MMC_NRMM_INIT_REQ();
  
  return 1;
}

void send_MM_RRC_DATA_IND(uint8_t *buf, uint32_t input_size) {
  uint8_t *pData = (uint8_t *)pal_MemAlloc(4, input_size + 8, __FILE__, __LINE__);
  if (!pData) {
    MODEM_LOG("ALLOC FAILED");
    return;
  }
  memcpy(pData + 8, buf, input_size);

  SItem *msg = (SItem *)pal_MemAlloc(4, sizeof(SItem), __FILE__, __LINE__);
  if (!msg) {
    MODEM_LOG("ALLOC FAILED");
    return;
  }
  msg->field_0x0.msg_id = MM_MSG_CLASS;
  msg->field_0x0.field_0x4 = (MM_MSG_CLASS >> 0xc) | MM_MSG_DOMAIN;
  msg->field_0x0.target_obj_id = (MM_MSG_CLASS >> 0x16) | MM_MSG_DOMAIN;
  msg->field_0x0.domain_s = 0x40;
  msg->field_0x0.domain_d = 0;
  msg->field_0x0.routing = 0x80;
  memset(msg->field_0x0.field_0x14, 0, 0xc);
  msg->field_0x0.msg_type = 4;
  msg->field_0x0.size = 0x48;
  msg->field_0x0.msg_name = "MM_RRC_DATA_IND";
  msg->pl.pData = pData + 8;
  msg->pl.dataLength = input_size;

  (*fake_test)(msg);
}

void fuzz_single()
{
  uint32_t input_size;
  uint16_t size;
  
  MODEM_LOG("Getting Work");
  uint8_t *buf = (uint8_t *)getWork(&input_size);
  size = (uint16_t) input_size;

  MODEM_LOG("[+] Received 0x%x bytes (buf=0x%08x): ", input_size, (uint32_t)buf);
  uart_dump_hex((uint8_t *)buf, size); // Print some for testing

  MODEM_LOG("FIRE");
  startWork(0, 0xffffffff); // memory range to collect coverage

  uint8_t *harness = fake_test_harness();
  *harness = 1;

  NrmmStartProcedure_Wrapper(NrmmFacade, 1);
  SetMmState(MmGeneralContext, 0, 0x4035634, 0);
  MODEM_LOG("Sending MM_RRC_DATA_IND...");
  send_MM_RRC_DATA_IND(buf + 8, input_size - 8);

  doneWork(0);
  MODEM_LOG("WorkDone");
}
