#ifndef _SMPF_H
#define _SMPF_H

#include <common.h>
#include <modkit.h>

typedef enum PACKED {
  SMPF_URGENT_MSG_Q = 0,
  SMPF_HIGH_MSG_Q,
  SMPF_SELF_MSG_Q,
  SMPF_INTERNAL_MSG_Q,
  SMPF_EXTERNAL_MSG_Q,
  SMPF_TIMER_MSG_Q,
  SMPF_BYPASS_MSG_Q,
  SMPF_BYPASS_URG_MSG_Q,
  SMPF_USER_CB_MSG_Q,
} SmpfMsgType;

typedef struct PACKED {
  uint32_t msg_id;
  uint32_t field_0x4;
  uint32_t target_obj_id;
  uint8_t domain_s;
  uint8_t domain_d;
  uint8_t field_0xe[2];
  uint32_t routing;
  uint8_t field_0x14[0xc];
  SmpfMsgType msg_type;
  uint16_t field_0x21;
  uint8_t field_0x23;
  uint32_t size;
  char * msg_name;
} astruct_28;

typedef struct PACKED {
  uint8_t *pData;
  uint16_t dataLength;
} SItemPayload;

typedef struct PACKED {
  astruct_28 field_0x0;
  SItemPayload pl;
} SItem;

MODKIT_DATA_SYMBOL(uint8_t *, SMPF_TASK_CREATED)
MODKIT_FUNCTION_SYMBOL(void, fake_test, SItem *)

#endif // _SMPF_H