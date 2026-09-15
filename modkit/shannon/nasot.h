#ifndef _NASOT_H
#define _NASOT_H

#include <smpf.h>

MODKIT_FUNCTION_SYMBOL(void, SetMmState, uint32_t, uint32_t, uint32_t, uint32_t)
MODKIT_FUNCTION_SYMBOL(uint8_t *, fake_test_harness, void)
MODKIT_FUNCTION_SYMBOL(void, NrmmStartProcedure_Wrapper, uint32_t, uint32_t)
MODKIT_DATA_SYMBOL(uint32_t, MmGeneralContext)
MODKIT_DATA_SYMBOL(uint32_t, MM_MSG_CLASS)
MODKIT_DATA_SYMBOL(uint32_t, MM_MSG_DOMAIN)
MODKIT_DATA_SYMBOL(uint32_t, NrmmFacade)

#endif