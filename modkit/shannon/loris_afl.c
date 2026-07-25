#include <common.h>
#include <shannon.h>
#include <modkit.h>
#include <afl.h>
#include <task.h>


////////////////////////
// GLOBAL DATA
////////////////////////
#define AFL_SHMEM_FUZZ_HDR_SIZE 4
#define SHMEM_FUZZ_HDR_SIZE 8


static unsigned int bufsz;
char afl_buf[AFL_MAX_INPUT + AFL_SHMEM_FUZZ_HDR_SIZE];
uint8_t p_pre_cond_vars[LORIS_MAX_INPUT + SHMEM_FUZZ_HDR_SIZE];


////////////////////////
// FUNCTION DEFINITIONS
////////////////////////

static inline unsigned int aflCall(unsigned int a0, unsigned int a1, unsigned int a2)
{

    unsigned int ret;
    register long r0 asm ("r0") = a0;
    register long r1 asm ("r1") = a1;
    register long r2 asm ("r2") = a2;

    //asm(".word 0x0f4c4641"
    asm volatile("svc 0x3f" //.byte 0x3f, 0xdf" // 0x0f4c4641"
            : "=r"(r0)
            : "r"(r0), "r"(r1), "r"(r2)
            );
    ret = r0;

    return ret;
}

static void aflInit(void)
{
    static int aflInit = 0;

    if(aflInit)
        return;

    memset(afl_buf, 0x00, sizeof(afl_buf)); // touch all the bits!
    bufsz = sizeof(afl_buf) - AFL_SHMEM_FUZZ_HDR_SIZE;
    aflInit = 1;
}

int lorisInit(void)
{
    uint32_t max_size;
    max_size = sizeof (p_pre_cond_vars) - SHMEM_FUZZ_HDR_SIZE;
    *(uint32_t *)p_pre_cond_vars = max_size;

    // a0 and a1 are ignored
    return aflCall(0xd0, 0, 0);
}

int startForkserver(int ticks)
{
    aflInit();
    // last arg ignored
    return aflCall(1, ticks, 0);
}

char * getWork(unsigned int *sizep)
{
    *sizep = aflCall(2, (unsigned int)afl_buf, bufsz);
    return afl_buf;
}

uint8_t *getPreVariables(uint32_t *p_size)
{
    uint32_t max_size = *(uint32_t *)p_pre_cond_vars;
    *p_size = aflCall(0xd3, (uint32_t)p_pre_cond_vars, max_size);
    return p_pre_cond_vars + sizeof (uint32_t);
}

int startWork(unsigned int start, unsigned int end)
{
    aflInit();
    return aflCall(3, start, end);
}

int doneWork(int val)
{
    aflInit();
    return aflCall(4, (unsigned int)val, 0);
}

void task_main() {
    MODEM_LOG("[+] AFL task starting\n");

    // we're essentially acting like a kernel
    zero_bss();

    // this settles the baseband tasks
    MODEM_LOG("[+] Init sleep\n");
    pal_Sleep(200);

    lorisInit();

    if (!fuzz_single_setup()) {
      MODEM_LOG("[!] Fuzzer init error\n");
      for (;;) ;
    }
    MODEM_LOG("[+] Fuzzer init complete\n");

    MODEM_LOG("[+] Starting fork server\n");
    startForkserver(1);

    while (1) {
      fuzz_single();
    }

    // tasks can NEVER return from main
}
