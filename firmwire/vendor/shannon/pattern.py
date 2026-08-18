## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
import logging
import time

import firmwire.vendor.shannon.pattern_handlers as handlers

log = logging.getLogger(__name__)

PATTERNS_COMMON = {
    "BXLR": {
        "pattern": "70 47",
        "required": True,
        "align": 2
    },
    "SYM_MEMORY_DUMP_ENABLED" : {
        "lookup": lambda data, offset: 0x0,
    },
    "SYM_MEMORY_TRACING_ENABLED" : {
        "lookup": lambda data, offset: 0x0,
    },
}

PATTERNS_CORTEX_R = {
    "boot_mpu_table": {
        "pattern": "00000000 00000000 1c000000"
        + "????????" * 6
        + "01000000 01000000 00000004 20",
        "required": True,
    },
    "boot_setup_memory": {
        "pattern": [
            "00008004 200c0000",
            "00000004 ????0100",  # S335
        ],
        "offset": -0x14,
        "align": 4,
        "post_lookup": handlers.parse_memory_table,
        "required": True,
    },
    "boot_key_check": {
        "pattern": [
            "?? 49 00 22 ?? 48 ?? a3 ?? ?? ?? ?? 80 21 68 46 ?? ?? ?? ?? 10 22 20 a9 68 46 ?? ?? ?? ??"
        ],
        "offset_end": 0x0,
        "soc_match": ["S5000AP"],
        "required": True,
    },
    "OS_fatal_error": {
        "pattern": "70 b5 05 46 ???????? ?? 48 ?? 24",
    },
    "pal_MemAlloc": {
        "pattern" : [
            "2d e9 f0 4f  0d 00  83 b0  99 46  92 46  80 46",
            "2d e9 ff 4f  4f f0  00 05  0e 00  83 b0  9a 46"
            ],
        "post_lookup": handlers.fixup_bios_symbol,
    },
    "pal_MemFree": {
        "pattern": "?? 4b 10 b5 9b 68 13 b1 bd e8 10 40 18 47",
    },
    "pal_MsgSendTo": {
        "pattern": [
            "70 b5 ?+ 04 46 15 46 0e 46 ?? ?? 01 df ?* 88 60 08 46 ?+ ?? 48 ???? ???? 20 46 98 47",  # G973F
            "???????? b0f5fa7f 0446 ??46",  # S337AP
        ]
    },
    "pal_Sleep": {
        "pattern": "30 b5 ?+ 98 ?+  ??98 ??22 ??23 11 46 ?? 94",
        # 30 b5 00 25 83 b0 04 46 2a 46 29 46 01 a8 d9 f6 2a e9 01 98 78 b1 29 46 d9 f6 90 e8 01 98 01 22 00 23 11 46 00 94 d9 f6 36 e9 01 98 d8 f6 5e ee 01 98 d9 f6 28 e9 5c f7 09 d8 00 28 02 d0 02 a8 ff f7 42 fe 03 b0 30 bd
        # 30 b5 04 46 85 b0 df 4b 40 f2 02 30 00 22 00 90 11 46 01 a8 0e f1 54 ee dd f8 04 c0 bc f1 00 0f 1c d0 00 25 01 21 03 ab 2a 46 0c f1 38 00 00 95 65 f4 1a f1 01 98 29 46 8b f1 a8 ed 01 98 01 22 00 23 11 46 00 94 5b f1 58 ed 01 98 8b f1 2e ec cd 49 40 f2 13 32 01 98 8b f1 a0 ed f0 f4 a1 f0 00 28 02 d0 02 a8 ff f7 1a fe 05 b0 30 bd
    },
    "log_printf": {
        "pattern": [
            "0fb4 2de9f047 ???? ??98 d0e90060 c0f34815",
            "0fb4 2de9f0?? ???? ??98 d0e900?? ??f3????",
            "0f b4 10 b5 03 a9 02 98 ff f7 9a ff 10 bc 5d f8 14 fb",
        ],
        "required": True,
    },
    # log_printf_debug
    "log_printf2": {
        "pattern": "0fb4 2de9f04f ???? ??0a 8fb01898 4068",
    },
    "pal_SmSetEvent": {
        "pattern": [
            "10b5 ???? ???????? 04 b2",  # thumb G973F, no NULL check
            "10b5 0068 0028 ???? ???????? 04 b2",  # thumb S337AP, NULL check
        ],
    },
    # OS_Delete_Event_Group is the function (based off string name). It is in the baseband (2017+) otherwise search for string
    # "LTE_RRC_EVENT_GRP_NAME" to find the creation function and explore from there.
    "SYM_EVENT_GROUP_LIST": {
        "pattern": [
            "70 40 2d e9 00 40 a0 e1 ?? ?? 00 eb 00 50 a0 e1 20 00 9f e5 04 10 a0 e1 ?? ?? 00 eb ?? 00 94 e5 00 00 50 e3 30 ff 2f 11 05 00 a0 e1 ?? ?? 00 eb 00 00 a0 e3 70 80 bd e8"
        ],
        "offset_end": 0x0,
        "post_lookup": handlers.dereference,
    },
    "SYM_TASK_LIST": {
        "lookup": handlers.find_task_table,
        "post_lookup": handlers.fixup_set_task_layout,
    },
    "SYM_SCHEDULABLE_TASK_LIST": {"lookup": handlers.find_schedulable_task_table},
    "SYM_CUR_TASK_ID": {"lookup": handlers.find_current_task_ptr},
    "SYM_FN_EXCEPTION_SWITCH": {"lookup": handlers.find_exception_switch},
    "SYM_QUEUE_LIST": {"lookup": handlers.find_queue_table},
    "QUIRK_SXXXAP_DVFS_HACK": {
        "pattern": [
            "??f8???? 00f01f01 ??48 d0 f8 ????  c0 f3 ????  ????????  ????  00 ?? ?* ??f1???? ??82 ??eb??11 0988",
            "????  00 ?? ?* ??f1???? ??82 ??eb??11 0988",  # S335AP alternate
        ],
        "offset_end": 0x0,
        "soc_match": ["S335AP", "S355AP", "S360AP"],
        # Thumb alignment
        "align": 2,
        "required": True,
    },
    # S337AP for Moto One does a memclr of the SHM area on boot.
    # As SHM is implemented via remote memory, this is slow - this quirck is a workaround
    "QUIRK_S337AP_SHM_HACK": {
        "pattern": [
            "4ff09041 095889b1 6c4900f1 90424ff4 800306 a80097cd e906164f f09041?? ??????67 496748?? ??????03 e0"
        ],
        "offset_end": -6,
        "soc_match": ["S337AP"],
        # Thumb alignment
        "align": 2,
        "required": False,
    },
    # S337AP for A51 has a boot key, but S337AP for Moto does not, thus this workaround
    # The better solution would probably to split this into two socs and handle the difference in the loader
    "quirk_boot_key_check_a51": {
        "pattern": [
            "?? 49 00 22 ?? 48 ?? a3 ?? ?? ?? ?? 80 21 68 46 ?? ?? ?? ?? 10 22 20 a9 68 46 ?? ?? ?? ??"
        ],
        "offset_end": 0x0,
        "soc_match": ["S337AP"],
        "required": False,
    },
    "SYM_LTERRC_INT_MOB_CMD_HO_FROM_IRAT_MSG_ID": {
        "lookup": handlers.find_lterrc_int_mob_cmd_ho_from_irat_msgid
    },
    "DSP_SYNC_WORD_0": {
        "pattern": [
            "??21??68 4ff4??72 884202d1 ??689042 07d0 ??23??a0 cde90003 ??????a0 ?* ??b0bde8 f0 ??",
            "??21??68 ??22     884202d1 ??689042 07d0 ??23??a0 cde90003 ??????a0 ?* ??b0bde8 f0 ??", # G930F

        ],
        "post_lookup": handlers.get_dsp_sync0,
        "required": False,
    },
    "DSP_SYNC_WORD_1": {
        "pattern": [
            "4ff4??72 884202d1 ??689042 07d0 ??23??a0 cde90003 ??????a0 ?* ??b0bde8 f0 ??",
            "??????22 884202d1 ??689042 07d0 ??23??a0 cde90003 ??????a0 ?* ??b0bde8 f0 ??", # G930F
        ],
        "offset": 2,
        "offset_end": 3,
        "post_lookup": handlers.get_dsp_sync1,
        "required": False,
    },
    # Look for "LTE_PDCP_DATA_IND malloc fail"
    "MSG_ID_LTE_PDCP_DATA_IND" : {
        "pattern": [
            "0420 ???????? ???? ???????? 0cf0???? ??90 ???? ??21 0160",
            "???????? 0420 ???????? 0cf0???? ??90 0028 ???? ??21 0160"
        ],
        "offset": 20,
        "post_lookup": handlers.find_msg_id_lte_pdcp_data_ind,
        "required": False
    },
    "MSG_ID_LTE_PDCP_DATA_REQ" : {
        "lookup": handlers.find_msg_id_lte_pdcp_data_req,
        "required": False
    },
    "SYM_POST_INIT_MEMORY":
    {
        "pattern": [
            "f0 b5 03 20 85 b0 8d f8 00 00"
        ]

    },

    "SYM_HEAP_PARTITIONS_INIT": {
        "pattern": [
            "70 b5 04 46 ???? 29 62 a8 60 ???? ???? 01 60 ???? 41 60 ???? 81 60 ???? c1 60 ???? 01 61 ???? 41 61 ???? 81 61 1c 30 ???? 01 60 ???? 41 60"
        ],
        "post_lookup": handlers.find_heap_metadata,
    },

    "LteRrcBoolPrintLog" : {
        "pattern": [
            "4cf25434 01f10806 2027 00f10805 ??4a 0120 1070"
        ],
        "offset": 14,
        "post_lookup" : handlers.find_LteRrcBoolPrintLog,
    },
    "pal_BusyWait1": {
        "pattern": [
            "2de9f041 0446 ???????? 0746 1348 80?? 00fb04f6"
        ]
    },
    "pal_BusyWait2": {
        "pattern": [
            "0949 70b5 89?? 01fb00f6 ??f7???? 0446 e543"
        ]
    },
    "Nas_MacCheck":
    {
        "pattern": [
            "04 22 59 46 04 a8 ???????? 01 28 06 46 40 f2 e3 15 ?? d0 ?? 48 02 90 20 68 ???????? 00 28 ?? db 20 68 ???????? 02 28 ?? da 20 68",
            "04 22 59 46 04 a8 ???????? ?? 25 01 28 06 46 ?? d0 ?? 48 54 30 02 90 20 68 ???????? 00 28 ?? db 20 68 ???????? 02 28 ?? da 20 68",
            "04 22 59 46 04 a8 ???????? ?? 25 01 28 06 46 ?? d0 ?? 48 02 90 20 68 ???????? 00 28 ?? db 20 68 ???????? 02 28 ?? da 20 68"

        ],
        "offset": 6,
    },
    "LteRrc_Timer_GUARD" : {
        "pattern": [
            "25 6a 01 26 00 2d ?? d0 ?? 46 ???????? 94 f8 2d 10 ?? 4b 61 b1 01 29 01 d0 1d 46 1c e0"
        ],
    },
}

PATTERNS_CORTEX_A = {
    "main_mmu_table": {
        "pattern": [
            "01000000 00000000 00000000 0c940100 01000000 00001000", # S5123
            "00000000 00000000 00001000 0c940100 00000040 00000040", # S5123AP
        ],
        "required": True,
    },
    "boot_key_check": {
        "pattern": [
            "0880 ???????? e2a0 ???????? 06f0???? 05f0???? 3aac 8021 2046 ???????? 1aa9 2046 1022", # S5123AP
        ],
        "offset_end": 0x0,
        "soc_match": ["S5123AP"],
        "required": True,
    },
    "set_task_affinity": {
        # Search for == Task(%d) ==
        "pattern": [
            "2de9f047 86b0 ???????? 0446 9846 9146 0e46 0021 0122 0827 c4f2???? 04f10803 2546 daf80000 0590 3c20 07c3 c4e90517 e161 ???????? 2820 3c22 c4f2???? 0023 45f8041f", # S5123AP
            "2de9f043 85b0 0546 9846 9146 0e46 3c20 0021 0122 0827 05f10803 2c46 07c3 c5e90517 e961 ???????? 2820 3c22 c4f2???? 0023 44f8041f",  # oriole
        ],
        "required": True,
    },
    "log_printf": {
        "pattern": [
            "83b0 2de9f0?? ??b0 0df14c0c 0024",  # oriole-sq3a.220705.004
            "83b0 2de9f0?? ??b0 4af29018 0df14c0c 0024",  # G981BXXSKHXEA
            "83b0 2de9f04f ??b0 ???????? 0df14c0c 0024", # S5123AP
        ],
        "required": True,
    },
    "OS_fatal_error": {
        "pattern": [
            "f0b5 81b0 0446 fff7ecea 0546 fff7eaea 49f28036 c4f23046 7179 8842",  # G981BXXSKHXEA
            "f0b5 81b0 0446 00f0???? 0546 00f0???? ???????? c4f2???? 7179 8842", # S5123AP
            "f0b5 81b0 0446 fff7???? 0546 fff7???? ???????? c4f6???? 7179 8842",  # oriole
        ],
    },
    "disableIRQinterrupts": {
        "pattern": "00 00 0f e1 80 00 00 e2 80 00 0c f1 1e ff 2f e1",
        "align": 4,
    },
    "enableIRQinterrupts": {
        "pattern": "80 00 10 e3 ?? 00 00 1a 80 00 08 f1 1e ff 2f e1",
        "align": 4,
    },
    "disableIRQinterrupts_trap": {
        "pattern": "00 00 0f e1 80 00 10 e2 ?+ 80 00 0c f1",
        "align": 4,
    },
    "enableIRQinterrupts_trap": {
        "pattern": "80 00 10 e3 ?? 00 00 1a ?+ 80 00 08 f1 1e ff 2f e1",
        "align": 4,
    },
    "pal_MemAlloc": {
        "pattern": [
            "2de9f04f 85b0 9a46 9146 0c46 8046 29b1 14f00305 18bf c5f10405 11e0",  # oriole-sq3a.220705.004, oriole-ap2a.240905.003.f1
            "2de9f04f 85b0 0c46 9a46 9146 8046 2cb1 14f00305 18bf c5f10405 11e0",  # G981BXXSKHXEA
            "2de9f04f 85b0 ???????? 8046 0c46 9a46 9146 c4f2???? 002c 2868 0490 05d0 14f00307 18bf c7f10407 11e0", # S5123AP
        ],
    },
    "pal_MemFree": {
        "pattern": [
            "2de9f04f 87b0 1546 0491 0646 43f2d6c7 8346 3df246c6 43f2c059 c4f20d59 99f80510 8842",  # G981BXXSKHXEA
            "2de9f04f 89b0 ???????? cde90421 0746 c4f2???? daf80000 0890 ???????? 0646 ???????? ???????? c4f2???? 9bf80510 8842", # S5123AP
            "2de9f04f 87b0 cde90312 8146 ???????? 8246 ???????? ???????? c4f6???? 6979 8842",  # oriole
        ],
    },
    "pal_Sleep": {
        "lookup": handlers.find_pal_sleep,
    },
    "pal_MsgReceiveMbx": {
        "pattern": [
            "10b5 82b0 8c46 0021 1446 002a ccf80010 00d0 2170",  # oriole-sq3a.220705.004, oriole-ap2a.240905.003.f1
            "10b5 82b0 8c46 0021 1446 002c ccf80010 00d0 2170",  # G981BXXSKHXEA
            "70b5 82b0 ???????? 1446 0a46 c4f2???? 3168 0191 0021 002c 1160 00d0 2170",  # S5123AP
            "f0b5 81b0 0e46 0021 1d46 1446 002a 3160 00d0 2170",  # oriole-bp2a.250605.031.a5
        ],
        "soc_match": ["S5123", "S5123AP"],
        "required": True,
    },
    "pal_MsgSendTo": {
        "pattern": [
            "2de9f041 1546 0c46 0646 b0f57a7f ?+ 2de90f00 bff35f8f 01df bff35f8f bde80f00",  # oriole-sq3a.220705.004, oriole-ap2a.240905.003.f1
            "f0b5 81b0 0646 1546 0c46 b6f57a7f ?+ 2de90f00 bff35f8f 01df bff35f8f bde80f00",  # G981BXXSKHXEA
            "2de9???? ??b0 0646 ??46 ??46 b6f57a7f ??db ?+ 2de90f00 bff35f8f 01df bff35f8f bde80f00",  # S5123AP
        ]
    },
    "pal_SmSetEvent": {
        "pattern": [
            "10b5 0068 80b1 57f6c6d1 0446 4ff6ff70 0442 0ad0 45f6b801 20b2",  # G981BXXSKHXEA
            "10b5 0068 80b1 ???????? 0446 4ff6ff70 0442 0ad0 ???????? 20b2",  # S5123AP
            "10b5 0068 80b1 ???????? 0446 4ff6ff70 0442 0ad0 ???????? 20b2",  # oriole
        ],
    },
    "SYM_LTERRC_INT_MOB_CMD_HO_FROM_IRAT_MSG_ID": {
        "lookup": lambda data, offset: 0xc3a5,
    },
    "SYM_QUEUE_LIST": {"lookup": handlers.find_queue_table},             # G991B, oriole
    "SYM_CUR_TASK_PTR": {"lookup": handlers.find_current_task_ptr_a},    # G991B, oriole
    # Find function OS_Create_Event_Group which calls a function to inject the pointer of pal_event_group into a fixed pointer
    "SYM_EVENT_GROUP_LIST": {
        "lookup": handlers.find_sym_event_group_list,
        "soc_match": ["S5123", "S5123AP"],
    },
    "SYM_TASK_LIST": {                                                   # G991B, oriole
        "lookup": handlers.find_task_table,
        "post_lookup": handlers.fixup_set_task_layout,
    },
    "DSP_SYNC_WORD_0": {
        "pattern": [
            "80b5 82b0 0368 ???????? 4ff48f70 ???????? ???????? cde90010 ??a0 c121 ???????? 02b0 80bd",
            "80b5 82b0 0368 ???????? 4ff49570 4ff4de72 c4f28801 cde90010 03a0 c121 ???????? 02b0 80bd", # S5123AP
        ],
        "offset": 28,
        "post_lookup": handlers.s5123_get_dsp_sync0,
        "required": False,
        "soc_match": ["S5123", "S5123AP"],
    },
    "DSP_SYNC_WORD_1": {
        "pattern": [
            "80b5 82b0 0368 ???????? 4ff48f70 ???????? ???????? cde90010 ??a0 c121 ???????? 02b0 80bd",
            "80b5 82b0 0368 ???????? 4ff49570 4ff4de72 c4f28801 cde90010 03a0 c121 ???????? 02b0 80bd", # S5123AP
        ],
        "offset": 14,
        "post_lookup": handlers.s5123_get_dsp_sync1,
        "required": False,
        "soc_match": ["S5123", "S5123AP"],
    },
    "rf_hwid": {
        "lookup": handlers.find_rf_hwid,
        "soc_match": ["S5123"],
    },
    "board_rf_config": {
        "lookup": handlers.find_board_rf_config,
        "soc_match": ["S5123"],
    },
    "trng_init": {
        "lookup": handlers.find_trng_init,
        "soc_match": ["S5123"],
    },
    "main_task_counter": {
        "lookup": handlers.find_counter,
        "soc_match": ["S5123", "S5123AP"],
    },
    # PHY_IPC_C2P_Sender: recover the CP->PHY ring base, published as
    # SYM_PHY_IPC_C2P_RING_BASE and consumed by the PhyIpc peripheral to drain
    # the ring (see PhyIpcPeripheral.py). The two Cortex-A NR variants differ in
    # how the sender loads the base, so each SoC family gets its own entry:
    #
    #  - S5123AP (e.g. G991B): base via a `bl` to a thunk. Pattern anchors on the
    #    prologue + `add.w r5, r0, r4, lsl #8` bracketing that first bl; the
    #    handler decodes bl -> thunk -> movw/movt.
    #  - S5123 (e.g. oriole): base built inline as `movw rD / movt rD` in the
    #    prologue (no call). Pattern wildcards the two immediate-bearing
    #    instructions; the handler decodes them in place.
    "PHY_IPC_C2P_Sender_thunked": {
        "pattern": "2de9f04f 83b0 0e46 0446 ???????? 00eb0425",
        "post_lookup": handlers.get_phy_ipc_c2p_ring_base_thunked,
        "required": False,
        "soc_match": ["S5123AP"],
    },
    "PHY_IPC_C2P_Sender_inline": {
        "pattern": "2de9f04f 83b0 ???????? 0546 8846 ????????",
        "post_lookup": handlers.get_phy_ipc_c2p_ring_base_inline,
        "required": False,
        "soc_match": ["S5123"],
    },
    # "SMPF task is not created yet. Message(%s) is inserted to pending array"
    "fake_test": {
        "pattern": [
            "2de9f043 83b0 0446 a068 10f4007f 43d1 4cf21401 c4f28171 0978 0029 40d0 617b 4029 01d3 0021 6173", # oriole-ap2a.240905.003.f1
            "2de9f043 83b0 0446 a068 10f4007f 43d1 42f21451 c4f28271 0978 0029 40d0 617b 4029 01d3 0021 6173", # oriole-bp2a.250605.031.a5
            "2de9f043 83b0 0446 a068 10f4007f 43d1 4cf21401 c4f28171 0978 0029 40d0 617b 4029 01d3 0021 6173", # oriole-ap2a.240805.005.f1
            "2de9f043 83b0 0446 a068 10f4007f 43d1 47f29401 c4f28171 0978 0029 40d0 617b 4029 01d3 0021 6173", # oriole-uq1a.240205.002
            "2de9f043 83b0 0446 a068 10f4007f 43d1 41f6d411 c4f28271 0978 0029 40d0 617b 4029 01d3 0021 6173", # oriole-bp1a.250505.005

            "2de9f047 84b0 4bf68827 0446 c4f2b627 3868 0390 a068 10f4007f 43d1 4df64071 c4f2cc41 0978 0029 40d0 617b 4029 01d3 0021 6173", # G991BXXSCGXF5
            "2de9f047 84b0 4df6c057 0446 c4f2b727 3868 0390 a068 10f4007f 43d1 40f22031 c4f2ce41 0978 0029 40d0 617b 4029 01d3 0021 6173", # G991BXXSIHYK1
            "2de9f047 84b0 4df2f057 0446 c4f2b727 3868 0390 a068 10f4007f 43d1 4ff62031 c4f2cd41 0978 0029 40d0 617b 4029 01d3 0021 6173", # G991BXXUEHYD5
            "2de9f047 84b0 4ef2d837 0446 c4f2b627 3868 0390 a068 10f4007f 43d1 40f6c001 c4f2cd41 0978 0029 40d0 617b 4029 01d3 0021 6173", # G991BXXUEGXJE
            "2de9f047 84b0 4ff29847 0446 c4f2b627 3868 0390 a068 10f4007f 43d1 41f68011 c4f2cd41 0978 0029 40d0 617b 4029 01d3 0021 6173", # G991BXXUCGXGC
            "2de9f047 84b0 4df6a057 0446 c4f2b727 3868 0390 a068 10f4007f 43d1 40f2e021 c4f2ce41 0978 0029 40d0 617b 4029 01d3 0021 6173", # G991BXXSHHYJ1
            "2de9f047 84b0 4df2f057 0446 c4f2b727 3868 0390 a068 10f4007f 43d1 4ff62031 c4f2cd41 0978 0029 40d0 617b 4029 01d3 0021 6173", # G991BXXSGHYH1
            "2de9f047 84b0 4df2f057 0446 c4f2b727 3868 0390 a068 10f4007f 43d1 4ff62031 c4f2cd41 0978 0029 40d0 617b 4029 01d3 0021 6173", # G991BXXSFHYE1
            "2de9f047 84b0 4ff25807 0446 c4f2b627 3868 0390 a068 10f4007f 43d1 41f26051 c4f2cd41 0978 0029 40d0 617b 4029 01d3 0021 6173", # G991BXXSEGXL2
            "2de9f047 84b0 4ff2d857 0446 c4f2b627 3868 0390 a068 10f4007f 43d1 41f6c021 c4f2cd41 0978 0029 40d0 617b 4029 01d3 0021 6173", # G991BXXSDGXI5

            "2de9???? ??b0 ?* 0446 ?* 10f4007f 43d1 ???????? c4f2???? 0978 0029 40d0 617b 4029 01d3 0021 6173"
        ],
        "soc_match": ["S5123","S5123AP"],
    },
    # lookup handler creation
    # 44ccdf40 - G991BXXSCGXF5
    # 478219d4 - oriole-bp1a.250505.005
    # decode the movw and movt:
    #   420d5240 41 f6 d4 11     movw       r1,#0x19d4
    #   420d5244 c4 f2 82 71     movt       r1,#0x4782
    "SMPF_TASK_CREATED": {
        "lookup": handlers.find_smpf_task_created,
        "soc_match": ["S5123","S5123AP"],
    },
    # G991B: Security Header Check: "[N :MM,%d]  Allowed Plain Nas message rcvd" if fake_test_harness() != 0
    # => Could result in OS Fatal Error Call?
    "fake_test_harness": {
        "pattern": [
            "10b5 4ff23c04 c4f26774 2068 00b1 10bd 4ff6fb71 0c20 8722 0023 c4f21a11 fcf722f8 edf4f3f0 2060 10bd", # oriole-ap2a.240905.003.f1
            "10b5 45f23c44 c4f26874 2068 00b1 10bd 40f2ff51 0c20 8722 0023 c4f21b11 fbf76ffc ebf484f3 2060 10bd", # oriole-bp2a.250605.031.a5
            "10b5 4ff23c04 c4f26774 2068 00b1 10bd 4ff6fb71 0c20 8722 0023 c4f21a11 fcf722f8 edf4f3f0 2060 10bd", # oriole-ap2a.240805.005.f1
            "10b5 4af2bc04 c4f26774 2068 00b1 10bd 4ff63331 0c20 8722 0023 c4f21a11 fcf786fe edf413f4 2060 10bd", # oriole-uq1a.240205.002
            "10b5 44f6fc04 c4f26874 2068 00b1 10bd 40f2ff51 0c20 8722 0023 c4f21b11 fbf76ffc ebf474f3 2060 10bd", # oriole-bp1a.250505.005

            "10b5 4ef68474 c4f2bb44 2068 00b1 10bd 43f2e851 0c20 8722 0023 c4f27401 80f0d6fc c5f619f0 2060 10bd", # G991BXXSIHYK1
            "10b5 4cf6c434 c4f2ba44 2068 00b1 10bd 41f68171 0c20 8722 0023 c4f27401 79f0a8fc c2f68df7 2060 10bd", # G991BXXSCGXF5
            "10b5 4ef28474 c4f2bb44 2068 00b1 10bd 43f2e851 0c20 8722 0023 c4f27401 80f0fbff c5f6d9f3 2060 10bd", # G991BXXUEHYD5
            "10b5 4ff24454 c4f2ba44 2068 00b1 10bd 42f2d811 0c20 8722 0023 c4f27401 7af04dff c2f6a5f7 2060 10bd", # G991BXXUEGXJE
            "10b5 40f20464 c4f2bb44 2068 00b1 10bd 42f2b811 0c20 8722 0023 c4f27401 7bf0a1fe c2f6fff7 2060 10bd", # G991BXXUCGXGC
            "10b5 4ef64474 c4f2bb44 2068 00b1 10bd 43f2e851 0c20 8722 0023 c4f27401 80f0d6fc c5f619f0 2060 10bd", # G991BXXSHHYJ1
            "10b5 4ef28474 c4f2bb44 2068 00b1 10bd 43f2e851 0c20 8722 0023 c4f27401 80f0d6fc c5f619f0 2060 10bd", # G991BXXSGHYH1
            "10b5 4ef28474 c4f2bb44 2068 00b1 10bd 43f2e851 0c20 8722 0023 c4f27401 80f0fbff c5f6d9f3 2060 10bd", # G991BXXSFHYE1
            "10b5 40f2c414 c4f2bb44 2068 00b1 10bd 42f2c651 0c20 8722 0023 c4f27401 7af0ebff c2f6a9f7 2060 10bd", # G991BXXSEGXL2
            "10b5 40f24474 c4f2bb44 2068 00b1 10bd 42f2b811 0c20 8722 0023 c4f27401 7bf0a1fe c2f6fff7 2060 10bd", # G991BXXSDGXI5
        ],
        "soc_match": ["S5123","S5123AP"],
    },
    # "[N :MM,%d]    SetMmState = %lx %lx"
    # G991B: Searching back through to rediscover the cn::mm::MmGeneralContext_MacroClass::vtable via "../../../SMPF/Protocol/CoreNetwork/MM/Context/cn_MmContextProvider.hpp" in cn_MmContextProvider__MmContext
    "SetMmState": {
        "pattern": [
            "2de9f043 85b0 0446 43f29c20 1d46 1646 c4f2bb40 0390 21f6dbdd 42f66638 48ea8040 0490 96f5eadc 4bf69829 0146 2a46 3346 cff6cd69 cde90099 03a8 eff5cef1 2746 57f8281f 7b68", # oriole-ap2a.240905.003.f1
            "2de9f043 85b0 0446 49f24070 1d46 1646 c4f2bb40 0390 21f6e5dc 42f66638 48ea8040 0490 95f5e6df 4bf69829 0146 2a46 3346 cff6cd69 cde90099 03a8 f1f500f0 2746 57f8281f 7b68", # oriole-bp2a.250605.031.a5
            "2de9f043 85b0 0446 43f29c20 1d46 1646 c4f2bb40 0390 21f6dbdd 42f66638 48ea8040 0490 96f5eadc 4bf69829 0146 2a46 3346 cff6cd69 cde90099 03a8 eff5cef1 2746 57f8281f 7b68", # oriole-ap2a.240805.005.f1
            "2de9f043 85b0 0446 4ef27420 1d46 1646 c4f2ba40 0390 23f6eddf 42f66638 48ea8040 0490 96f51cdb 4bf69829 0146 2a46 3346 cff6cd69 cde90099 03a8 eff52ef6 2746 57f8281f 7b68", # oriole-uq1a.240205.002
            "2de9f043 85b0 0446 48f60040 1d46 1646 c4f2bb40 0390 21f6e3df 42f66638 48ea8040 0490 96f5e6da 4bf69829 0146 2a46 3346 cff6cd69 cde90099 03a8 f1f5faf2 2746 57f8281f 7b68", # oriole-bp1a.250505.005

            "2de9f047 86b0 4df6c058 0446 1d46 1646 c4f2b728 d8f80000 0590 43f6ec30 c4f2d820 0390 6ff48ff5 42f64639 49ea8040 0490 5cf7a3dc 4bf6982a 0146 2a46 3346 cff6cd6a cde900aa 03a8 a9f5fffb 2746 57f8281f 7b68", # G991BXXSIHYK1
            "2de9f047 86b0 4bf68828 0446 1d46 1646 c4f2b628 d8f80000 0590 41f27050 c4f2d720 0390 73f4b7f7 42f64639 49ea8040 0490 60f72cda 4bf6982a 0146 2a46 3346 cff6cd6a cde900aa 03a8 acf598fa 2746 57f8281f 7b68", # G991BXXSCGXF5
            "2de9f047 86b0 4df2f058 0446 1d46 1646 c4f2b728 d8f80000 0590 43f2ec30 c4f2d820 0390 6ff479f5 42f64639 49ea8040 0490 5cf7cbdb 4bf6982a 0146 2a46 3346 cff6cd6a cde900aa 03a8 a9f5edfb 2746 57f8281f 7b68", # G991BXXUEHYD5
            "2de9f047 86b0 4ef2d838 0446 1d46 1646 c4f2b628 d8f80000 0590 43f69870 c4f2d720 0390 73f49bf6 42f64639 49ea8040 0490 5ff704dd 4bf6982a 0146 2a46 3346 cff6cd6a cde900aa 03a8 abf5a6f8 2746 57f8281f 7b68", # G991BXXUEGXJE
            "2de9f047 86b0 4ff29848 0446 1d46 1646 c4f2b628 d8f80000 0590 45f23c00 c4f2d720 0390 71f459f2 42f64639 49ea8040 0490 5df78bda 4bf6982a 0146 2a46 3346 cff6cd6a cde900aa 03a8 a8f5d2fc 2746 57f8281f 7b68", # G991BXXUCGXGC
            "2de9f047 86b0 4df6a058 0446 1d46 1646 c4f2b728 d8f80000 0590 43f6ac30 c4f2d820 0390 6ff495f5 42f64639 49ea8040 0490 5cf7a9dc 4bf6982a 0146 2a46 3346 cff6cd6a cde900aa 03a8 a9f5fdfb 2746 57f8281f 7b68", # G991BXXSHHYJ1
            "2de9f047 86b0 4df2f058 0446 1d46 1646 c4f2b728 d8f80000 0590 43f2ec30 c4f2d820 0390 6ff483f5 42f64639 49ea8040 0490 5cf79fdc 4bf6982a 0146 2a46 3346 cff6cd6a cde900aa 03a8 a9f5f7fb 2746 57f8281f 7b68", # G991BXXSGHYH1
            "2de9f047 86b0 4df2f058 0446 1d46 1646 c4f2b728 d8f80000 0590 43f2ec30 c4f2d820 0390 6ff479f5 42f64639 49ea8040 0490 5cf7cbdb 4bf6982a 0146 2a46 3346 cff6cd6a cde900aa 03a8 a9f5edfb 2746 57f8281f 7b68", # G991BXXSFHYE1
            "2de9f047 86b0 4ff25808 0446 1d46 1646 c4f2b628 d8f80000 0590 44f64c50 c4f2d720 0390 73f475f7 42f64639 49ea8040 0490 5ff7b8de 4bf6982a 0146 2a46 3346 cff6cd6a cde900aa 03a8 abf58cf9 2746 57f8281f 7b68", # G991BXXSEGXL2
            "2de9f047 86b0 4ff2d858 0446 1d46 1646 c4f2b628 d8f80000 0590 45f27c10 c4f2d720 0390 71f439f2 42f64639 49ea8040 0490 5df769da 4bf6982a 0146 2a46 3346 cff6cd6a cde900aa 03a8 a9f5d0fe 2746 57f8281f 7b68", # G991BXXSDGXI5
        ],
        "soc_match": ["S5123","S5123AP"],
    },
    # "[N :MM,%d]  Start Procedure : %d" and calls NrmmStartProcedure
    "NrmmStartProcedure_Wrapper": {
        "pattern": [
            "b0b5 0c46 0546 0129 03d1 2846 0221 eaf723fe e86c 2146 bde8b040 c7f57dbe", # oriole-ap2a.240905.003.f1
            "b0b5 0c46 0546 0129 03d1 2846 0221 ebf7c5fe e86c 2146 bde8b040 c6f50abd", # oriole-bp2a.250605.031.a5
            "b0b5 0c46 0546 0129 03d1 2846 0221 eaf723fe e86c 2146 bde8b040 c7f57dbe", # oriole-ap2a.240805.005.f1
            "b0b5 0c46 0546 0129 03d1 2846 0221 e9f7c4f8 e86c 2146 bde8b040 c8f572b8", # oriole-uq1a.240205.002
            "b0b5 0c46 0546 0129 03d1 2846 0221 ebf7c5fe e86c 2146 bde8b040 c6f5f0bc", # oriole-bp1a.250505.005

            "b0b5 0c46 0546 012c 03d1 2846 0221 d8f744f8 e86c 2146 bde8b040 c9f6b1b2", # G991BXXSIHYK1
            "b0b5 0c46 0546 012c 03d1 2846 0221 cbf72efc e86c 2146 bde8b040 c7f625b2", # G991BXXSCGXF5
            "b0b5 0c46 0546 012c 03d1 2846 0221 d8f7befa e86c 2146 bde8b040 c9f671b6", # G991BXXUEHYD5
            "b0b5 0c46 0546 012c 03d1 2846 0221 ccf79afe e86c 2146 bde8b040 c7f63db2", # G991BXXUEGXJE
            "b0b5 0c46 0546 012c 03d1 2846 0221 cef73ef8 e86c 2146 bde8b040 c7f697b2", # G991BXXUCGXGC
            "b0b5 0c46 0546 012c 03d1 2846 0221 d8f744f8 e86c 2146 bde8b040 c9f6b1b2", # G991BXXSHHYJ1
            "b0b5 0c46 0546 012c 03d1 2846 0221 d8f744f8 e86c 2146 bde8b040 c9f6b1b2", # G991BXXSGHYH1
            "b0b5 0c46 0546 012c 03d1 2846 0221 d8f7befa e86c 2146 bde8b040 c9f671b6", # G991BXXSFHYE1
            "b0b5 0c46 0546 012c 03d1 2846 0221 ccf79cfe e86c 2146 bde8b040 c7f641b2", # G991BXXSEGXL2
            "b0b5 0c46 0546 012c 03d1 2846 0221 cef73ef8 e86c 2146 bde8b040 c7f697b2", # G991BXXSDGXI5

            "b0b5 0c46 0546 ???? 03d1 2846 0221 ???????? e86c 2146 bde8b040 ????????",
        ],
        "soc_match": ["S5123","S5123AP"],
    },
    "MM_MSG_CLASS": {
        "lookup": handlers.find_mm_msg_class,
        "soc_match": ["S5123","S5123AP"],
    },
    "MM_MSG_DOMAIN": {
        "lookup": handlers.find_mm_msg_domain,
        "soc_match": ["S5123","S5123AP"],
    },
    "NrmmFacade": { #placeholder
        "pattern": [
            "10b5 44f27c52 44f66023 0446 0020 c4f23102 c4f23103 0832 0833 c4e90020 c4e90200 c4e90403 c4e90610 04f12000", # oriole-ap2a.240905.003.f1
            "10b5 ???????? ???????? 0446 0020 ???????? ???????? 0832 0833 ???????? ???????? ???????? ???????? ????????", # oriole

            "10b5 ???????? ???????? 0446 0020 ???????? ???????? 0832 0833 ???????? ???????? ???????? ???????? ????????", # CP_G991BXXSDGXI5
            "10b5 ???????? ???????? 0446 0020 ???????? ???????? 0832 0833 ???????? ???????? ???????? ???????? ????????", # CP_G991BXXSEGXL2
            "10b5 ???????? ???????? 0446 0020 ???????? ???????? 0832 0833 ???????? ???????? ???????? ???????? ????????", # CP_G991BXXSFHYE1
            "10b5 ???????? ???????? 0446 0020 ???????? ???????? 0832 0833 ???????? ???????? ???????? ???????? ????????", # CP_G991BXXSGHYH1
            "10b5 ???????? ???????? 0446 0020 ???????? ???????? 0832 0833 ???????? ???????? ???????? ???????? ????????", # CP_G991BXXUEGXJE_CP28097318_MQB88157872_REV01_user_low_ship_MULTI_CERT
        ],
        "soc_match": ["S5123", "S5123AP"],
    },
    "CreateNrmmFacade_func": { #returns NrmmFacade
        "pattern": [
            "10b5 44f27c52 44f66023 0446 0020 c4f23102 c4f23103 0832 0833 c4e90020 c4e90200 c4e90403 c4e90610 04f12000", # oriole-ap2a.240905.003.f1
            "10b5 ???????? ???????? 0446 0020 ???????? ???????? 0832 0833 ???????? ???????? ???????? ???????? ????????", # oriole

            "10b5 ???????? ???????? 0446 0020 ???????? ???????? 0832 0833 ???????? ???????? ???????? ???????? ????????", # CP_G991BXXSDGXI5
            "10b5 ???????? ???????? 0446 0020 ???????? ???????? 0832 0833 ???????? ???????? ???????? ???????? ????????", # CP_G991BXXSEGXL2
            "10b5 ???????? ???????? 0446 0020 ???????? ???????? 0832 0833 ???????? ???????? ???????? ???????? ????????", # CP_G991BXXSFHYE1
            "10b5 ???????? ???????? 0446 0020 ???????? ???????? 0832 0833 ???????? ???????? ???????? ???????? ????????", # CP_G991BXXSGHYH1
            "10b5 ???????? ???????? 0446 0020 ???????? ???????? 0832 0833 ???????? ???????? ???????? ???????? ????????", # CP_G991BXXUEGXJE_CP28097318_MQB88157872_REV01_user_low_ship_MULTI_CERT
        ],
        "soc_match": ["S5123","S5123AP"],
    },
    "MmGeneralContext": { #placeholder
        "pattern": [
            "b0b5 0446 45f23800 1121 c4f23100 0830 2060 04f13c00 caf082c0 0020 5021 a4f8ba00 84f8b800 c4f8bc00", # oriole-ap2a.240905.003.f1
            "b0b5 0446 45f23800 1121 c4f23100 0830 2060 04f13c00 caf082c0 0020 5021 a4f8ba00 84f8b800 c4f8bc00", # oriole-ap2a.240805.005.f1
            "b0b5 0446 ???????? 1121 ???????? 0830 2060 ???????? ???????? 0020 5021 ???????? ???????? ????????", # oriole-bp1a.250505.005
            "b0b5 0446 ???????? 1121 ???????? 0830 2060 ???????? ???????? 0020 5021 ???????? ???????? ????????", # oriole-bp2a.250605.031.a5
            "b0b5 0446 ???????? 1121 ???????? 0830 2060 ???????? ???????? 0020 5021 ???????? ???????? ????????", # oriole-uq1a.240205.002

            "b0b5 0446 40f25c00 1121 c4f23000 0830 2060 04f13c00 eef0c2c7 0025 04f16600 5021 a4f8ba50", # CP_G991BXXSDGXI5
            "b0b5 0446 ???????? 1121 ???????? 0830 2060 ???????? ???????? 0025 ???????? 5021 ????????", # CP_G991BXXSEGXL2
            "b0b5 0446 ???????? 1121 ???????? 0830 2060 ???????? ???????? 0025 ???????? 5021 ????????", # CP_G991BXXSFHYE1
            "b0b5 0446 ???????? 1121 ???????? 0830 2060 ???????? ???????? 0025 ???????? 5021 ????????", # CP_G991BXXSGHYH1
            "b0b5 0446 ???????? 1121 ???????? 0830 2060 ???????? ???????? 0025 ???????? 5021 ????????", # CP_G991BXXUEGXJE_CP28097318_MQB88157872_REV01_user_low_ship_MULTI_CERT
        ],
        "soc_match": ["S5123", "S5123AP"],
    },
    "CreateMmGeneralContext_func": { #returns MmGeneralContext
        "pattern": [
            "b0b5 0446 45f23800 1121 c4f23100 0830 2060 04f13c00 caf082c0 0020 5021 a4f8ba00 84f8b800 c4f8bc00", # oriole-ap2a.240905.003.f1
            "b0b5 0446 45f23800 1121 c4f23100 0830 2060 04f13c00 caf082c0 0020 5021 a4f8ba00 84f8b800 c4f8bc00", # oriole-ap2a.240805.005.f1
            "b0b5 0446 ???????? 1121 ???????? 0830 2060 ???????? ???????? 0020 5021 ???????? ???????? ????????", # oriole-bp1a.250505.005
            "b0b5 0446 ???????? 1121 ???????? 0830 2060 ???????? ???????? 0020 5021 ???????? ???????? ????????", # oriole-bp2a.250605.031.a5
            "b0b5 0446 ???????? 1121 ???????? 0830 2060 ???????? ???????? 0020 5021 ???????? ???????? ????????", # oriole-uq1a.240205.002

            "b0b5 0446 40f25c00 1121 c4f23000 0830 2060 04f13c00 eef0c2c7 0025 04f16600 5021 a4f8ba50", # CP_G991BXXSDGXI5
            "b0b5 0446 ???????? 1121 ???????? 0830 2060 ???????? ???????? 0025 ???????? 5021 ????????", # CP_G991BXXSEGXL2
            "b0b5 0446 ???????? 1121 ???????? 0830 2060 ???????? ???????? 0025 ???????? 5021 ????????", # CP_G991BXXSFHYE1
            "b0b5 0446 ???????? 1121 ???????? 0830 2060 ???????? ???????? 0025 ???????? 5021 ????????", # CP_G991BXXSGHYH1
            "b0b5 0446 ???????? 1121 ???????? 0830 2060 ???????? ???????? 0025 ???????? 5021 ????????", # CP_G991BXXUEGXJE_CP28097318_MQB88157872_REV01_user_low_ship_MULTI_CERT
        ],
        "soc_match": ["S5123", "S5123AP"],
    }
}
