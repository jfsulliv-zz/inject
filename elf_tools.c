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
#include "elf_tools.h"

/* 
 * Contains a variety of ELF related tools for parsing,
 *  dissecting, and modifying ELFS.
 */

const char JMP_INSTR    = ARCH_JUMP_INSTR;
const int REDIR_SZ      = 5;
const UWORD BASE_ADDR   = ARCH_BASE_ADDR;

/* 
 * Returns a pointer to the n'th Section Header 
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

/* 
 * Expands the size of any segments containing addr by n bytes,
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

/* 
 * Shifts the address of all dynamic section entries by n bytes,
 *  if they are between base and top.
 * Returns 0 on success, 1 on failure
 */
int rearrange_dynamic(char *elf, ElfN_Shdr *shdr, void *base, 
        void *top, size_t n)
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

/* 
 * Shifts the address of all reloc objects by n bytes,
 *  if they are between base and top.
 * Returns 0 on success, 1 on failure
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
        int num, i;
        UWORD addr;
        if(shdr->sh_type == SHT_RELA) {
            num = shdr->sh_size / sizeof(ElfN_Rela);
            ElfN_Rela *rel;
            for(i = 0; i < num; i++) {
                addr = ((UWORD)elf + shdr->sh_offset 
                        + (i * sizeof(ElfN_Rela)));
                rel = (ElfN_Rela *)addr;
                if((UWORD)rel->r_offset >= (UWORD)base
                        && (UWORD)rel->r_offset < (UWORD)top) {
                    rel->r_offset += n;
                }
            }
        }
        else if(shdr->sh_type == SHT_REL) {
            num = shdr->sh_size / sizeof(ElfN_Rel);
            ElfN_Rel *rel;
            for(i = 0; i < num; i++) {
                addr = ((UWORD)elf + shdr->sh_offset 
                        + (i * sizeof(ElfN_Rel)));
                rel = (ElfN_Rel *)addr;
                if((UWORD)rel->r_offset >= (UWORD)base
                        && (UWORD)rel->r_offset < (UWORD)top) {
                    rel->r_offset += n;
                }
            }
        }
    }

    return 0;
}

/* 
 * Shifts the address of all symtab section entries by n bytes,
 *  if they are between base and top.
 * Returns 0 on success, 1 on failure
 */
int rearrange_syms(char *elf, void *base, void *top,
        size_t n)
{
    if(!elf)
        return 1;

    int sh_num;
    sh_num = 0;
    ElfN_Shdr *shdr;

    while((shdr = get_s_header(elf,sh_num++))) {
        /* Concerned with dynamic and regular symbol tables */
        if(shdr->sh_type == SHT_DYNSYM 
                || shdr->sh_type == SHT_SYMTAB) {
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
 * Move sections in memory based on the difference in their 
 *  offsets from the original ELF.
 * The section header table may also be moved if it is at risk
 *  of overwrite.
 * Returns 0 on success and 1 on failure.
 */
int move_sections(char *elf, char *new_elf)
{
    if(!elf || !new_elf)
        return 1;
    ElfN_Ehdr *ehdr;
    ElfN_Ehdr *new_ehdr;
    ehdr = (ElfN_Ehdr *)elf;
    new_ehdr = (ElfN_Ehdr *)new_elf;
    if(ehdr->e_shnum != new_ehdr->e_shnum)
        return 1;

    UWORD sht_loc;
    sht_loc = (UWORD)new_elf + new_ehdr->e_shoff;
    UWORD sht_sz;
    sht_sz = new_ehdr->e_shnum * new_ehdr->e_shentsize;

    int i;
    ElfN_Shdr *shdr;
    ElfN_Shdr *new_shdr;
    /* Work backwards since we're shifting data strictly up */
    for(i = ehdr->e_shnum-1; i >= 0; i--) {
        shdr = get_s_header(elf,i);
        new_shdr = get_s_header(new_elf,i);
        if(!shdr || !new_shdr)
            return 1;

        WORD diff;
        UWORD sz;
        diff = new_shdr->sh_offset - shdr->sh_offset;
        if(diff < 0)
            return 1;
        if(diff == 0)
            continue;
        sz = new_shdr->sh_size;

        UWORD shdr_addr;
        shdr_addr = (UWORD)new_elf + new_shdr->sh_offset - diff;
        /* Check if we're stomping our header table */
        if(shdr_addr + sz > sht_loc) {
            /* Move the header table by this amount */
            memmove((void *)sht_loc + diff,
                    (void *)sht_loc,
                    sht_sz);
            /* Also update the reference to the header */
            new_ehdr->e_shoff += diff;
            sht_loc += diff;
        }

        /* If this section contains relocatable objects
         * that are referenced, then we need to increase
         * their offset by diff */
        if(new_shdr->sh_addr) {
            rearrange_relocs(new_elf, 
                    (void *)new_shdr->sh_addr,
                    (void *)new_shdr->sh_addr + sz,
                    diff);
        }

        /* Now we can move the section */ 
        memmove((void *)shdr_addr + diff,
                (void *)shdr_addr,
                sz);
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
int shift_sh_offsets(char *elf, ElfN_Shdr *shdr, 
        ElfN_Shdr *dyn_shdr, size_t n, size_t bias)
{
    if(!elf || !shdr)
        return 0;

    int i;
    i = shdr_index(elf, shdr);
    if(i == -1)
        return 0;

    ElfN_Shdr *shdr_next;
    shdr_next = get_s_header(elf, i+1);
    if(!shdr_next) {
        return bias;
    } 

    if(shdr_next->sh_flags & SHF_ALLOC && shdr_next->sh_addralign) {
        /* Set bias to the next aligned value */
        if(bias % shdr_next->sh_addralign) {
            bias += shdr_next->sh_addralign;
            bias -= (bias % shdr_next->sh_addralign);
        }
    }

    bias = shift_sh_offsets(elf,shdr_next,dyn_shdr,n,bias);

    /* Any dynamic objects that live in this section
     * must be shifted; do this after to guarantee we don't
     * shift our dyn table */
    if(dyn_shdr) {
        rearrange_dynamic(elf, dyn_shdr,
                (void *)shdr_next->sh_addr,
                (void *)shdr_next->sh_addr + shdr_next->sh_size,
                bias);
    }

    /* Now we can inc the offset and address by the bias */
    shdr_next->sh_offset += bias;
    if(shdr_next->sh_addr) 
        shdr_next->sh_addr += bias;

    return bias;
}


/* 
 * Expands the given section by n bytes by increasing its size.
 * Any following sections will have their offsets increased and 
 *  their file offset by this amount.
 * Any following loaded sections will have their address increased,
 *  with alignment maintained.
 * The section header table may move during this process,
 *  to prevent data loss- in this case, section header pointers
 *  must be reassigned.
 * Any dynamic objects will have their addresses increased if 
 *  their address is after this section's start.
 * Returns the introduced bias on success or 0 on failure.
 */
int expand_section(char *old_elf, char *elf, ElfN_Shdr *shdr, 
        ElfN_Shdr *dyn_shdr, size_t n)
{
    if(!elf || !shdr)
        return 0;
    if(dyn_shdr) {
        if(dyn_shdr->sh_type != SHT_DYNAMIC)
            return 0;
    }

    int shdr_ind;
    shdr_ind = shdr_index(elf,shdr);
    if(shdr_ind == -1)
        return 0;

    shdr->sh_size += n;
    int ret;
    ret = shift_sh_offsets(elf, shdr, dyn_shdr, n, n);
    ElfN_Ehdr *ehdr;
    ehdr = (ElfN_Ehdr *)elf;

    /* Also expand and shift segments */
    UWORD shdata_addr;
    shdata_addr = (UWORD)elf + shdr->sh_offset;
    expand_segments(elf,(void *)shdata_addr,ret);

    /* We may have to shift our header table */
    int off;
    if(ret > n)
        off = ret;
    else
        off = n;
    off += 8;
    off -= (off % 8);
    UWORD shtab_addr;
    shtab_addr = (UWORD)elf+ ehdr->e_shoff;
    UWORD shtab_sz;
    shtab_sz = ehdr->e_shnum * ehdr->e_shentsize;
    memmove((void *)shtab_addr + off,
            (void *)shtab_addr,
            shtab_sz);
    ehdr->e_shoff += off;

    /* Move the actual data in the sections */
    if(move_sections(old_elf, elf))
        return 0;

    return off; 
}

/*
 * Increments the value of sh_link for any header
 *  that has sh_link greater than or equal to index.
 * This is used when a new section is inserted at index,
 *  to update the link index.
 * Returns 1 on failure or 0 on success.
 */
int fix_sh_links(char *elf, size_t index) 
{
    if(!elf)
        return 1;

    ElfN_Shdr *shdr;
    int i;
    i = 0;
    while((shdr = get_s_header(elf,i++))) {
        if(shdr->sh_link >= index)
            shdr->sh_link++;
    }
    return 0;
}

/* 
 * Inserts a new section header entry at the given table
 *  index, as long as this index is no greater than the
 *  size of the table. Assumes that the table has at least
 *  sizeof(ElfN_Shdr) bytes of free space after it. 
 * Since some section headers may be moved during the insertion,
 *  it is unsafe to assume that section header references will
 *  still be valid after this process- they should be reassigned.
 * Returns a pointer to the new entry on success, or NULL on 
 *  failure.
 */
ElfN_Shdr *insert_section_hdr(char *elf, size_t index)
{
    if(!elf)
        return NULL;

    ElfN_Ehdr *ehdr;
    ehdr = (ElfN_Ehdr *)elf;

    if(index > ehdr->e_shnum)
        return NULL;

    /* See if we need to update the section header string table
     * index */
    if(index <= ehdr->e_shstrndx)
        ehdr->e_shstrndx += 1;
    /* Also check if any headers after this one are referenced
     *  by a relocation section with sh_link; if so, we need
     *  to increment sh_link to account for the new index. 
     */
    fix_sh_links(elf, index);
    /* Increment shnum */
    ehdr->e_shnum++;

    /* Move all of the table entries after index */
    UWORD start_addr;
    UWORD end_addr;
    UWORD sz;
    /* Starting from the current entry at index */
    start_addr = (UWORD)elf + ehdr->e_shoff + 
        (ehdr->e_shentsize * index);
    /* Moved back by the size of an entry */
    end_addr = start_addr + ehdr->e_shentsize;
    /* Moving back shnum - index entries */
    sz = ehdr->e_shentsize * (ehdr->e_shnum - index);
    if(sz) {
        memmove((void *)end_addr,
                (void *)start_addr,
                sz);
    }
    /* Zero the new header and return a reference */
    memset((void *)start_addr, 0, ehdr->e_shentsize);
    ElfN_Shdr *new_shdr;
    new_shdr = (ElfN_Shdr *)start_addr;
    return new_shdr; 
}

/* 
 * Injects a new section into the ELF loaded into 'elf',
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

    char *new_elf;
    new_elf = *dst;

    /* How many bytes we have written to the new ELF */
    UWORD bytes_written;
    bytes_written = 0;
    WORD bytes_to_copy;

    /* Copy in the new ELF */
    bytes_to_copy = elf_sz;
    memcpy(new_elf, elf, bytes_to_copy);
    bytes_written += bytes_to_copy;

    ElfN_Ehdr *new_ehdr;
    new_ehdr = (ElfN_Ehdr *)new_elf;

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

    /* Mark where the new code goes - if there is a plt
     * section, put it before that. If not, put it before
     * .text (and if it has neither, abort)
     */
    WORD new_shdr_ind;
    UWORD code_loc, code_sz, code_addr;
    ElfN_Shdr *text_shdr;
    text_shdr = find_section_hdr(elf, ".text");
    if(!text_shdr)
        goto fail;
    ElfN_Shdr *plt_shdr;
    plt_shdr = find_section_hdr(elf, ".plt");
    if(!plt_shdr) {
        code_loc = (UWORD)new_elf + text_shdr->sh_offset;
        code_addr = text_shdr->sh_addr;
        new_shdr_ind = shdr_index(elf,text_shdr);
    } else {
        code_loc = (UWORD)new_elf + plt_shdr->sh_offset;
        code_addr = plt_shdr->sh_addr;
        new_shdr_ind = shdr_index(elf,plt_shdr);
    }
    code_sz = dat_sz + REDIR_SZ;
    if(new_shdr_ind == -1)
        goto fail;

    /* Mark where the new strtab goes */
    ElfN_Shdr *new_sht;
    new_sht = get_s_header(new_elf, ehdr->e_shstrndx);
    if(!new_sht)
        goto fail;
    UWORD shent_loc;
    shent_loc = (UWORD)new_elf + new_sht->sh_offset 
        + new_sht->sh_size;
    UWORD shent_sz;
    shent_sz = strlen(sect_name) + 1;

    /* Make room for our new string table entry */
    int bias;
    bias = expand_section(elf,new_elf, new_sht, new_dyn_shdr,
            shent_sz);
    bytes_written += bias; 

    /* Fix references in case header table moved */
    new_sht = get_s_header(new_elf, ehdr->e_shstrndx);
    if(!new_sht)
        goto fail;
    new_dyn_shdr = get_s_header(new_elf, dyn_shdr_ind);
    if(!new_dyn_shdr)
        goto fail;

    /* Make room for the new code */
    ElfN_Shdr *prev_hdr;
    prev_hdr = get_s_header(new_elf, new_shdr_ind - 1);
    if(!prev_hdr)
        goto fail;
    bias = expand_section(elf,new_elf, prev_hdr, new_dyn_shdr, 
            code_sz);
    bytes_written += bias;

    /* Fix references in case header table moved */
    new_sht = get_s_header(new_elf, ehdr->e_shstrndx);
    if(!new_sht)
        goto fail;
    prev_hdr = get_s_header(new_elf, new_shdr_ind - 1);
    if(!prev_hdr)
        goto fail;

    /* Just undo the size increase for this section, 
     * since we're adding a new one instead */
    prev_hdr->sh_size -= (dat_sz + REDIR_SZ);

    /* Now we can inject the new code */
    bytes_to_copy = dat_sz;
    memcpy((void *)code_loc,
            dat,
            bytes_to_copy);

    /* Also inject a jump instruction, but leave the dst for now */
    UWORD jmp_instr_addr;
    jmp_instr_addr = (UWORD)code_loc + dat_sz;
    char * jmp_instr;
    jmp_instr = (char *)jmp_instr_addr;
    jmp_instr[0] = JMP_INSTR;
    UWORD jmp_dst_addr;
    jmp_dst_addr = (UWORD)jmp_instr_addr + 1;
    int32_t *jmp_dst;
    jmp_dst = (int32_t *)jmp_dst_addr;

    /* Insert the new strtab entry */
    shent_loc = (UWORD)new_elf + new_sht->sh_offset 
        + new_sht->sh_size;
    shent_sz = strlen(sect_name) + 1;
    shent_loc -= shent_sz;
    int str_ind;
    str_ind = new_sht->sh_size - shent_sz;
    bytes_to_copy = shent_sz;
    memcpy((void *)shent_loc,
            sect_name,
            bytes_to_copy);

    /* Insert the new section header before the .text section
     *  header */
    ElfN_Shdr *new_shdr;
    new_shdr = insert_section_hdr(new_elf, new_shdr_ind); 
    if(!new_shdr)
        goto fail;
    new_shdr->sh_name = str_ind; /* Name index in strtab */
    new_shdr->sh_type = SHT_PROGBITS; /* Contains prog code */
    new_shdr->sh_flags = SHF_EXECINSTR | SHF_ALLOC;
    new_shdr->sh_offset = code_loc - (UWORD)new_elf; 
    new_shdr->sh_addr = code_addr; 
    new_shdr->sh_size = dat_sz + REDIR_SZ;
    new_shdr->sh_addralign = 4;
    bytes_written += sizeof(ElfN_Shdr);

    /* Set the new entry point */
    new_ehdr->e_entry = new_shdr->sh_addr;

    /* Finally set the jmp target */
    UWORD old_entry, new_entry;
    old_entry = ehdr->e_entry;
    new_entry = new_ehdr->e_entry;
    uint32_t jmp_rel; 
    jmp_rel = (uint32_t)old_entry - (uint32_t)new_entry;
    jmp_rel -= code_sz;
    *jmp_dst = jmp_rel;

    return bytes_written;
fail:
    return -1;
}
