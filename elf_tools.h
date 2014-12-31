#include <sys/types.h>

/* Contains useful macros and definitions for elf_tools */
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
#define ElfN_Rel     Elf64_Rel
#define ElfN_Rela    Elf64_Rela
#define ElfN_Sym     Elf64_Sym
#define ELFN_R_SYM   ELF64_R_SYM
#define ELFN_R_SYM_SHIFT 32
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
#define ElfN_Rel     Elf32_Rel
#define ElfN_Rela    Elf32_Rela
#define ElfN_Sym     Elf32_Sym
#define ELFN_R_SYM   ELF32_R_SYM
#define ELFN_R_SYM_SHIFT 8
#define print_addr(format, ...) do {            \
    printf(format "0x%08x",                     \
            (unsigned int)__VA_ARGS__);         \
} while(0)
#endif

int inject_section(
        char *elf, size_t elf_sz,
        char *dat, size_t dat_sz,
        const char *sect_name,
        char **dst);
