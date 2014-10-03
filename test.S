bits 32
section .text
_start:
    xor eax, eax
    xor ebx, ebx
    inc eax
    int 0x80
    jmp -29
