#include <Windows.h>
#include <stdio.h>

int main()
{
	DWORD dwIsDebug = 0;
    __asm {
        pushad
        mov eax, fs: [30h]
        movzx ecx, byte ptr[eax + 2]
        cmp ecx, 1
        jz Again
        jmp Bye
        Again :
            int 3
        Bye :
            popad
    }
    printf("HelloWorld...\n");
	return 0;
}