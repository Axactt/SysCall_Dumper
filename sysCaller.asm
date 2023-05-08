

option casemap:none    ; To make assembly instruction case sensitive


.data 

fmtStr db "NtGetCurrentProcessorNumberEx: %11d",0


.code

externdef printf:proc ; to define external printf function inside our assembly procedure


public asmSysCaller

asmSysCaller proc

sub rsp,20h
;and rsp,0fffffffffffffff0h

mov rcx,0
mov r10,rcx
mov eax, 0fbh ; NtGetCurrentProcessorNumberEx

syscall
lea rcx,fmtStr
mov rdx, rdi  ; why rdi is used as an argument to printf ,does syscall return value in rdi
call printf

add rsp,20h
ret

asmSysCaller endp
end


