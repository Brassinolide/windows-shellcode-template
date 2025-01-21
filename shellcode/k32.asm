.code
GetK32 proc
	mov rax,gs:[60h]
	mov rax,[rax+18h]
	mov rax,[rax+30h]
	mov rax,[rax]
	mov rax,[rax]
	mov rax,[rax+10h]
	ret
GetK32 endp
end