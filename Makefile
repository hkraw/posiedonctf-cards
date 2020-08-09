all:
	wget https://raw.githubusercontent.com/jwang-a/CTF/master/utils/Pwn/SECCOMP.h
	gcc -Wl,-z,now -fpie -fstack-protector-all -s cards.c -o cards
	strip cards
	rm SECCOMP.h
clean:
	rm cards
