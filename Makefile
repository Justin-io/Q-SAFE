all: qsafe_demo protected_app

qsafe_demo: qsafe_monitor.o qsafe_driver.o
	gcc -no-pie -o qsafe_demo qsafe_driver.o qsafe_monitor.o

protected_app: qsafe_monitor.o protected_app.c
	# Compiling with protections DISABLED to allow simple buffer overflow
	gcc -no-pie -fno-stack-protector -z execstack -o protected_app protected_app.c qsafe_monitor.o

qsafe_monitor.o: qsafe_monitor.asm
	nasm -f elf64 -o qsafe_monitor.o qsafe_monitor.asm

qsafe_driver.o: qsafe_driver.c
	gcc -c qsafe_driver.c -o qsafe_driver.o

clean:
	rm -f *.o qsafe_demo allowlist.bin
