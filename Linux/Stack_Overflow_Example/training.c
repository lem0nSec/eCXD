// Compile me with one of the followings:

// (x86 - no protections) | gcc -m32 -no-pie -fno-stack-protector -z execstack training.c -o training
// (x86 - NX) | gcc -m32 -no-pie -fno-stack-protector training.c -o training
// (x86 - NX + Canary) | gcc -m32 -no-pie -fstack-protector-all training.c -o training

// (x86_64 - no protections) | gcc -no-pie -fno-stack-protector -z execstack training.c -o training
// (x86_64 - NX) | gcc -no-pie -fno-stack-protector training.c -o training
// (x86_64 - NX + Canary) | gcc -no-pie -fstack-protector-all training.c -o training

// ASLR on Linux can be disabled or enabled by issuing the following commands as root:

// (disable ASLR) | echo 0 > /proc/sys/kernel/randomize_va_space
// (enable ASLR) | echo 2 > /proc/sys/kernel/randomize_va_space

#include <stdio.h>

void vuln() {

	char buf[600];
	gets(buf);
	puts(buf);
}

int main(void) {

	vuln();

}
