#  Note: Assignment will be graded with a fresh copy of this file
#  Note: You must run ./setcookie before running make.

CC := gcc
CFLAGS := -m32 -fno-pie -no-pie -static -U_FORTIFY_SOURCE -DCOOKIE=$(shell cat cookie)
LDFLAGS :=
LDLIBS :=

programs := 1.1.1 1.1.2 1.1.3 1.1.4 1.1.5 1.2.1 1.2.2 1.2.3 1.2.4 1.2.5 1.2.6 1.2.7 1.2.8 1.2.9 1.2.10 1.2.11

.PHONY: default clean install uninstall 1.1.5

default: $(programs) 1.1.5 permissions

1.1.1: CFLAGS += -w
1.1.2: CFLAGS +=
1.1.3: CFLAGS +=
1.1.4: CFLAGS +=
1.2.1: CFLAGS += -fno-stack-protector -z execstack
1.2.2: CFLAGS += -fno-stack-protector -z execstack
1.2.3: CFLAGS += -fno-stack-protector -z execstack 
1.2.4: CFLAGS += -fno-stack-protector -z execstack 
1.2.5: CFLAGS += -fno-stack-protector -z execstack
1.2.6: CFLAGS += -fno-stack-protector
1.2.7: CFLAGS += -fno-stack-protector -z execstack
1.2.8: CFLAGS += -fno-stack-protector -z execstack
1.2.9: CFLAGS += -fno-stack-protector -z execstack -w
1.2.10: CFLAGS += -fno-stack-protector
1.2.11: CFLAGS += -fno-stack-protector -z execstack

1.1.1: 1.1.1.c helper.c 1.1.1.S
1.1.2: 1.1.2.c helper.c 1.1.2.S
1.1.3: 1.1.3.c helper.c 1.1.3.S
1.1.4: 1.1.4.c helper.c 1.1.4.S
1.2.1: 1.2.1.c helper.c
1.2.2: 1.2.2.c helper.c
1.2.3: 1.2.3.c helper.c
1.2.4: 1.2.4.c helper.c
1.2.5: 1.2.5.c helper.c
1.2.6: 1.2.6.c helper.c
1.2.7: 1.2.7.c helper.c
1.2.8: 1.2.8.c helper.c
1.2.9: 1.2.9.c helper.c
1.2.10: 1.2.10.c helper.c
1.2.11: 1.2.11.c helper.c

1.1.5:
	gcc -m32 -fno-pie -no-pie -static 1.1.5.S helper.c -o 1.1.5

clean:
	rm -f $(programs)

permissions:
	sudo chown root:student 1.2.[123456789] 1.2.10 1.2.11 1.1.5
	sudo chmod 6777 1.2.[123456789] 1.2.10 1.2.11 1.1.5
	
