#include <stdio.h>
#include <stdlib.h>

void to_remove() {

        int arg;
        arg = "/bin/sh";
        system(arg);
}


void stack() {

        char buf[140];
        printf("Please enter a value: \n");
        scanf("%s", &buf);
        puts(buf);
}

void strings() {

        char buf[200];
        printf("Please enter a value: \n");
        read(0, buf, sizeof(buf));
        printf(buf);
        exit(0);


}

int main() {

        printf("Please select: \n1) Echo stuff\n2) Use those strings!!\n> ");
        int userinput;
        scanf("%d", &userinput);
        if (userinput == 1) {
                stack();
        }
        else if (userinput == 2) {
                strings();
        }
        else {
                printf("Wrong input\n");
                exit(0);
        }
}
