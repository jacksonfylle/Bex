#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int vulnerable2()
{
    char str4[20];
    scanf("%s",str4);
    if (str4[1] == 'y') {
        if (str4[0] == 'z') {
            return 0;
        }
    }
    return -1;
}

char * readW()
{
    int x;
    int i = 0;
    char str[100];
    x = fgetc(stdin);
    do
    {
        x = fgetc(stdin);
        printf ("x = %d ('%c')\n", x, x);
        str[i] = x;
        i++;
        if(x == 10){
            str[i] = '\x00';
            break;
        }
    }
    while (1);
    return str;
}


int vulnerable(const char *arg) {
    char str1[20];
    char *str2;
    char str3[20];
    char *str4;
    int retcode;
    int mytest;
    if(arg[1] == 'u') {
        if(arg[0] == 'f') {
            if(arg[2] == 'z') {
                scanf("%s", str1);
                mytest = atoi(str1);
                if(mytest > 200) {
                    if(arg[3] == 'z') {
                        str4 = readW();
                        printf("%s asdfasf\n", str4);
                        if (strlen(str4) > 6) {
                            if(str4[4] == 'h') {
                                return 0;
                            } else {
                                // lets deref some user specified memory
                                int** z = (int**)((void*)(arg+4));
                                return **z;
                            }
                        }
                    }
                }
            }
            if(arg[2] == 'r') {
                if(arg[3] == 'i') {
                    str2= (char *) malloc(30);
                    scanf("%s", str2);
                    if(str2[0] == 'b') {
                        if(arg[4] == 'o') {
                            while (1) {
                                scanf("%s", str3);
                                retcode = vulnerable2();
                                if (str3[1] == 'b') {
                                    if (str3[0] == 'a') {
                                        return retcode;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return -1;
}

int main(int argc, const char *argv[]) {

    if(argc != 2) {
        printf("Usage:\n");
        printf("%s: <text>\n", argv[0]);
        return 1;
    }

    if(0 == vulnerable(argv[1])) {
        printf("Processed correctly\n");
    } else {
        printf("Bad input\n");
    }

    return 0;
}
