#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

struct {

    char* ip; 
    char nickname[32];

} userCreate;

struct {



} userInfo;

int main(void) {

    struct userCreate *user;

    if(user) {
        for(int i = 0; i < 32; i++) {
        }
    }

    printf("%s", &user->);

}
