#include <stdio.h>
#include <string.h>

int check(char *user) {
	char *passwd = "Th1s_1s_@_fuck1ng_g00d_p@ssw0rd";
	int good = strcmp(passwd,user);
	return good;
}

int main(int argc, char *argv[]) {

	if(argc < 2) {
		printf("usage: ./crackme password\n");
		return 0;
	}

	char *user = argv[1];
	int ret = check(user);

	if(ret==0) {
		printf("well done !!\n");
	} else {
		printf("Get out bastard !\n");
	}

	return 0;

}
