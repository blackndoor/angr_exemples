#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {

	if(argc < 2) {
		printf("usage: ./strcpy word\n");
		return 0;
	}

	/* var*/
	char dest[10]={0};
	char *src =argv[1];

	/* copy src to dest */
	strcpy(dest,src);

	/* print the dest */
	printf("word: %s\n",dest);

	return 0;
}