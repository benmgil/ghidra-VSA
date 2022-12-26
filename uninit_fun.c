#include <stdlib.h>
#include <string.h>

char array[500];

void fun(int index) {
	array[index] = 100;
}

void main(int argc, char* argv[]) {

	memset(array, 0, 500*sizeof(char));
	int a, b, c;

	if(argc != 2){
		exit(1);
	}
	//a = read();  // pseudo function, retun a int value
	a = atoi(argv[1]);

	if (a > 100) {
		b = a;
	} 
	else {
		c = a;
	}

	if (b < 300)
		fun(b);
	else if (c > 50)
		fun(c);
	else
		fun(200);
}
