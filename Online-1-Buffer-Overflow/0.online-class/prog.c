#include<stdio.h>
void func(int* a1){
	printf("a1's address is %p\n", (unsigned int) &a1);
}

int main(){
	int x = 3;
	func(&x);
	return 1;
}
