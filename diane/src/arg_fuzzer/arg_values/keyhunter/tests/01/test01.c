#include <stdio.h>
#include <string.h>

const char* keys[] = {"username", "password"};
const char* values[] = {"sherlock", "1337"};

const char* get_key_val(char* key) {
	int num_keys = sizeof(keys);
	int i;

	for(i = 0; i < num_keys; i++)
		if(!strcmp(keys[i], key))
			return values[i];
	return NULL;
}

int main() {
	printf("username: %s\n", get_key_val("username"));
	printf("password: %s\n", get_key_val("password"));
	return 0;
}
