#include <string.h>
#include <unistd.h>

int main(int argc, char *argv[]) {

	char *args[++argc];
	memset(args, 0, sizeof(argv[0]) * argc);
	memcpy(args, &argv[0], sizeof(argv[0]) * argc);
	return execvp(INIT_PATH, args);
}
