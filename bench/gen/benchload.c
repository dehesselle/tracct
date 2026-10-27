/* benchload — load for lib/loadtest.py, all to 127.0.0.1.
 *
 *   benchload tcp <port> <interval_ms> <seconds> <tag>
 *       one TCP connection, 8 bytes every <interval_ms> (a long-lived, mostly idle client)
 *   benchload churn <port> <nports> <per_sec> <seconds> <tag>
 *       32-byte UDP datagrams to <nports> consecutive ports from <port>, <per_sec> in all,
 *       so every port is a connection of its own (connection cardinality)
 *   benchload once <port> <tag>
 *       one 32-byte UDP datagram, then exit (a short-lived process, for exec storms)
 *
 * <tag> marks the command line so the load test finds its rows; pad it to make argv long.
 * Prints one "RESULT sent=<bytes>" line with the application bytes actually sent.
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static double now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static struct sockaddr_in addr(int port) {
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port)};
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    return a;
}

static int tcp(int port, int interval_ms, double seconds) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = addr(port);
    if (connect(fd, (struct sockaddr *)&a, sizeof a) < 0) { perror("connect"); return 1; }
    long long sent = 0;
    double end = now() + seconds;
    while (now() < end) {
        ssize_t n = write(fd, "pingpong", 8);
        if (n <= 0) break;
        sent += n;
        usleep(interval_ms * 1000);
    }
    close(fd);
    printf("RESULT sent=%lld\n", sent);
    return 0;
}

static int churn(int port, int nports, long per_sec, double seconds) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    char buf[32] = {0};
    long long sent = 0;
    long i = 0;
    /* send in 10 ms slices so the rate holds without a syscall-per-datagram sleep */
    long per_slice = per_sec / 100 > 0 ? per_sec / 100 : 1;
    double start = now(), end = start + seconds, next = start;
    while (now() < end) {
        for (long k = 0; k < per_slice; k++, i++) {
            struct sockaddr_in a = addr(port + (int)(i % nports));
            ssize_t n = sendto(fd, buf, sizeof buf, 0, (struct sockaddr *)&a, sizeof a);
            if (n > 0) sent += n;
        }
        next += 0.01;
        double wait = next - now();
        if (wait > 0) usleep((useconds_t)(wait * 1e6));
    }
    close(fd);
    printf("RESULT sent=%lld\n", sent);
    return 0;
}

static int once(int port) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    char buf[32] = {0};
    struct sockaddr_in a = addr(port);
    ssize_t n = sendto(fd, buf, sizeof buf, 0, (struct sockaddr *)&a, sizeof a);
    close(fd);
    printf("RESULT sent=%lld\n", (long long)(n > 0 ? n : 0));
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 6 && !strcmp(argv[1], "tcp")) return tcp(atoi(argv[2]), atoi(argv[3]), atof(argv[4]));
    if (argc == 7 && !strcmp(argv[1], "churn")) return churn(atoi(argv[2]), atoi(argv[3]), atol(argv[4]), atof(argv[5]));
    if (argc == 4 && !strcmp(argv[1], "once")) return once(atoi(argv[2]));
    fprintf(stderr, "usage: benchload tcp <port> <interval_ms> <seconds> <tag>\n"
                    "       benchload churn <port> <nports> <per_sec> <seconds> <tag>\n"
                    "       benchload once <port> <tag>\n");
    return 2;
}
