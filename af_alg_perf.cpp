#include "sys/socket.h"
#include "linux/if_alg.h"
#include "iostream"
#include "string.h"
#include "unistd.h"
#include "fcntl.h"
#include "sys/time.h"
#include "sys/syscall.h"
#include "assert.h"

using namespace std;

uint64_t now_usec()
{
	struct timeval tv;
	gettimeofday(&tv, nullptr);
	return tv.tv_sec*1000000 + tv.tv_usec;
}

#ifndef AF_ALG
#define AF_ALG 38
#endif
#ifndef SOL_ALG
#define SOL_ALG 279
#endif

int main(int argc, char** argv)
{
	int serv;
	int fd;
	for (auto mode : {"ecb(cipher_null)","cbc(aes)"})
	{
		serv = socket(AF_ALG, SOCK_SEQPACKET, 0);
		assert(serv>=0);
		struct sockaddr_alg addr = {0};

		addr.salg_family = AF_ALG;
		memcpy(addr.salg_type, "skcipher", 9);
		//memcpy(addr.salg_name, "ecb(cipher_null)", 17);
		//memcpy(addr.salg_name, "cbc(aes)", 9);
		memcpy(addr.salg_name, mode, strlen(mode)+1);
		int r;
		r = bind(serv, (struct sockaddr *)&addr, sizeof(addr));
		assert(r==0);

		r = setsockopt(serv, SOL_ALG, ALG_SET_KEY, "\1\0\0\0\2\0\0\0\3\0\0\0\4\0\0\0", 16);
		//assert(r==0); this fails for cipher_null, so commented out

		fd = accept(serv, nullptr, 0);
		assert(fd>=0);

		int chunk_size = 1024;
		int progression = 0;

		printf(
				"\n\n   ALG: %20s         "
				" ----total-for-all-executed-jobs----"
				" ------per-single-executed-job-----\n", mode);
		printf(
				"   chunk executed     total      mean"
				"   pipe->   crypto    mem->  syscall"
				"  pipe->   crypto    mem->  syscall\n");
		printf(
				"    size     jobs      data  throuput"
				"   crypto    ->mem     pipe cost(x3)"
				"  crypto    ->mem     pipe cost(x3)\n");
		printf(
				" (bytes)  (count)      (MB)    (MB/s)"
				"   (usec)   (usec)   (usec)   (usec)"
				"  (usec)   (usec)   (usec)   (usec)\n\n");

		do
		{
			char buffer[chunk_size];// = {0};
			memset(buffer, 0, chunk_size);
			int fds[2];
			r = ::pipe(fds);
			assert(r == 0);
			r = ::fcntl(fds[1], F_SETPIPE_SZ, chunk_size*2);
			assert(r >= chunk_size);

			r = setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &chunk_size, sizeof(int));
			assert(r == 0);
			int val;
			socklen_t vallen = sizeof(int);
			r = getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &val, &vallen);
			assert(r == 0);
			assert(val >= chunk_size);

			//fill pipe
			r = write(fds[1], buffer, chunk_size);
			assert(r == chunk_size);

			uint64_t start = now_usec();
			uint64_t end;
			uint64_t tp0=0, tp1=0, tp2=0, tp3=0, tp4=0;
			int no_tests = 0;
			void *mem = aligned_alloc(4096, chunk_size + 4096);
			assert(mem != nullptr);

			do {
				tp0 += now_usec();
				//push to encryption
				r = splice(fds[0], nullptr, fd, nullptr, chunk_size, SPLICE_F_NONBLOCK | SPLICE_F_MOVE);
				assert(r == chunk_size);

				tp1 += now_usec();
				r = read(fd, mem, chunk_size);
				assert(r == chunk_size);

				struct iovec vec;
				vec.iov_base = mem;
				vec.iov_len = chunk_size;
				tp2 += now_usec();
				r = vmsplice(fds[1], &vec, 1, SPLICE_F_GIFT);
				assert(r == chunk_size);

				tp3 += now_usec();

				syscall(SYS_gettid);
				tp4 += now_usec();
				end = now_usec();
				no_tests++;
			}
			while (end - start < 1000000);

			close(fds[0]);
			close(fds[1]);
			free(mem);

			printf("%8d %8d %9.2lf %9.2lf ",
					chunk_size,
					no_tests,
					((double)chunk_size*no_tests)/(1024.*1024.),
					((double)chunk_size * no_tests * 1000000)/(end - start)/(1024.*1024.));
			printf("%8ld %8ld %8ld %8ld",
					tp1 - tp0, tp2 - tp1, tp3 - tp2, (tp4 - tp3)*3);
			printf("%8.3lf %8.3lf %8.3lf %8.3lf\n",
					(double)(tp1 - tp0)/no_tests,
					(double)(tp2 - tp1)/no_tests,
					(double)(tp3 - tp2)/no_tests,
					(double)(tp4 - tp3)*3/no_tests);

			const double next[4] = { 5./4, 6./5, 7./6, 8./7 };
			chunk_size = chunk_size * next[progression];
			progression = (progression + 1) % 4 ;

		} while(chunk_size < 1000000);
	}
}
