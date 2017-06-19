/*
system_call_prototypes.h file

Problems:
It seems for jprobes to work properly, I need a receiver function for every system call that
matches the arguments of the sender function. However, I want all of my system calls, for
simplicity's sake, to all be processed by the same function (process_sycall()). To do this, I
was thinking of using an array of functions, but it seems this might be difficult or impossible
for functions with varying arguments.
*/

#include <linux/aio_abi.h>

// Grab syscalls
#ifdef __i386__
#define __SYSCALL_I386(nr, sym, qual) [nr] = 1,
static char syscalls[] = {
#include <asm/syscalls_32.h>
};
#else
#define __SYSCALL_64(nr, sym, qual) [nr] = 1,
static char syscalls[] = {
#include <asm/syscalls_64.h>
};
#endif

int process_syscall(long); // process_syscall prototype

// Global variables
//#define num_syscalls (sizeof(syscalls) / sizeof(syscalls[0]))
//static struct jprobe jprobes_array[num_syscalls];

// System call prototypes
long sys32_quotactl(unsigned int cmd, const char __user *special,
			       qid_t id, void __user *addr);
long sys_time(time_t __user *tloc);
long sys_stime(time_t __user *tptr);
long sys_gettimeofday(struct timeval __user *tv,
				struct timezone __user *tz);
long sys_settimeofday(struct timeval __user *tv,
				struct timezone __user *tz);
long sys_adjtimex(struct timex __user *txc_p);

long sys_times(struct tms __user *tbuf);

long sys_gettid(void);
long sys_nanosleep(struct timespec __user *rqtp, struct timespec __user *rmtp);
long sys_alarm(unsigned int seconds);
long sys_getpid(void);
long sys_getppid(void);
long sys_getuid(void);
long sys_geteuid(void);
long sys_getgid(void);
long sys_getegid(void);
long sys_getresuid(uid_t __user *ruid, uid_t __user *euid, uid_t __user *suid);
long sys_getresgid(gid_t __user *rgid, gid_t __user *egid, gid_t __user *sgid);
long sys_getpgid(pid_t pid);
long sys_getpgrp(void);
long sys_getsid(pid_t pid);
long sys_getgroups(int gidsetsize, gid_t __user *grouplist);

long sys_setregid(gid_t rgid, gid_t egid);
long sys_setgid(gid_t gid);
long sys_setreuid(uid_t ruid, uid_t euid);
long sys_setuid(uid_t uid);
long sys_setresuid(uid_t ruid, uid_t euid, uid_t suid);
long sys_setresgid(gid_t rgid, gid_t egid, gid_t sgid);
long sys_setfsuid(uid_t uid);
long sys_setfsgid(gid_t gid);
long sys_setpgid(pid_t pid, pid_t pgid);
long sys_setsid(void);
long sys_setgroups(int gidsetsize, gid_t __user *grouplist);

long sys_acct(const char __user *name);
long sys_capget(cap_user_header_t header,
				cap_user_data_t dataptr);
long sys_capset(cap_user_header_t header,
				const cap_user_data_t data);
long sys_personality(unsigned int personality);

long sys_sigpending(old_sigset_t __user *set);
long sys_sigprocmask(int how, old_sigset_t __user *set,
				old_sigset_t __user *oset);
long sys_sigaltstack(const struct sigaltstack __user *uss,
				struct sigaltstack __user *uoss);

long sys_getitimer(int which, struct itimerval __user *value);
long sys_setitimer(int which,
				struct itimerval __user *value,
				struct itimerval __user *ovalue);
long sys_timer_create(clockid_t which_clock,
				 struct sigevent __user *timer_event_spec,
				 timer_t __user * created_timer_id);
long sys_timer_gettime(timer_t timer_id,
				struct itimerspec __user *setting);
long sys_timer_getoverrun(timer_t timer_id);
long sys_timer_settime(timer_t timer_id, int flags,
				const struct itimerspec __user *new_setting,
				struct itimerspec __user *old_setting);
long sys_timer_delete(timer_t timer_id);
long sys_clock_settime(clockid_t which_clock,
				const struct timespec __user *tp);
long sys_clock_gettime(clockid_t which_clock,
				struct timespec __user *tp);
long sys_clock_adjtime(clockid_t which_clock,
				struct timex __user *tx);
long sys_clock_getres(clockid_t which_clock,
				struct timespec __user *tp);
long sys_clock_nanosleep(clockid_t which_clock, int flags,
				const struct timespec __user *rqtp,
				struct timespec __user *rmtp);

long sys_nice(int increment);
long sys_sched_setscheduler(pid_t pid, int policy,
					struct sched_param __user *param);
long sys_sched_setparam(pid_t pid,
					struct sched_param __user *param);
long sys_sched_setattr(pid_t pid,
					struct sched_attr __user *attr,
					unsigned int flags);
long sys_sched_getscheduler(pid_t pid);
long sys_sched_getparam(pid_t pid,
					struct sched_param __user *param);
long sys_sched_getattr(pid_t pid,
					struct sched_attr __user *attr,
					unsigned int size,
					unsigned int flags);
long sys_sched_setaffinity(pid_t pid, unsigned int len,
					unsigned long __user *user_mask_ptr);
long sys_sched_getaffinity(pid_t pid, unsigned int len,
					unsigned long __user *user_mask_ptr);
long sys_sched_yield(void);
long sys_sched_get_priority_max(int policy);
long sys_sched_get_priority_min(int policy);
long sys_sched_rr_get_interval(pid_t pid,
					struct timespec __user *interval);
long sys_setpriority(int which, int who, int niceval);
long sys_getpriority(int which, int who);

long sys_shutdown(int sockfd, int how);
long sys_reboot(int magic1, int magic2, unsigned int cmd,
				void __user *arg);
long sys_restart_syscall(void);
long sys_kexec_load(unsigned long entry, unsigned long nr_segments,
				struct kexec_segment __user *segments,
				unsigned long flags);
long sys_kexec_file_load(int kernel_fd, int initrd_fd,
				    unsigned long cmdline_len,
				    const char __user *cmdline_ptr,
				    unsigned long flags);

long sys_exit(int error_code);
long sys_exit_group(int error_code);
long sys_wait4(pid_t pid, int __user *stat_addr,
				int options, struct rusage __user *ru);
long sys_waitid(int which, pid_t pid,
			   struct siginfo __user *infop,
			   int options, struct rusage __user *ru);
long sys_waitpid(pid_t pid, int __user *stat_addr, int options);
long sys_set_tid_address(int __user *tidptr);
long sys_futex(u32 __user *uaddr, int op, u32 val,
			struct timespec __user *utime, u32 __user *uaddr2,
			u32 val3);

long sys_init_module(void __user *umod, unsigned long len,
				const char __user *uargs);
long sys_delete_module(const char __user *name_user,
				unsigned int flags);

#ifdef CONFIG_OLD_SIGSUSPEND
long sys_sigsuspend(old_sigset_t mask);
#endif

#ifdef CONFIG_OLD_SIGSUSPEND3
long sys_sigsuspend(int unused1, int unused2, old_sigset_t mask);
#endif

long sys_rt_sigsuspend(sigset_t __user *unewset, size_t sigsetsize);

#ifdef CONFIG_OLD_SIGACTION
long sys_sigaction(int, const struct old_sigaction __user *,
				struct old_sigaction __user *);
#endif

#ifndef CONFIG_ODD_RT_SIGACTION
long sys_rt_sigaction(int signum,
				 const struct sigaction __user *act,
				 struct sigaction __user *oldact,
				 size_t size);
#endif
long sys_rt_sigprocmask(int how, sigset_t __user *set,
				sigset_t __user *oset, size_t sigsetsize);
long sys_rt_sigpending(sigset_t __user *set, size_t sigsetsize);
long sys_rt_sigtimedwait(const sigset_t __user *uthese,
				siginfo_t __user *uinfo,
				const struct timespec __user *uts,
				size_t sigsetsize);
long sys_rt_tgsigqueueinfo(pid_t tgid, pid_t  pid, int sig,
		siginfo_t __user *uinfo);
long sys_kill(pid_t pid, int sig);
long sys_tgkill(pid_t tgid, pid_t pid, int sig);
long sys_tkill(pid_t pid, int sig);
long sys_rt_sigqueueinfo(pid_t pid, int sig, siginfo_t __user *uinfo);
long sys_sgetmask(void);
long sys_ssetmask(int newmask);
long sys_signal(int sig, __sighandler_t handler);
long sys_pause(void);

long sys_sync(void);
long sys_fsync(unsigned int fd);
long sys_fdatasync(unsigned int fd);
long sys_bdflush(int func, long data);
long sys_mount(char __user *dev_name, char __user *dir_name,
				char __user *type, unsigned long flags,
				void __user *data);
long sys_umount(char __user *name, int flags);
long sys_oldumount(char __user *name);
long sys_truncate(const char __user *path, long length);
long sys_ftruncate(unsigned int fd, unsigned long length);
long sys_stat(const char __user *filename,
			struct __old_kernel_stat __user *statbuf);
long sys_statfs(const char __user * path,
				struct statfs __user *buf);
long sys_statfs64(const char __user *path, size_t sz,
				struct statfs64 __user *buf);
long sys_fstatfs(unsigned int fd, struct statfs __user *buf);
long sys_fstatfs64(unsigned int fd, size_t sz,
				struct statfs64 __user *buf);
long sys_lstat(const char __user *filename,
			struct __old_kernel_stat __user *statbuf);
long sys_fstat(unsigned int fd,
			struct __old_kernel_stat __user *statbuf);
long sys_newstat(const char __user *filename,
				struct stat __user *statbuf);
long sys_newlstat(const char __user *filename,
				struct stat __user *statbuf);
long sys_newfstat(unsigned int fd, struct stat __user *statbuf);
long sys_ustat(unsigned dev, struct ustat __user *ubuf);
#if defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64)
long sys_stat64(const char __user *filename,
				struct stat64 __user *statbuf);
long sys_fstat64(unsigned long fd, struct stat64 __user *statbuf);
long sys_lstat64(const char __user *filename,
				struct stat64 __user *statbuf);
long sys_fstatat64(int dfd, const char __user *filename,
			       struct stat64 __user *statbuf, int flag);
#endif
#if BITS_PER_LONG == 32
long sys_truncate64(const char __user *path, loff_t length);
long sys_ftruncate64(unsigned int fd, loff_t length);
#endif

long sys_setxattr(const char __user *path, const char __user *name,
			     const void __user *value, size_t size, int flags);
long sys_lsetxattr(const char __user *path, const char __user *name,
			      const void __user *value, size_t size, int flags);
long sys_fsetxattr(int fd, const char __user *name,
			      const void __user *value, size_t size, int flags);
long sys_getxattr(const char __user *path, const char __user *name,
			     void __user *value, size_t size);
long sys_lgetxattr(const char __user *path, const char __user *name,
			      void __user *value, size_t size);
long sys_fgetxattr(int fd, const char __user *name,
			      void __user *value, size_t size);
long sys_listxattr(const char __user *path, char __user *list,
			      size_t size);
long sys_llistxattr(const char __user *path, char __user *list,
			       size_t size);
long sys_flistxattr(int fd, char __user *list, size_t size);
long sys_removexattr(const char __user *path,
				const char __user *name);
long sys_lremovexattr(const char __user *path,
				 const char __user *name);
long sys_fremovexattr(int fd, const char __user *name);

long sys_brk(unsigned long brk);
long sys_mprotect(unsigned long start, size_t len,
				unsigned long prot);
long sys_mremap(unsigned long addr,
			   unsigned long old_len, unsigned long new_len,
			   unsigned long flags, unsigned long new_addr);
long sys_remap_file_pages(unsigned long start, unsigned long size,
			unsigned long prot, unsigned long pgoff,
			unsigned long flags);
long sys_msync(unsigned long start, size_t len, int flags);
long sys_fadvise64(int fd, loff_t offset, size_t len, int advice);
long sys_fadvise64_64(int fd, loff_t offset, loff_t len, int advice);
long sys_munmap(unsigned long addr, size_t len);
long sys_mlock(unsigned long start, size_t len);
long sys_munlock(unsigned long start, size_t len);
long sys_mlockall(int flags);
long sys_munlockall(void);
long sys_madvise(unsigned long start, size_t len, int behavior);
long sys_mincore(unsigned long start, size_t len,
				unsigned char __user * vec);

long sys_pivot_root(const char __user *new_root,
				const char __user *put_old);
long sys_chroot(const char __user *filename);
long sys_mknod(const char __user *filename, umode_t mode,
				unsigned dev);
long sys_link(const char __user *oldname,
				const char __user *newname);
long sys_symlink(const char __user *old, const char __user *new);
long sys_unlink(const char __user *pathname);
long sys_rename(const char __user *oldname,
				const char __user *newname);
long sys_chmod(const char __user *filename, umode_t mode);
long sys_fchmod(unsigned int fd, umode_t mode);

long sys_fcntl(unsigned int fd, unsigned int cmd, unsigned long arg);
#if BITS_PER_LONG == 32
long sys_fcntl64(unsigned int fd,
				unsigned int cmd, unsigned long arg);
#endif
long sys_pipe(int __user *fildes);
long sys_pipe2(int __user *fildes, int flags);
long sys_dup(unsigned int fildes);
long sys_dup2(unsigned int oldfd, unsigned int newfd);
long sys_dup3(unsigned int oldfd, unsigned int newfd, int flags);
long sys_ioperm(unsigned long from, unsigned long num, int on);
long sys_ioctl(unsigned int fd, unsigned int cmd,
				unsigned long arg);
long sys_flock(unsigned int fd, unsigned int cmd);
long sys_io_setup(unsigned nr_reqs, aio_context_t __user *ctx);
long sys_io_destroy(aio_context_t ctx);
long sys_io_getevents(aio_context_t ctx_id,
				long min_nr,
				long nr,
				struct io_event __user *events,
				struct timespec __user *timeout);
long sys_io_submit(aio_context_t ctx_id, long nr,
				struct iocb __user * __user *iocbpp);
long sys_io_cancel(aio_context_t ctx_id, struct iocb __user *iocb,
			      struct io_event __user *result);
long sys_sendfile(int out_fd, int in_fd,
			     off_t __user *offset, size_t count);
long sys_sendfile64(int out_fd, int in_fd,
			       loff_t __user *offset, size_t count);
long sys_readlink(const char __user *path,
				char __user *buf, int bufsiz);
long sys_creat(const char __user *pathname, umode_t mode);
long sys_open(const char __user *filename,
				int flags, umode_t mode);
long sys_close(unsigned int fd);
long sys_access(const char __user *filename, int mode);
long sys_vhangup(void);
long sys_chown(const char __user *filename,
				uid_t user, gid_t group);
long sys_lchown(const char __user *filename,
				uid_t user, gid_t group);
long sys_fchown(unsigned int fd, uid_t user, gid_t group);
#ifdef CONFIG_HAVE_UID16
long sys_chown16(const char __user *filename,
				old_uid_t user, old_gid_t group);
long sys_lchown16(const char __user *filename,
				old_uid_t user, old_gid_t group);
long sys_fchown16(unsigned int fd, old_uid_t user, old_gid_t group);
long sys_setregid16(old_gid_t rgid, old_gid_t egid);
long sys_setgid16(old_gid_t gid);
long sys_setreuid16(old_uid_t ruid, old_uid_t euid);
long sys_setuid16(old_uid_t uid);
long sys_setresuid16(old_uid_t ruid, old_uid_t euid, old_uid_t suid);
long sys_getresuid16(old_uid_t __user *ruid,
				old_uid_t __user *euid, old_uid_t __user *suid);
long sys_setresgid16(old_gid_t rgid, old_gid_t egid, old_gid_t sgid);
long sys_getresgid16(old_gid_t __user *rgid,
				old_gid_t __user *egid, old_gid_t __user *sgid);
long sys_setfsuid16(old_uid_t uid);
long sys_setfsgid16(old_gid_t gid);
long sys_getgroups16(int gidsetsize, old_gid_t __user *grouplist);
long sys_setgroups16(int gidsetsize, old_gid_t __user *grouplist);
long sys_getuid16(void);
long sys_geteuid16(void);
long sys_getgid16(void);
long sys_getegid16(void);
#endif

long sys_utime(char __user *filename,
				struct utimbuf __user *times);
long sys_utimes(char __user *filename,
				struct timeval __user *utimes);
long sys_lseek(unsigned int fd, off_t offset,
			  unsigned int whence);
long sys_llseek(unsigned int fd, unsigned long offset_high,
			unsigned long offset_low, loff_t __user *result,
			unsigned int whence);
long sys_read(unsigned int fd, char __user *buf, size_t count);
long sys_readahead(int fd, loff_t offset, size_t count);
long sys_readv(unsigned long fd,
			  const struct iovec __user *vec,
			  unsigned long vlen);
long sys_write(unsigned int fd, const char __user *buf,
			  size_t count);
long sys_writev(unsigned long fd,
			   const struct iovec __user *vec,
			   unsigned long vlen);
long sys_pread64(unsigned int fd, char __user *buf,
			    size_t count, loff_t pos);
long sys_pwrite64(unsigned int fd, const char __user *buf,
			     size_t count, loff_t pos);
long sys_preadv(unsigned long fd, const struct iovec __user *vec,
			   unsigned long vlen, unsigned long pos_l, unsigned long pos_h);
long sys_preadv2(unsigned long fd, const struct iovec __user *vec,
			    unsigned long vlen, unsigned long pos_l, unsigned long pos_h,
			    int flags);
long sys_pwritev(unsigned long fd, const struct iovec __user *vec,
			    unsigned long vlen, unsigned long pos_l, unsigned long pos_h);
long sys_pwritev2(unsigned long fd, const struct iovec __user *vec,
			    unsigned long vlen, unsigned long pos_l, unsigned long pos_h,
			    int flags);
long sys_getcwd(char __user *buf, unsigned long size);
long sys_mkdir(const char __user *pathname, umode_t mode);
long sys_chdir(const char __user *filename);
long sys_fchdir(unsigned int fd);
long sys_rmdir(const char __user *pathname);
long sys_lookup_dcookie(u64 cookie64, char __user *buf, size_t len);
long sys_quotactl(unsigned int cmd, const char __user *special,
				qid_t id, void __user *addr);
long sys_getdents(unsigned int fd,
				struct linux_dirent __user *dirent,
				unsigned int count);
long sys_getdents64(unsigned int fd,
				struct linux_dirent64 __user *dirent,
				unsigned int count);

long sys_setsockopt(int fd, int level, int optname,
				char __user *optval, int optlen);
long sys_getsockopt(int fd, int level, int optname,
				char __user *optval, int __user *optlen);
long sys_bind(int sockfd, struct sockaddr __user *my_addr, int addrlen);
long sys_connect(int sockfd, struct sockaddr __user *addr, int addrlen);
long sys_accept(int sockfd, struct sockaddr __user *addr, int __user *addrlen);
long sys_accept4(int sockfd, struct sockaddr __user *addr, int __user *addrlen, int flags);
long sys_getsockname(int sockfd, struct sockaddr __user *addr, int __user *addrlen);
long sys_getpeername(int sockfd, struct sockaddr __user *addr, int __user *addrlen);
long sys_send(int sockfd, void __user *buf, size_t len, unsigned flags);
long sys_sendto(int sockfd, void __user *buf, size_t len, unsigned flags,
				struct sockaddr __user *dest_addr, int addrlen);
long sys_sendmsg(int fd, struct user_msghdr __user *msg, unsigned flags);
long sys_sendmmsg(int fd, struct mmsghdr __user *msg,
			     unsigned int vlen, unsigned flags);
long sys_recv(int sockfd, void __user *buf, size_t len, unsigned flags);
long sys_recvfrom(int sockfd, void __user *buf, size_t len, unsigned flags,
				struct sockaddr __user *src_addr, int __user *addrlen);
long sys_recvmsg(int fd, struct user_msghdr __user *msg, unsigned flags);
long sys_recvmmsg(int fd, struct mmsghdr __user *msg,
			     unsigned int vlen, unsigned flags,
			     struct timespec __user *timeout);
long sys_socket(int domain, int type, int protocol);
long sys_socketpair(int domain, int type, int protocol, int __user *sv);
long sys_socketcall(int call, unsigned long __user *args);
long sys_listen(int sockfd, int backlog);
long sys_poll(struct pollfd __user *ufds, unsigned int nfds,
				int timeout);
long sys_select(int n, fd_set __user *inp, fd_set __user *outp,
			fd_set __user *exp, struct timeval __user *tvp);
long sys_old_select(struct sel_arg_struct __user *arg);
long sys_epoll_create(int size);
long sys_epoll_create1(int flags);
long sys_epoll_ctl(int epfd, int op, int fd,
				struct epoll_event __user *event);
long sys_epoll_wait(int epfd, struct epoll_event __user *events,
				int maxevents, int timeout);
long sys_epoll_pwait(int epfd, struct epoll_event __user *events,
				int maxevents, int timeout,
				const sigset_t __user *sigmask,
				size_t sigsetsize);
long sys_gethostname(char __user *name, int len);
long sys_sethostname(char __user *name, int len);
long sys_setdomainname(char __user *name, int len);
long sys_newuname(struct new_utsname __user *name);
long sys_uname(struct old_utsname __user *buf);
long sys_olduname(struct oldold_utsname __user *);

long sys_getrlimit(unsigned int resource,
				struct rlimit __user *rlim);
#if defined(COMPAT_RLIM_OLD_INFINITY) || !(defined(CONFIG_IA64))
long sys_old_getrlimit(unsigned int resource, struct rlimit __user *rlim);
#endif
long sys_setrlimit(unsigned int resource,
				struct rlimit __user *rlim);
long sys_prlimit64(pid_t pid, unsigned int resource,
				const struct rlimit64 __user *new_rlim,
				struct rlimit64 __user *old_rlim);
long sys_getrusage(int who, struct rusage __user *ru);
long sys_umask(int mask);

long sys_msgget(key_t key, int msgflg);
long sys_msgsnd(int msqid, struct msgbuf __user *msgp,
				size_t msgsz, int msgflg);
long sys_msgrcv(int msqid, struct msgbuf __user *msgp,
				size_t msgsz, long msgtyp, int msgflg);
long sys_msgctl(int msqid, int cmd, struct msqid_ds __user *buf);

long sys_semget(key_t key, int nsems, int semflg);
long sys_semop(int semid, struct sembuf __user *sops,
				unsigned nsops);
long sys_semctl(int semid, int semnum, int cmd, unsigned long arg);
long sys_semtimedop(int semid, struct sembuf __user *sops,
				unsigned nsops,
				const struct timespec __user *timeout);
long sys_shmat(int shmid, char __user *shmaddr, int shmflg);
long sys_shmget(key_t key, size_t size, int flag);
long sys_shmdt(char __user *shmaddr);
long sys_shmctl(int shmid, int cmd, struct shmid_ds __user *buf);
long sys_ipc(unsigned int call, int first, unsigned long second,
		unsigned long third, void __user *ptr, long fifth);

long sys_mq_open(const char __user *name, int oflag, umode_t mode, struct mq_attr __user *attr);
long sys_mq_unlink(const char __user *name);
long sys_mq_timedsend(mqd_t mqdes, const char __user *msg_ptr, size_t msg_len, unsigned int msg_prio, const struct timespec __user *abs_timeout);
long sys_mq_timedreceive(mqd_t mqdes, char __user *msg_ptr, size_t msg_len, unsigned int __user *msg_prio, const struct timespec __user *abs_timeout);
long sys_mq_notify(mqd_t mqdes, const struct sigevent __user *notification);
long sys_mq_getsetattr(mqd_t mqdes, const struct mq_attr __user *mqstat, struct mq_attr __user *omqstat);

long sys_pciconfig_iobase(long which, unsigned long bus, unsigned long devfn);
long sys_pciconfig_read(unsigned long bus, unsigned long dfn,
				unsigned long off, unsigned long len,
				void __user *buf);
long sys_pciconfig_write(unsigned long bus, unsigned long dfn,
				unsigned long off, unsigned long len,
				void __user *buf);

long sys_prctl(int option, unsigned long arg2, unsigned long arg3,
			unsigned long arg4, unsigned long arg5);
long sys_swapon(const char __user *specialfile, int swap_flags);
long sys_swapoff(const char __user *specialfile);
long sys_sysctl(struct __sysctl_args __user *args);
long sys_sysinfo(struct sysinfo __user *info);
long sys_sysfs(int option,
				unsigned long arg1, unsigned long arg2);
long sys_syslog(int type, char __user *buf, int len);
long sys_uselib(const char __user *library);
long sys_ni_syscall(void);
long sys_ptrace(long request, long pid, unsigned long addr,
			   unsigned long data);

long sys_add_key(const char __user *_type,
			    const char __user *_description,
			    const void __user *_payload,
			    size_t plen,
			    key_serial_t destringid);

long sys_request_key(const char __user *_type,
				const char __user *_description,
				const char __user *_callout_info,
				key_serial_t destringid);

long sys_keyctl(int cmd, unsigned long arg2, unsigned long arg3,
			   unsigned long arg4, unsigned long arg5);

long sys_ioprio_set(int which, int who, int ioprio);
long sys_ioprio_get(int which, int who);
long sys_set_mempolicy(int mode, const unsigned long __user *nmask,
				unsigned long maxnode);
long sys_migrate_pages(pid_t pid, unsigned long maxnode,
				const unsigned long __user *from,
				const unsigned long __user *to);
long sys_move_pages(pid_t pid, unsigned long nr_pages,
				const void __user * __user *pages,
				const int __user *nodes,
				int __user *status,
				int flags);
long sys_mbind(unsigned long start, unsigned long len,
				unsigned long mode,
				const unsigned long __user *nmask,
				unsigned long maxnode,
				unsigned flags);
long sys_get_mempolicy(int __user *policy,
				unsigned long __user *nmask,
				unsigned long maxnode,
				unsigned long addr, unsigned long flags);

long sys_inotify_init(void);
long sys_inotify_init1(int flags);
long sys_inotify_add_watch(int fd, const char __user *path,
					u32 mask);
long sys_inotify_rm_watch(int fd, __s32 wd);

long sys_spu_run(int fd, __u32 __user *unpc,
				 __u32 __user *ustatus);
long sys_spu_create(const char __user *name,
		unsigned int flags, umode_t mode, int fd);

long sys_mknodat(int dfd, const char __user * filename, umode_t mode,
			    unsigned dev);
long sys_mkdirat(int dfd, const char __user * pathname, umode_t mode);
long sys_unlinkat(int dfd, const char __user * pathname, int flag);
long sys_symlinkat(const char __user * oldname,
			      int newdfd, const char __user * newname);
long sys_linkat(int olddfd, const char __user *oldname,
			   int newdfd, const char __user *newname, int flags);
long sys_renameat(int olddfd, const char __user * oldname,
			     int newdfd, const char __user * newname);
long sys_renameat2(int olddfd, const char __user *oldname,
			      int newdfd, const char __user *newname,
			      unsigned int flags);
long sys_futimesat(int dfd, const char __user *filename,
			      struct timeval __user *utimes);
long sys_faccessat(int dfd, const char __user *filename, int mode);
long sys_fchmodat(int dfd, const char __user * filename,
			     umode_t mode);
long sys_fchownat(int dfd, const char __user *filename, uid_t user,
			     gid_t group, int flag);
long sys_openat(int dfd, const char __user *filename, int flags,
			   umode_t mode);
long sys_newfstatat(int dfd, const char __user *filename,
			       struct stat __user *statbuf, int flag);
long sys_readlinkat(int dfd, const char __user *path, char __user *buf,
			       int bufsiz);
long sys_utimensat(int dfd, const char __user *filename,
				struct timespec __user *utimes, int flags);
long sys_unshare(unsigned long unshare_flags);

long sys_splice(int fd_in, loff_t __user *off_in,
			   int fd_out, loff_t __user *off_out,
			   size_t len, unsigned int flags);

long sys_vmsplice(int fd, const struct iovec __user *iov,
			     unsigned long nr_segs, unsigned int flags);

long sys_tee(int fdin, int fdout, size_t len, unsigned int flags);

long sys_sync_file_range(int fd, loff_t offset, loff_t nbytes,
					unsigned int flags);
long sys_sync_file_range2(int fd, unsigned int flags,
				     loff_t offset, loff_t nbytes);
long sys_get_robust_list(int pid,
				    struct robust_list_head __user * __user *head_ptr,
				    size_t __user *len_ptr);
long sys_set_robust_list(struct robust_list_head __user *head,
				    size_t len);
long sys_getcpu(unsigned __user *cpu, unsigned __user *node, struct getcpu_cache __user *cache);
long sys_signalfd(int ufd, sigset_t __user *user_mask, size_t sizemask);
long sys_signalfd4(int ufd, sigset_t __user *user_mask, size_t sizemask, int flags);
long sys_timerfd_create(int clockid, int flags);
long sys_timerfd_settime(int ufd, int flags,
				    const struct itimerspec __user *utmr,
				    struct itimerspec __user *otmr);
long sys_timerfd_gettime(int ufd, struct itimerspec __user *otmr);
long sys_eventfd(unsigned int count);
long sys_eventfd2(unsigned int count, int flags);
long sys_memfd_create(const char __user *uname_ptr, unsigned int flags);
long sys_userfaultfd(int flags);
long sys_fallocate(int fd, int mode, loff_t offset, loff_t len);
long sys_old_readdir(unsigned int ui2, struct old_linux_dirent __user *old_linux_dirent, unsigned int ui2);
long sys_pselect6(int i, fd_set __user *fd_set1, fd_set __user *fd_set2,
			     fd_set __user *fd_set3, struct timespec __user *timespec,
			     void __user *v);
long sys_ppoll(struct pollfd __user *pollfd, unsigned int ui,
			  struct timespec __user *timespec, const sigset_t __user *sigset,
			  size_t size);
long sys_fanotify_init(unsigned int flags, unsigned int event_f_flags);
long sys_fanotify_mark(int fanotify_fd, unsigned int flags,
				  u64 mask, int fd,
				  const char  __user *pathname);
long sys_syncfs(int fd);

long sys_fork(void);
long sys_vfork(void);
#ifdef CONFIG_CLONE_BACKWARDS
long sys_clone(unsigned long, unsigned long, int __user *, unsigned long,
	       int __user *);
#else
#ifdef CONFIG_CLONE_BACKWARDS3
long sys_clone(unsigned long, unsigned long, int, int __user *,
			  int __user *, unsigned long);
#else
long sys_clone(unsigned long, unsigned long, int __user *,
	       int __user *, unsigned long);
#endif
#endif

long sys_execve(const char __user *filename,
		const char __user *const __user *argv,
		const char __user *const __user *envp);

long sys_perf_event_open(
		struct perf_event_attr __user *attr_uptr,
		pid_t pid, int cpu, int group_fd, unsigned long flags);

long sys_mmap_pgoff(unsigned long addr, unsigned long len,
			unsigned long prot, unsigned long flags,
			unsigned long fd, unsigned long pgoff);
long sys_old_mmap(struct mmap_arg_struct __user *arg);
long sys_name_to_handle_at(int dfd, const char __user *name,
				      struct file_handle __user *handle,
				      int __user *mnt_id, int flag);
long sys_open_by_handle_at(int mountdirfd,
				      struct file_handle __user *handle,
				      int flags);
long sys_setns(int fd, int nstype);
long sys_process_vm_readv(pid_t pid,
				     const struct iovec __user *lvec,
				     unsigned long liovcnt,
				     const struct iovec __user *rvec,
				     unsigned long riovcnt,
				     unsigned long flags);
long sys_process_vm_writev(pid_t pid,
				      const struct iovec __user *lvec,
				      unsigned long liovcnt,
				      const struct iovec __user *rvec,
				      unsigned long riovcnt,
				      unsigned long flags);

long sys_kcmp(pid_t pid1, pid_t pid2, int type,
			 unsigned long idx1, unsigned long idx2);
long sys_finit_module(int fd, const char __user *uargs, int flags);
long sys_seccomp(unsigned int op, unsigned int flags,
			    const char __user *uargs);
long sys_getrandom(char __user *buf, size_t count,
			      unsigned int flags);
long sys_bpf(int cmd, union bpf_attr *attr, unsigned int size);

long sys_execveat(int dfd, const char __user *filename,
			const char __user *const __user *argv,
			const char __user *const __user *envp, int flags);

long sys_membarrier(int cmd, int flags);
long sys_copy_file_range(int fd_in, loff_t __user *off_in,
				    int fd_out, loff_t __user *off_out,
				    size_t len, unsigned int flags);

long sys_mlock2(unsigned long start, size_t len, int flags);

long sys_pkey_mprotect(unsigned long start, size_t len,
				  unsigned long prot, int pkey);
long sys_pkey_alloc(unsigned long flags, unsigned long init_val);
long sys_pkey_free(int pkey);
long sys_statx(int dfd, const char __user *path, unsigned flags,
			  unsigned mask, struct statx __user *buffer);

// JProbe functions - for now, just comment these out

struct jprobe jprobes_array[] = {
	static long jsys32_quotactl(unsigned int cmd, const char __user *special,
					   qid_t id, void __user *addr) { process_syscall(); },
	static long jsys_time(time_t __user *tloc) { process_syscall(); },
	static long jsys_stime(time_t __user *tptr) { process_syscall(); },
	static long jsys_gettimeofday(struct timeval __user *tv,
					struct timezone __user *tz) { process_syscall(); },
	static long jsys_settimeofday(struct timeval __user *tv,
					struct timezone __user *tz) { process_syscall(); },
	static long jsys_adjtimex(struct timex __user *txc_p) { process_syscall(); },

	static long jsys_times(struct tms __user *tbuf) { process_syscall(); },

	static long jsys_gettid(void) { process_syscall(); },
	static long jsys_nanosleep(struct timespec __user *rqtp, struct timespec __user *rmtp) { process_syscall(); },
	static long jsys_alarm(unsigned int seconds) { process_syscall(); },
	static long jsys_getpid(void) { process_syscall(); },
	static long jsys_getppid(void) { process_syscall(); },
	static long jsys_getuid(void) { process_syscall(); },
	static long jsys_geteuid(void) { process_syscall(); },
	static long jsys_getgid(void) { process_syscall(); },
	static long jsys_getegid(void) { process_syscall(); },
	static long jsys_getresuid(uid_t __user *ruid, uid_t __user *euid, uid_t __user *suid) { process_syscall(); },
	static long jsys_getresgid(gid_t __user *rgid, gid_t __user *egid, gid_t __user *sgid) { process_syscall(); },
	static long jsys_getpgid(pid_t pid) { process_syscall(); },
	static long jsys_getpgrp(void) { process_syscall(); },
	static long jsys_getsid(pid_t pid) { process_syscall(); },
	static long jsys_getgroups(int gidsetsize, gid_t __user *grouplist) { process_syscall(); },

	static long jsys_setregid(gid_t rgid, gid_t egid) { process_syscall(); },
	static long jsys_setgid(gid_t gid) { process_syscall(); },
	static long jsys_setreuid(uid_t ruid, uid_t euid) { process_syscall(); },
	static long jsys_setuid(uid_t uid) { process_syscall(); },
	static long jsys_setresuid(uid_t ruid, uid_t euid, uid_t suid) { process_syscall(); },
	static long jsys_setresgid(gid_t rgid, gid_t egid, gid_t sgid) { process_syscall(); },
	static long jsys_setfsuid(uid_t uid) { process_syscall(); },
	static long jsys_setfsgid(gid_t gid) { process_syscall(); },
	static long jsys_setpgid(pid_t pid, pid_t pgid) { process_syscall(); },
	static long jsys_setsid(void) { process_syscall(); },
	static long jsys_setgroups(int gidsetsize, gid_t __user *grouplist) { process_syscall(); },

	static long jsys_acct(const char __user *name) { process_syscall(); },
	static long jsys_capget(cap_user_header_t header,
					cap_user_data_t dataptr) { process_syscall(); },
	static long jsys_capset(cap_user_header_t header,
					const cap_user_data_t data) { process_syscall(); },
	static long jsys_personality(unsigned int personality) { process_syscall(); },

	static long jsys_sigpending(old_sigset_t __user *set) { process_syscall(); },
	static long jsys_sigprocmask(int how, old_sigset_t __user *set,
					old_sigset_t __user *oset) { process_syscall(); },
	static long jsys_sigaltstack(const struct sigaltstack __user *uss,
					struct sigaltstack __user *uoss) { process_syscall(); },

	static long jsys_getitimer(int which, struct itimerval __user *value) { process_syscall(); },
	static long jsys_setitimer(int which,
					struct itimerval __user *value,
					struct itimerval __user *ovalue) { process_syscall(); },
	static long jsys_timer_create(clockid_t which_clock,
					 struct sigevent __user *timer_event_spec,
					 timer_t __user * created_timer_id) { process_syscall(); },
	static long jsys_timer_gettime(timer_t timer_id,
					struct itimerspec __user *setting) { process_syscall(); },
	static long jsys_timer_getoverrun(timer_t timer_id) { process_syscall(); },
	static long jsys_timer_settime(timer_t timer_id, int flags,
					const struct itimerspec __user *new_setting,
					struct itimerspec __user *old_setting) { process_syscall(); },
	static long jsys_timer_delete(timer_t timer_id) { process_syscall(); },
	static long jsys_clock_settime(clockid_t which_clock,
					const struct timespec __user *tp) { process_syscall(); },
	static long jsys_clock_gettime(clockid_t which_clock,
					struct timespec __user *tp) { process_syscall(); },
	static long jsys_clock_adjtime(clockid_t which_clock,
					struct timex __user *tx) { process_syscall(); },
	static long jsys_clock_getres(clockid_t which_clock,
					struct timespec __user *tp) { process_syscall(); },
	static long jsys_clock_nanosleep(clockid_t which_clock, int flags,
					const struct timespec __user *rqtp,
					struct timespec __user *rmtp) { process_syscall(); },

	static long jsys_nice(int increment) { process_syscall(); },
	static long jsys_sched_setscheduler(pid_t pid, int policy,
						struct sched_param __user *param) { process_syscall(); },
	static long jsys_sched_setparam(pid_t pid,
						struct sched_param __user *param) { process_syscall(); },
	static long jsys_sched_setattr(pid_t pid,
						struct sched_attr __user *attr,
						unsigned int flags) { process_syscall(); },
	static long jsys_sched_getscheduler(pid_t pid) { process_syscall(); },
	static long jsys_sched_getparam(pid_t pid,
						struct sched_param __user *param) { process_syscall(); },
	static long jsys_sched_getattr(pid_t pid,
						struct sched_attr __user *attr,
						unsigned int size,
						unsigned int flags) { process_syscall(); },
	static long jsys_sched_setaffinity(pid_t pid, unsigned int len,
						unsigned long __user *user_mask_ptr) { process_syscall(); },
	static long jsys_sched_getaffinity(pid_t pid, unsigned int len,
						unsigned long __user *user_mask_ptr) { process_syscall(); },
	static long jsys_sched_yield(void) { process_syscall(); },
	static long jsys_sched_get_priority_max(int policy) { process_syscall(); },
	static long jsys_sched_get_priority_min(int policy) { process_syscall(); },
	static long jsys_sched_rr_get_interval(pid_t pid,
						struct timespec __user *interval) { process_syscall(); },
	static long jsys_setpriority(int which, int who, int niceval) { process_syscall(); },
	static long jsys_getpriority(int which, int who) { process_syscall(); },

	static long jsys_shutdown(int, int) { process_syscall(); },
	static long jsys_reboot(int magic1, int magic2, unsigned int cmd,
					void __user *arg) { process_syscall(); },
	static long jsys_restart_syscall(void) { process_syscall(); },
	static long jsys_kexec_load(unsigned long entry, unsigned long nr_segments,
					struct kexec_segment __user *segments,
					unsigned long flags) { process_syscall(); },
	static long jsys_kexec_file_load(int kernel_fd, int initrd_fd,
						unsigned long cmdline_len,
						const char __user *cmdline_ptr,
						unsigned long flags) { process_syscall(); },

	static long jsys_exit(int error_code) { process_syscall(); },
	static long jsys_exit_group(int error_code) { process_syscall(); },
	static long jsys_wait4(pid_t pid, int __user *stat_addr,
					int options, struct rusage __user *ru) { process_syscall(); },
	static long jsys_waitid(int which, pid_t pid,
				   struct siginfo __user *infop,
				   int options, struct rusage __user *ru) { process_syscall(); },
	static long jsys_waitpid(pid_t pid, int __user *stat_addr, int options) { process_syscall(); },
	static long jsys_set_tid_address(int __user *tidptr) { process_syscall(); },
	static long jsys_futex(u32 __user *uaddr, int op, u32 val,
				struct timespec __user *utime, u32 __user *uaddr2,
				u32 val3) { process_syscall(); },

	static long jsys_init_module(void __user *umod, unsigned long len,
					const char __user *uargs) { process_syscall(); },
	static long jsys_delete_module(const char __user *name_user,
					unsigned int flags) { process_syscall(); },

	static long jsys_rt_sigprocmask(int how, sigset_t __user *set,
					sigset_t __user *oset, size_t sigsetsize) { process_syscall(); },
	static long jsys_rt_sigpending(sigset_t __user *set, size_t sigsetsize) { process_syscall(); },
	static long jsys_rt_sigtimedwait(const sigset_t __user *uthese,
					siginfo_t __user *uinfo,
					const struct timespec __user *uts,
					size_t sigsetsize) { process_syscall(); },
	static long jsys_rt_tgsigqueueinfo(pid_t tgid, pid_t  pid, int sig,
			siginfo_t __user *uinfo) { process_syscall(); },
	static long jsys_kill(pid_t pid, int sig) { process_syscall(); },
	static long jsys_tgkill(pid_t tgid, pid_t pid, int sig) { process_syscall(); },
	static long jsys_tkill(pid_t pid, int sig) { process_syscall(); },
	static long jsys_rt_sigqueueinfo(pid_t pid, int sig, siginfo_t __user *uinfo) { process_syscall(); },
	static long jsys_sgetmask(void) { process_syscall(); },
	static long jsys_ssetmask(int newmask) { process_syscall(); },
	static long jsys_signal(int sig, __sighandler_t handler) { process_syscall(); },
	static long jsys_pause(void) { process_syscall(); },

	static long jsys_sync(void) { process_syscall(); },
	static long jsys_fsync(unsigned int fd) { process_syscall(); },
	static long jsys_fdatasync(unsigned int fd) { process_syscall(); },
	static long jsys_bdflush(int func, long data) { process_syscall(); },
	static long jsys_mount(char __user *dev_name, char __user *dir_name,
					char __user *type, unsigned long flags,
					void __user *data) { process_syscall(); },
	static long jsys_umount(char __user *name, int flags) { process_syscall(); },
	static long jsys_oldumount(char __user *name) { process_syscall(); },
	static long jsys_truncate(const char __user *path, long length) { process_syscall(); },
	static long jsys_ftruncate(unsigned int fd, unsigned long length) { process_syscall(); },
	static long jsys_stat(const char __user *filename,
				struct __old_kernel_stat __user *statbuf) { process_syscall(); },
	static long jsys_statfs(const char __user * path,
					struct statfs __user *buf) { process_syscall(); },
	static long jsys_statfs64(const char __user *path, size_t sz,
					struct statfs64 __user *buf) { process_syscall(); },
	static long jsys_fstatfs(unsigned int fd, struct statfs __user *buf) { process_syscall(); },
	static long jsys_fstatfs64(unsigned int fd, size_t sz,
					struct statfs64 __user *buf) { process_syscall(); },
	static long jsys_lstat(const char __user *filename,
				struct __old_kernel_stat __user *statbuf) { process_syscall(); },
	static long jsys_fstat(unsigned int fd,
				struct __old_kernel_stat __user *statbuf) { process_syscall(); },
	static long jsys_newstat(const char __user *filename,
					struct stat __user *statbuf) { process_syscall(); },
	static long jsys_newlstat(const char __user *filename,
					struct stat __user *statbuf) { process_syscall(); },
	static long jsys_newfstat(unsigned int fd, struct stat __user *statbuf) { process_syscall(); },
	static long jsys_ustat(unsigned dev, struct ustat __user *ubuf) { process_syscall(); },

	static long jsys_setxattr(const char __user *path, const char __user *name,
					 const void __user *value, size_t size, int flags) { process_syscall(); },
	static long jsys_lsetxattr(const char __user *path, const char __user *name,
					  const void __user *value, size_t size, int flags) { process_syscall(); },
	static long jsys_fsetxattr(int fd, const char __user *name,
					  const void __user *value, size_t size, int flags) { process_syscall(); },
	static long jsys_getxattr(const char __user *path, const char __user *name,
					 void __user *value, size_t size) { process_syscall(); },
	static long jsys_lgetxattr(const char __user *path, const char __user *name,
					  void __user *value, size_t size) { process_syscall(); },
	static long jsys_fgetxattr(int fd, const char __user *name,
					  void __user *value, size_t size) { process_syscall(); },
	static long jsys_listxattr(const char __user *path, char __user *list,
					  size_t size) { process_syscall(); },
	static long jsys_llistxattr(const char __user *path, char __user *list,
					   size_t size) { process_syscall(); },
	static long jsys_flistxattr(int fd, char __user *list, size_t size) { process_syscall(); },
	static long jsys_removexattr(const char __user *path,
					const char __user *name) { process_syscall(); },
	static long jsys_lremovexattr(const char __user *path,
					 const char __user *name) { process_syscall(); },
	static long jsys_fremovexattr(int fd, const char __user *name) { process_syscall(); },

	static long jsys_brk(unsigned long brk) { process_syscall(); },
	static long jsys_mprotect(unsigned long start, size_t len,
					unsigned long prot) { process_syscall(); },
	static long jsys_mremap(unsigned long addr,
				   unsigned long old_len, unsigned long new_len,
				   unsigned long flags, unsigned long new_addr) { process_syscall(); },
	static long jsys_remap_file_pages(unsigned long start, unsigned long size,
				unsigned long prot, unsigned long pgoff,
				unsigned long flags) { process_syscall(); },
	static long jsys_msync(unsigned long start, size_t len, int flags) { process_syscall(); },
	static long jsys_fadvise64(int fd, loff_t offset, size_t len, int advice) { process_syscall(); },
	static long jsys_fadvise64_64(int fd, loff_t offset, loff_t len, int advice) { process_syscall(); },
	static long jsys_munmap(unsigned long addr, size_t len) { process_syscall(); },
	static long jsys_mlock(unsigned long start, size_t len) { process_syscall(); },
	static long jsys_munlock(unsigned long start, size_t len) { process_syscall(); },
	static long jsys_mlockall(int flags) { process_syscall(); },
	static long jsys_munlockall(void) { process_syscall(); },
	static long jsys_madvise(unsigned long start, size_t len, int behavior) { process_syscall(); },
	static long jsys_mincore(unsigned long start, size_t len,
					unsigned char __user * vec) { process_syscall(); },

	static long jsys_pivot_root(const char __user *new_root,
					const char __user *put_old) { process_syscall(); },
	static long jsys_chroot(const char __user *filename) { process_syscall(); },
	static long jsys_mknod(const char __user *filename, umode_t mode,
					unsigned dev) { process_syscall(); },
	static long jsys_link(const char __user *oldname,
					const char __user *newname) { process_syscall(); },
	static long jsys_symlink(const char __user *old, const char __user *new) { process_syscall(); },
	static long jsys_unlink(const char __user *pathname) { process_syscall(); },
	static long jsys_rename(const char __user *oldname,
					const char __user *newname) { process_syscall(); },
	static long jsys_chmod(const char __user *filename, umode_t mode) { process_syscall(); },
	static long jsys_fchmod(unsigned int fd, umode_t mode) { process_syscall(); },

	static long jsys_fcntl(unsigned int fd, unsigned int cmd, unsigned long arg) { process_syscall(); },
	
	static long jsys_pipe(int __user *fildes) { process_syscall(); },
	static long jsys_pipe2(int __user *fildes, int flags) { process_syscall(); },
	static long jsys_dup(unsigned int fildes) { process_syscall(); },
	static long jsys_dup2(unsigned int oldfd, unsigned int newfd) { process_syscall(); },
	static long jsys_dup3(unsigned int oldfd, unsigned int newfd, int flags) { process_syscall(); },
	static long jsys_ioperm(unsigned long from, unsigned long num, int on) { process_syscall(); },
	static long jsys_ioctl(unsigned int fd, unsigned int cmd,
					unsigned long arg) { process_syscall(); },
	static long jsys_flock(unsigned int fd, unsigned int cmd) { process_syscall(); },
	static long jsys_io_setup(unsigned nr_reqs, aio_context_t __user *ctx) { process_syscall(); },
	static long jsys_io_destroy(aio_context_t ctx) { process_syscall(); },
	static long jsys_io_getevents(aio_context_t ctx_id,
					long min_nr,
					long nr,
					struct io_event __user *events,
					struct timespec __user *timeout) { process_syscall(); },
	static long jsys_io_submit(aio_context_t, long,
					struct iocb __user * __user *) { process_syscall(); },
	static long jsys_io_cancel(aio_context_t ctx_id, struct iocb __user *iocb,
					  struct io_event __user *result) { process_syscall(); },
	static long jsys_sendfile(int out_fd, int in_fd,
					 off_t __user *offset, size_t count) { process_syscall(); },
	static long jsys_sendfile64(int out_fd, int in_fd,
					   loff_t __user *offset, size_t count) { process_syscall(); },
	static long jsys_readlink(const char __user *path,
					char __user *buf, int bufsiz) { process_syscall(); },
	static long jsys_creat(const char __user *pathname, umode_t mode) { process_syscall(); },
	static long jsys_open(const char __user *filename,
					int flags, umode_t mode) { process_syscall(); },
	static long jsys_close(unsigned int fd) { process_syscall(); },
	static long jsys_access(const char __user *filename, int mode) { process_syscall(); },
	static long jsys_vhangup(void) { process_syscall(); },
	static long jsys_chown(const char __user *filename,
					uid_t user, gid_t group) { process_syscall(); },
	static long jsys_lchown(const char __user *filename,
					uid_t user, gid_t group) { process_syscall(); },
	static long jsys_fchown(unsigned int fd, uid_t user, gid_t group) { process_syscall(); },

	static long jsys_utime(char __user *filename,
					struct utimbuf __user *times) { process_syscall(); },
	static long jsys_utimes(char __user *filename,
					struct timeval __user *utimes) { process_syscall(); },
	static long jsys_lseek(unsigned int fd, off_t offset,
				  unsigned int whence) { process_syscall(); },
	static long jsys_llseek(unsigned int fd, unsigned long offset_high,
				unsigned long offset_low, loff_t __user *result,
				unsigned int whence) { process_syscall(); },
	static long jsys_read(unsigned int fd, char __user *buf, size_t count) { process_syscall(); },
	static long jsys_readahead(int fd, loff_t offset, size_t count) { process_syscall(); },
	static long jsys_readv(unsigned long fd,
				  const struct iovec __user *vec,
				  unsigned long vlen) { process_syscall(); },
	static long jsys_write(unsigned int fd, const char __user *buf,
				  size_t count) { process_syscall(); },
	static long jsys_writev(unsigned long fd,
				   const struct iovec __user *vec,
				   unsigned long vlen) { process_syscall(); },
	static long jsys_pread64(unsigned int fd, char __user *buf,
					size_t count, loff_t pos) { process_syscall(); },
	static long jsys_pwrite64(unsigned int fd, const char __user *buf,
					 size_t count, loff_t pos) { process_syscall(); },
	static long jsys_preadv(unsigned long fd, const struct iovec __user *vec,
				   unsigned long vlen, unsigned long pos_l, unsigned long pos_h) { process_syscall(); },
	static long jsys_preadv2(unsigned long fd, const struct iovec __user *vec,
					unsigned long vlen, unsigned long pos_l, unsigned long pos_h,
					int flags) { process_syscall(); },
	static long jsys_pwritev(unsigned long fd, const struct iovec __user *vec,
					unsigned long vlen, unsigned long pos_l, unsigned long pos_h) { process_syscall(); },
	static long jsys_pwritev2(unsigned long fd, const struct iovec __user *vec,
					unsigned long vlen, unsigned long pos_l, unsigned long pos_h,
					int flags) { process_syscall(); },
	static long jsys_getcwd(char __user *buf, unsigned long size) { process_syscall(); },
	static long jsys_mkdir(const char __user *pathname, umode_t mode) { process_syscall(); },
	static long jsys_chdir(const char __user *filename) { process_syscall(); },
	static long jsys_fchdir(unsigned int fd) { process_syscall(); },
	static long jsys_rmdir(const char __user *pathname) { process_syscall(); },
	static long jsys_lookup_dcookie(u64 cookie64, char __user *buf, size_t len) { process_syscall(); },
	static long jsys_quotactl(unsigned int cmd, const char __user *special,
					qid_t id, void __user *addr) { process_syscall(); },
	static long jsys_getdents(unsigned int fd,
					struct linux_dirent __user *dirent,
					unsigned int count) { process_syscall(); },
	static long jsys_getdents64(unsigned int fd,
					struct linux_dirent64 __user *dirent,
					unsigned int count) { process_syscall(); },

	static long jsys_setsockopt(int fd, int level, int optname,
					char __user *optval, int optlen) { process_syscall(); },
	static long jsys_getsockopt(int fd, int level, int optname,
					char __user *optval, int __user *optlen) { process_syscall(); },
	static long jsys_bind(int, struct sockaddr __user *, int) { process_syscall(); },
	static long jsys_connect(int, struct sockaddr __user *, int) { process_syscall(); },
	static long jsys_accept(int, struct sockaddr __user *, int __user *) { process_syscall(); },
	static long jsys_accept4(int, struct sockaddr __user *, int __user *, int) { process_syscall(); },
	static long jsys_getsockname(int, struct sockaddr __user *, int __user *) { process_syscall(); },
	static long jsys_getpeername(int, struct sockaddr __user *, int __user *) { process_syscall(); },
	static long jsys_send(int, void __user *, size_t, unsigned) { process_syscall(); },
	static long jsys_sendto(int, void __user *, size_t, unsigned,
					struct sockaddr __user *, int) { process_syscall(); },
	static long jsys_sendmsg(int fd, struct user_msghdr __user *msg, unsigned flags) { process_syscall(); },
	static long jsys_sendmmsg(int fd, struct mmsghdr __user *msg,
					 unsigned int vlen, unsigned flags) { process_syscall(); },
	static long jsys_recv(int, void __user *, size_t, unsigned) { process_syscall(); },
	static long jsys_recvfrom(int, void __user *, size_t, unsigned,
					struct sockaddr __user *, int __user *) { process_syscall(); },
	static long jsys_recvmsg(int fd, struct user_msghdr __user *msg, unsigned flags) { process_syscall(); },
	static long jsys_recvmmsg(int fd, struct mmsghdr __user *msg,
					 unsigned int vlen, unsigned flags,
					 struct timespec __user *timeout) { process_syscall(); },
	static long jsys_socket(int, int, int) { process_syscall(); },
	static long jsys_socketpair(int, int, int, int __user *) { process_syscall(); },
	static long jsys_socketcall(int call, unsigned long __user *args) { process_syscall(); },
	static long jsys_listen(int, int) { process_syscall(); },
	static long jsys_poll(struct pollfd __user *ufds, unsigned int nfds,
					int timeout) { process_syscall(); },
	static long jsys_select(int n, fd_set __user *inp, fd_set __user *outp,
				fd_set __user *exp, struct timeval __user *tvp) { process_syscall(); },
	static long jsys_old_select(struct sel_arg_struct __user *arg) { process_syscall(); },
	static long jsys_epoll_create(int size) { process_syscall(); },
	static long jsys_epoll_create1(int flags) { process_syscall(); },
	static long jsys_epoll_ctl(int epfd, int op, int fd,
					struct epoll_event __user *event) { process_syscall(); },
	static long jsys_epoll_wait(int epfd, struct epoll_event __user *events,
					int maxevents, int timeout) { process_syscall(); },
	static long jsys_epoll_pwait(int epfd, struct epoll_event __user *events,
					int maxevents, int timeout,
					const sigset_t __user *sigmask,
					size_t sigsetsize) { process_syscall(); },
	static long jsys_gethostname(char __user *name, int len) { process_syscall(); },
	static long jsys_sethostname(char __user *name, int len) { process_syscall(); },
	static long jsys_setdomainname(char __user *name, int len) { process_syscall(); },
	static long jsys_newuname(struct new_utsname __user *name) { process_syscall(); },
	static long jsys_uname(struct old_utsname __user *) { process_syscall(); },
	static long jsys_olduname(struct oldold_utsname __user *) { process_syscall(); },

	static long jsys_getrlimit(unsigned int resource,
					struct rlimit __user *rlim) { process_syscall(); },
	static long jsys_setrlimit(unsigned int resource,
					struct rlimit __user *rlim) { process_syscall(); },
	static long jsys_prlimit64(pid_t pid, unsigned int resource,
					const struct rlimit64 __user *new_rlim,
					struct rlimit64 __user *old_rlim) { process_syscall(); },
	static long jsys_getrusage(int who, struct rusage __user *ru) { process_syscall(); },
	static long jsys_umask(int mask) { process_syscall(); },

	static long jsys_msgget(key_t key, int msgflg) { process_syscall(); },
	static long jsys_msgsnd(int msqid, struct msgbuf __user *msgp,
					size_t msgsz, int msgflg) { process_syscall(); },
	static long jsys_msgrcv(int msqid, struct msgbuf __user *msgp,
					size_t msgsz, long msgtyp, int msgflg) { process_syscall(); },
	static long jsys_msgctl(int msqid, int cmd, struct msqid_ds __user *buf) { process_syscall(); },

	static long jsys_semget(key_t key, int nsems, int semflg) { process_syscall(); },
	static long jsys_semop(int semid, struct sembuf __user *sops,
					unsigned nsops) { process_syscall(); },
	static long jsys_semctl(int semid, int semnum, int cmd, unsigned long arg) { process_syscall(); },
	static long jsys_semtimedop(int semid, struct sembuf __user *sops,
					unsigned nsops,
					const struct timespec __user *timeout) { process_syscall(); },
	static long jsys_shmat(int shmid, char __user *shmaddr, int shmflg) { process_syscall(); },
	static long jsys_shmget(key_t key, size_t size, int flag) { process_syscall(); },
	static long jsys_shmdt(char __user *shmaddr) { process_syscall(); },
	static long jsys_shmctl(int shmid, int cmd, struct shmid_ds __user *buf) { process_syscall(); },
	static long jsys_ipc(unsigned int call, int first, unsigned long second,
			unsigned long third, void __user *ptr, long fifth) { process_syscall(); },

	static long jsys_mq_open(const char __user *name, int oflag, umode_t mode, struct mq_attr __user *attr) { process_syscall(); },
	static long jsys_mq_unlink(const char __user *name) { process_syscall(); },
	static long jsys_mq_timedsend(mqd_t mqdes, const char __user *msg_ptr, size_t msg_len, unsigned int msg_prio, const struct timespec __user *abs_timeout) { process_syscall(); },
	static long jsys_mq_timedreceive(mqd_t mqdes, char __user *msg_ptr, size_t msg_len, unsigned int __user *msg_prio, const struct timespec __user *abs_timeout) { process_syscall(); },
	static long jsys_mq_notify(mqd_t mqdes, const struct sigevent __user *notification) { process_syscall(); },
	static long jsys_mq_getsetattr(mqd_t mqdes, const struct mq_attr __user *mqstat, struct mq_attr __user *omqstat) { process_syscall(); },

	static long jsys_pciconfig_iobase(long which, unsigned long bus, unsigned long devfn) { process_syscall(); },
	static long jsys_pciconfig_read(unsigned long bus, unsigned long dfn,
					unsigned long off, unsigned long len,
					void __user *buf) { process_syscall(); },
	static long jsys_pciconfig_write(unsigned long bus, unsigned long dfn,
					unsigned long off, unsigned long len,
					void __user *buf) { process_syscall(); },

	static long jsys_prctl(int option, unsigned long arg2, unsigned long arg3,
				unsigned long arg4, unsigned long arg5) { process_syscall(); },
	static long jsys_swapon(const char __user *specialfile, int swap_flags) { process_syscall(); },
	static long jsys_swapoff(const char __user *specialfile) { process_syscall(); },
	static long jsys_sysctl(struct __sysctl_args __user *args) { process_syscall(); },
	static long jsys_sysinfo(struct sysinfo __user *info) { process_syscall(); },
	static long jsys_sysfs(int option,
					unsigned long arg1, unsigned long arg2) { process_syscall(); },
	static long jsys_syslog(int type, char __user *buf, int len) { process_syscall(); },
	static long jsys_uselib(const char __user *library) { process_syscall(); },
	static long jsys_ni_syscall(void) { process_syscall(); },
	static long jsys_ptrace(long request, long pid, unsigned long addr,
				   unsigned long data) { process_syscall(); },

	static long jsys_add_key(const char __user *_type,
					const char __user *_description,
					const void __user *_payload,
					size_t plen,
					key_serial_t destringid) { process_syscall(); },

	static long jsys_request_key(const char __user *_type,
					const char __user *_description,
					const char __user *_callout_info,
					key_serial_t destringid) { process_syscall(); },

	static long jsys_keyctl(int cmd, unsigned long arg2, unsigned long arg3,
				   unsigned long arg4, unsigned long arg5) { process_syscall(); },

	static long jsys_ioprio_set(int which, int who, int ioprio) { process_syscall(); },
	static long jsys_ioprio_get(int which, int who) { process_syscall(); },
	static long jsys_set_mempolicy(int mode, const unsigned long __user *nmask,
					unsigned long maxnode) { process_syscall(); },
	static long jsys_migrate_pages(pid_t pid, unsigned long maxnode,
					const unsigned long __user *from,
					const unsigned long __user *to) { process_syscall(); },
	static long jsys_move_pages(pid_t pid, unsigned long nr_pages,
					const void __user * __user *pages,
					const int __user *nodes,
					int __user *status,
					int flags) { process_syscall(); },
	static long jsys_mbind(unsigned long start, unsigned long len,
					unsigned long mode,
					const unsigned long __user *nmask,
					unsigned long maxnode,
					unsigned flags) { process_syscall(); },
	static long jsys_get_mempolicy(int __user *policy,
					unsigned long __user *nmask,
					unsigned long maxnode,
					unsigned long addr, unsigned long flags) { process_syscall(); },

	static long jsys_inotify_init(void) { process_syscall(); },
	static long jsys_inotify_init1(int flags) { process_syscall(); },
	static long jsys_inotify_add_watch(int fd, const char __user *path,
						u32 mask) { process_syscall(); },
	static long jsys_inotify_rm_watch(int fd, __s32 wd) { process_syscall(); },

	static long jsys_spu_run(int fd, __u32 __user *unpc,
					 __u32 __user *ustatus) { process_syscall(); },
	static long jsys_spu_create(const char __user *name,
			unsigned int flags, umode_t mode, int fd) { process_syscall(); },

	static long jsys_mknodat(int dfd, const char __user * filename, umode_t mode,
					unsigned dev) { process_syscall(); },
	static long jsys_mkdirat(int dfd, const char __user * pathname, umode_t mode) { process_syscall(); },
	static long jsys_unlinkat(int dfd, const char __user * pathname, int flag) { process_syscall(); },
	static long jsys_symlinkat(const char __user * oldname,
					  int newdfd, const char __user * newname) { process_syscall(); },
	static long jsys_linkat(int olddfd, const char __user *oldname,
				   int newdfd, const char __user *newname, int flags) { process_syscall(); },
	static long jsys_renameat(int olddfd, const char __user * oldname,
					 int newdfd, const char __user * newname) { process_syscall(); },
	static long jsys_renameat2(int olddfd, const char __user *oldname,
					  int newdfd, const char __user *newname,
					  unsigned int flags) { process_syscall(); },
	static long jsys_futimesat(int dfd, const char __user *filename,
					  struct timeval __user *utimes) { process_syscall(); },
	static long jsys_faccessat(int dfd, const char __user *filename, int mode) { process_syscall(); },
	static long jsys_fchmodat(int dfd, const char __user * filename,
					 umode_t mode) { process_syscall(); },
	static long jsys_fchownat(int dfd, const char __user *filename, uid_t user,
					 gid_t group, int flag) { process_syscall(); },
	static long jsys_openat(int dfd, const char __user *filename, int flags,
				   umode_t mode) { process_syscall(); },
	static long jsys_newfstatat(int dfd, const char __user *filename,
					   struct stat __user *statbuf, int flag) { process_syscall(); },
	static long jsys_readlinkat(int dfd, const char __user *path, char __user *buf,
					   int bufsiz) { process_syscall(); },
	static long jsys_utimensat(int dfd, const char __user *filename,
					struct timespec __user *utimes, int flags) { process_syscall(); },
	static long jsys_unshare(unsigned long unshare_flags) { process_syscall(); },

	static long jsys_splice(int fd_in, loff_t __user *off_in,
				   int fd_out, loff_t __user *off_out,
				   size_t len, unsigned int flags) { process_syscall(); },

	static long jsys_vmsplice(int fd, const struct iovec __user *iov,
					 unsigned long nr_segs, unsigned int flags) { process_syscall(); },

	static long jsys_tee(int fdin, int fdout, size_t len, unsigned int flags) { process_syscall(); },

	static long jsys_sync_file_range(int fd, loff_t offset, loff_t nbytes,
						unsigned int flags) { process_syscall(); },
	static long jsys_sync_file_range2(int fd, unsigned int flags,
						 loff_t offset, loff_t nbytes) { process_syscall(); },
	static long jsys_get_robust_list(int pid,
						struct robust_list_head __user * __user *head_ptr,
						size_t __user *len_ptr) { process_syscall(); },
	static long jsys_set_robust_list(struct robust_list_head __user *head,
						size_t len) { process_syscall(); },
	static long jsys_getcpu(unsigned __user *cpu, unsigned __user *node, struct getcpu_cache __user *cache) { process_syscall(); },
	static long jsys_signalfd(int ufd, sigset_t __user *user_mask, size_t sizemask) { process_syscall(); },
	static long jsys_signalfd4(int ufd, sigset_t __user *user_mask, size_t sizemask, int flags) { process_syscall(); },
	static long jsys_timerfd_create(int clockid, int flags) { process_syscall(); },
	static long jsys_timerfd_settime(int ufd, int flags,
						const struct itimerspec __user *utmr,
						struct itimerspec __user *otmr) { process_syscall(); },
	static long jsys_timerfd_gettime(int ufd, struct itimerspec __user *otmr) { process_syscall(); },
	static long jsys_eventfd(unsigned int count) { process_syscall(); },
	static long jsys_eventfd2(unsigned int count, int flags) { process_syscall(); },
	static long jsys_memfd_create(const char __user *uname_ptr, unsigned int flags) { process_syscall(); },
	static long jsys_userfaultfd(int flags) { process_syscall(); },
	static long jsys_fallocate(int fd, int mode, loff_t offset, loff_t len) { process_syscall(); },
	static long jsys_old_readdir(unsigned int, struct old_linux_dirent __user *, unsigned int) { process_syscall(); },
	static long jsys_pselect6(int, fd_set __user *, fd_set __user *,
					 fd_set __user *, struct timespec __user *,
					 void __user *) { process_syscall(); },
	static long jsys_ppoll(struct pollfd __user *fds, unsigned int nfds,
				  struct timespec __user *tmo_p, const sigset_t __user *sigmask,
				  size_t size) { process_syscall(); },
	static long jsys_fanotify_init(unsigned int flags, unsigned int event_f_flags) { process_syscall(); },
	static long jsys_fanotify_mark(int fanotify_fd, unsigned int flags,
					  u64 mask, int fd,
					  const char  __user *pathname) { process_syscall(); },
	static long jsys_syncfs(int fd) { process_syscall(); },

	static long jsys_fork(void) { process_syscall(); },
	static long jsys_vfork(void) { process_syscall(); },

	static long jsys_execve(const char __user *filename,
			const char __user *const __user *argv,
			const char __user *const __user *envp) { process_syscall(); },

	static long jsys_perf_event_open(
			struct perf_event_attr __user *attr_uptr,
			pid_t pid, int cpu, int group_fd, unsigned long flags) { process_syscall(); },

	static long jsys_mmap_pgoff(unsigned long addr, unsigned long len,
				unsigned long prot, unsigned long flags,
				unsigned long fd, unsigned long pgoff) { process_syscall(); },
	static long jsys_old_mmap(struct mmap_arg_struct __user *arg) { process_syscall(); },
	static long jsys_name_to_handle_at(int dfd, const char __user *name,
						  struct file_handle __user *handle,
						  int __user *mnt_id, int flag) { process_syscall(); },
	static long jsys_open_by_handle_at(int mountdirfd,
						  struct file_handle __user *handle,
						  int flags) { process_syscall(); },
	static long jsys_setns(int fd, int nstype) { process_syscall(); },
	static long jsys_process_vm_readv(pid_t pid,
						 const struct iovec __user *lvec,
						 unsigned long liovcnt,
						 const struct iovec __user *rvec,
						 unsigned long riovcnt,
						 unsigned long flags) { process_syscall(); },
	static long jsys_process_vm_writev(pid_t pid,
						  const struct iovec __user *lvec,
						  unsigned long liovcnt,
						  const struct iovec __user *rvec,
						  unsigned long riovcnt,
						  unsigned long flags) { process_syscall(); },

	static long jsys_kcmp(pid_t pid1, pid_t pid2, int type,
				 unsigned long idx1, unsigned long idx2) { process_syscall(); },
	static long jsys_finit_module(int fd, const char __user *uargs, int flags) { process_syscall(); },
	static long jsys_seccomp(unsigned int op, unsigned int flags,
					const char __user *uargs) { process_syscall(); },
	static long jsys_getrandom(char __user *buf, size_t count,
					  unsigned int flags) { process_syscall(); },
	static long jsys_bpf(int cmd, union bpf_attr *attr, unsigned int size) { process_syscall(); },

	static long jsys_execveat(int dfd, const char __user *filename,
				const char __user *const __user *argv,
				const char __user *const __user *envp, int flags) { process_syscall(); },

	static long jsys_membarrier(int cmd, int flags) { process_syscall(); },
	static long jsys_copy_file_range(int fd_in, loff_t __user *off_in,
						int fd_out, loff_t __user *off_out,
						size_t len, unsigned int flags) { process_syscall(); },

	static long jsys_mlock2(unsigned long start, size_t len, int flags) { process_syscall(); },

	static long jsys_pkey_mprotect(unsigned long start, size_t len,
					  unsigned long prot, int pkey) { process_syscall(); },
	static long jsys_pkey_alloc(unsigned long flags, unsigned long init_val) { process_syscall(); },
	static long jsys_pkey_free(int pkey) { process_syscall(); },
	static long jsys_statx(int dfd, const char __user *path, unsigned flags,
				  unsigned mask, struct statx __user *buffer) { process_syscall(); }
};

#define num_syscalls (sizeof(jprobes_array) / sizeof(jprobes_array[0]))

