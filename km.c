/*
URL for cloning: https://github.com/shanebishop/pH-rewrite.git

Notes:
-Know when to use retreive_pH_profile_by_filename instead of retreive_pH_profile_by_pid
-When retrieving the PID of a process, use pid_vnr(task_tgid(tsk));, where tsk is the task_struct of 
the particular process
-Make sure that syscalls are still processed even while waiting to hear back from the user
-Make sure to update filenames and stuff when done (including ebbchar_init, ebbchar_exit, and 
ebbchar_mutex)
-Never use booleans to stop code from running after a fatal error, instead use ASSERT with a detailed
error message (code should ONLY stop running on ASSERT or rmmod)
*/
#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/mutex.h>

#include <linux/kprobes.h>   // For kprobes
#include <linux/slab.h>      // For kmalloc
#include <linux/vmalloc.h>   // For vmalloc

#include "system_call_prototypes.h"
#include "ebbcharmutex.h"

#define  DEVICE_NAME "ebbchar"
#define  CLASS_NAME  "ebb"

MODULE_LICENSE("GPL"); // Don't ever forget this line!

// Anil's definitions
//#define PH_NUM_SYSCALLS 256 // Size of array
#define PH_NUM_SYSCALLS num_syscalls // Size of array
#define PH_COUNT_PAGE_MAX (PAGE_SIZE / PH_NUM_SYSCALLS)
#define PH_MAX_PAGES (PH_NUM_SYSCALLS / PH_COUNT_PAGE_MAX)
#define PH_MAX_SEQLEN 9
#define PH_MAX_DISK_FILENAME 256
#define PH_LOCALITY_WIN 128
#define PH_FILE_MAGIC_LEN 20
#define PH_EMPTY_SYSCALL 255 // Note: This value is used as the "no system call" marker in sequences"

#define PH_LOG_ERR 1      /* real errors */
#define PH_LOG_STATE 2    /* changes in state */
#define PH_LOG_ACTION 3   /* actions pH takes (delays) */
#define PH_LOG_IO 4    /* I/O operations (read/write profiles) */

#define err(format, arg...) \
{ \
        if (pH_loglevel >= PH_LOG_ERR) { \
                printk(KERN_ERR "pH: " format "\n" , ## arg); \
        } \
}

#define state(format, arg...) \
{ \
        if (pH_loglevel >= PH_LOG_STATE) { \
                printk(KERN_INFO "pH: " format "\n" , ## arg); \
        } \
}

#define action(format, arg...) \
{ \
        if (pH_loglevel >= PH_LOG_ACTION) { \
                printk(KERN_DEBUG "pH: " format "\n" , ## arg); \
        } \
}

#define io(format, arg...) \
{ \
        if (pH_loglevel >= PH_LOG_IO) { \
                printk(KERN_DEBUG "pH: " format "\n" , ## arg); \
        } \
}

// My definitions
#define ASSERT(x)                                                       \
do {    if (x) break;                                                   \
        printk(KERN_EMERG "### ASSERTION FAILED %s: %s: %d: %s\n",      \
               __FILE__, __func__, __LINE__, #x); dump_stack(); BUG();  \
} while (0)

const char *PH_FILE_MAGIC = "pH profile 0.18\n";

static int     dev_open(struct inode *, struct file *);
static int     dev_release(struct inode *, struct file *);
static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);

static struct file_operations fops =
{
	.open = dev_open,
	.read = dev_read,
	.write = dev_write,
	.release = dev_release,
};

// Anil's structs
typedef int pH_seqflags;

typedef struct pH_seq {
	// My new fields
	struct pH_seq* next; // For linked list stack implementation
	struct pH_seq* prev;

	// Anil's old fields
	int last; // seq is a circular array; this is its end
	int length;
	u8 data[PH_MAX_SEQLEN]; // Current sequence being filled or processed - initialized to PH_EMPTY_SYSCALL initially
	struct list_head seqList;
} pH_seq;

typedef struct pH_profile_data {
	int sequences;					// # sequences that have been inserted NOT the number of lookahead pairs
	unsigned long last_mod_count;	// # syscalls since last modification
	unsigned long train_count;		// # syscalls seen during training
	//void *pages[PH_MAX_PAGES];
	//int current_page;				// pages[current_page] contains free space
	//int count_page;					// How many arrays have been allocated in the current page
	pH_seqflags *entry[PH_NUM_SYSCALLS];
} pH_profile_data;

typedef struct pH_profile pH_profile;

struct pH_profile {
	// My new fields
	struct hlist_node hlist; // Must be first field
	int identifier;
	spinlock_t freeing_lock;
	
	// Anil's old fields
	int normal;			// Is test profile normal?
	int frozen;			// Is train profile frozen (potential normal)?
	time_t normal_time;	// When will frozen become true normal?
	int length;
	unsigned long count;// Number of calls seen by this profile
	int anomalies;		// NOT LFC - decide if normal should be reset
	pH_profile_data train, test;
	char *filename;
	atomic_t refcount;
	pH_profile *next;
	//struct file *seq_logfile;
	pH_seq seq;
	spinlock_t* lock;
};

typedef struct pH_seq_logrec {
        unsigned long count;
        int pid;
        struct timespec time;
        pH_seq seq;
} pH_seq_logrec;

#define PH_CALLREC_SYSCALL 0
#define PH_CALLREC_FORK    1
#define PH_CALLREC_EXECVE  2

typedef struct pH_call_logrec {
        u16 pid;
        union {
                u16 syscall;      /* type = 0 */
                u16 child_pid;    /* type = 1 (fork) */
                u16 filename_len; /* type = 2 (execve) */
        } u;
        unsigned long count;
        long sec;
        long nsec;
        u8 type;          /* 0 = regular call, 1 = fork, 2, execve */
} pH_call_logrec;

typedef struct pH_locality {
	u8 win[PH_LOCALITY_WIN];
	int first;
	int total;
	int max;
} pH_locality;

// My own structs
typedef struct my_syscall {
	struct my_syscall* next;
	unsigned long syscall_num;
} my_syscall;

typedef struct pH_task_struct { // My own version of a pH_task_state
	struct pH_task_struct* next; // For linked lists
	struct pH_task_struct* prev;
	my_syscall* syscall_llist;
	long process_id;
	pH_locality alf;
	pH_seq* seq;
	spinlock_t pH_seq_stack_sem;
	int delay;
	unsigned long count;
	pH_profile* profile; // Pointer to appropriate profile
	struct task_struct* task_struct; // Pointer to corresponding task_struct
	struct pid* pid; // Pointer to corresponding struct pid
} pH_task_struct;

typedef struct read_filename {
	char* filename;
	struct read_filename* next;
} read_filename;

static void jhandle_signal(struct ksignal*, struct pt_regs*);

struct jprobe handle_signal_jprobe = {
	.entry = jhandle_signal,
	//.kp = {
	//	.symbol_name = "handle_signal",
	//},
};

/*
static long jsys_sigreturn(struct pt_regs*);

struct jprobe sys_sigreturn_jprobe = {
	.entry = jsys_sigreturn,
	.kp = {
		.symbol_name = "sys_sigreturn",
	},
};
*/

static long jsys_rt_sigreturn(void);

struct jprobe sys_sigreturn_jprobe = {
	.entry = jsys_rt_sigreturn,
};

static void jdo_signal(struct pt_regs* regs);

struct jprobe do_signal_jprobe = {
	.entry = jdo_signal,
};

/* this was atomic, but now we need a long - so, we could make
   a spinlock for this */
unsigned long pH_syscall_count = 0;
//spinlock_t pH_syscall_count_lock = SPIN_LOCK_UNLOCKED;

pH_profile *pH_profile_list = NULL;
int pH_default_looklen = 9;
struct file *pH_logfile = NULL;
int pH_delay_factor = 0;
unsigned int pH_normal_factor = 128;
#define pH_normal_factor_den 32        /* a define to make the asm better */
int pH_aremonitoring = 0;
int pH_monitorSignal = 0;
int pH_mod_min = 500;
int pH_normal_min = 5;
int pH_anomaly_limit = 30;   /* test reset if profile->anomalies */
                                 /* exceeds this limit */
int pH_tolerize_limit = 12; /* train reset if LFC exceeds this limit */
int pH_loglevel = PH_LOG_ACTION;
int pH_log_sequences = 0;
int pH_suspend_execve = 0; /* min LFC to suspend execve's, 0 = no suspends */
int pH_suspend_execve_time = 3600 * 24 * 2;  /* time to suspend execve's */
int pH_normal_wait = 7 * 24 * 3600;/* seconds before putting normal to work */

// My global variables
#define SIGNAL_PRIVILEGE (1)
pH_task_struct* pH_task_struct_list = NULL; // List of processes currently being monitored
struct jprobe jprobes_array[num_syscalls];  // Array of jprobes (is this obsolete?)
long userspace_pid;                         // The PID of the userspace process
const char TRANSFER_OPERATION[2] = {'t', '\0'};
const char STOP_TRANSFER_OPERATION[3] = {'s', 't', '\0'};
const char READ_PROFILE_FROM_DISK[3] = {'r', 'b', '\0'};
char* output_string;                        // The string that will be sent to userspace
void* bin_receive_ptr;                      // The pointer for binary writes
bool done_waiting_for_user        = FALSE;
bool have_userspace_pid           = FALSE;
bool binary_read                  = FALSE;
bool user_process_has_been_loaded = FALSE;
bool module_inserted_successfully = FALSE;
spinlock_t pH_profile_list_sem;             // Lock for list of profiles
spinlock_t pH_task_struct_list_sem;         // Lock for process list
int profiles_created = 0;                   // Number of profiles that have been created
int successful_jsys_execves = 0;            // Number of successful jsys_execves
spinlock_t execve_count_lock;
struct task_struct* last_task_struct_in_sigreturn = NULL;
pH_disk_profile* profile_queue_front = NULL;
pH_disk_profile* profile_queue_rear = NULL;
//pH_profile* read_profile_queue_front = NULL;
//pH_profile* read_profile_queue_rear = NULL;
read_filename* read_filename_queue_front = NULL;
read_filename* read_filename_queue_rear = NULL;

// Returns true if the process is being monitored, false otherwise
inline bool pH_monitoring(pH_task_struct* process) {
    return process->profile != NULL;
}

// Returns true if the profile is in use, false otherwise
inline bool pH_profile_in_use(pH_profile *profile)
{
    return atomic_read(&(profile->refcount)) > 0;
}

// Increments the profile's reference count
inline void pH_refcount_inc(pH_profile *profile)
{
    atomic_inc(&(profile->refcount));
}

// Decrements the profile's reference count
inline void pH_refcount_dec(pH_profile *profile)
{
    atomic_dec(&(profile->refcount));
}

// Initializes the profile's reference count
// Perhaps this should call atomic_set rather than directly changing the value
inline void pH_refcount_init(pH_profile *profile, int i)
{
    profile->refcount.counter = i;
}

inline int get_refcount(pH_profile* profile) {
	return atomic_read(&(profile->refcount));
}

/* // Commented out for now, as I might not need it
// Returns the length of the profile list
int pH_profile_list_length(void) {
	pH_profile* iterator;
	int i;
	
	for (i = 0, iterator = pH_profile_list; 
		iterator != NULL; 
		i++, iterator = iterator->next) 
	{
		if (sizeof(*iterator) == sizeof(pH_profile)) {
			pr_err("%s: Found object in pH_profile_list that is not a profile\n", DEVICE_NAME);
		}
	}
	
	return i;
}
*/

/*
// Returns the length of the process list
int pH_task_struct_list_length(void) {
	pH_task_struct* iterator;
	int i;
	
	//spin_lock(&pH_task_struct_list_sem);
	for (i = 0, iterator = pH_task_struct_list; 
		iterator != NULL; 
		i++, iterator = iterator->next) 
	{
		;
	}
	//spin_unlock(&pH_task_struct_list_sem);
	
	return i;
}
*/

// Adds an alloc'd profile to the profile list
void add_to_profile_llist(pH_profile* p) {
	pH_refcount_inc(p);
	
	ASSERT(spin_is_locked(&pH_profile_list_sem));
	//ASSERT(!spin_is_locked(&pH_task_struct_list_sem));
	
	//pr_err("%s: In add_to_profile_llist\n", DEVICE_NAME);
	
	// Checks for adding a NULL profile
	if (!p || p == NULL) {
		pr_err("%s: In add_to_profile_llist with a NULL profile\n", DEVICE_NAME);
		pH_refcount_dec(p);
		ASSERT(p != NULL);
		return;
	}
	
	//spin_lock(&pH_profile_list_sem);
	if (pH_profile_list == NULL) {
		pr_err("%s: First element added to list\n", DEVICE_NAME);
		pH_profile_list = p;
		p->next = NULL;
	}
	else {
		/* // Old implementation
		pH_profile* iterator = pH_profile_list;
		
		while (iterator->next) iterator = iterator->next;
		
		iterator->next = p;
		p->next = NULL;
		*/
		
		pr_err("%s: Adding a new element...\n", DEVICE_NAME);
		p->next = pH_profile_list;
		pH_profile_list = p;
		ASSERT(pH_profile_list->next != NULL);
	}
	//spin_unlock(&pH_profile_list_sem);
	
	pH_refcount_dec(p);
	
	ASSERT(pH_profile_list != NULL);
	ASSERT(pH_profile_list == p);
	
	//pr_err("%s: Returning from add_to_profile_llist()...\n", DEVICE_NAME);
}

bool profile_queue_is_empty(void) {
	return (profile_queue_front == NULL);
}

void add_to_profile_queue(pH_disk_profile* disk_profile) {
	if (!disk_profile || disk_profile == NULL) {
		pr_err("%s: In add_to_profile_queue with NULL disk_profile\n", DEVICE_NAME);
		return;
	}
	
	if (profile_queue_front == NULL) {
		profile_queue_front = disk_profile;
		profile_queue_rear = disk_profile;
		profile_queue_rear->next = NULL;
	}
	else {
		profile_queue_rear->next = disk_profile;
		profile_queue_rear = disk_profile;
		profile_queue_rear->next = NULL;
	}
}

// Calling functions MUST deallocate memory of return value
pH_disk_profile* remove_from_profile_queue(void) {
	pH_disk_profile* to_return;
	
	pr_err("%s: In remove_from_profile_queue\n", DEVICE_NAME);
	
	if (profile_queue_front == NULL) {
		pr_err("%s: Profile queue is empty\n", DEVICE_NAME);
		return NULL;
	}
	pr_err("%s: Profile queue is not empty\n", DEVICE_NAME);
	
	pr_err("%s: profile_queue_front = %p\n", DEVICE_NAME, profile_queue_front);
	to_return = profile_queue_front;
	pr_err("%s: Set to_return\n", DEVICE_NAME);
	profile_queue_front = profile_queue_front->next;
	pr_err("%s: Updated profile_queue_front\n", DEVICE_NAME);
	
	return to_return;
}

/*
void add_to_read_profile_queue(pH_profile* profile) {
	ASSERT(profile != NULL);
	
	if (read_profile_queue_front == NULL) {
		read_profile_queue_front = profile;
		read_profile_queue_rear = profile;
		read_profile_queue_rear->next = NULL;
	}
	else {
		read_profile_queue_rear->next = profile;
		read_profile_queue_rear = profile;
		read_profile_queue_rear->next = NULL;
	}
}

pH_profile* grab_profile_from_read_queue(void) {
	pH_profile* to_return;
	
	if (read_profile_queue_front == NULL) {
		return NULL;
	}
	
	to_return = read_profile_queue_front;
	read_profile_queue_front = read_profile_queue_front->next;
	return to_return;
}
*/

void add_to_read_filename_queue(char* filename) {
	read_filename* to_add = kmalloc(sizeof(read_filename), GFP_ATOMIC);
	if (!to_add || to_add == NULL) {
		pr_err("%s: Out of memory in add_to_read_filename\n", DEVICE_NAME);
		return;
	}
	to_add->filename = filename;
	to_add->next = NULL;
	
	if (read_filename_queue_front == NULL) {
		read_filename_queue_front = to_add;
		read_filename_queue_rear = to_add;
		read_filename_queue_rear->next = NULL;
	}
	else {
		read_filename_queue_rear->next = to_add;
		read_filename_queue_rear = to_add;
		read_filename_queue_rear->next = NULL;
	}
}

// The return value MUST be deallocated by the calling function
// Before freeing, use strcpy to copy to a local char*
read_filename* remove_from_read_filename_queue(void) {
	read_filename* to_return;
	
	if (read_filename_queue_front == NULL) return NULL;
	
	to_return = read_filename_queue_front;
	read_filename_queue_front = read_filename_queue_front->next;
	return to_return;
}

// Makes a new pH_profile and stores it in profile
// profile must be allocated before this function is called
int new_profile(pH_profile* profile, char* filename) {
	int i;

	// Checks for NULL
	if (!profile || profile == NULL) {
		pr_err("%s: ERROR: NULL profile was passed to new_profile()\n", DEVICE_NAME);
		return -1;
	}

	// Increments profiles_created, and stores it as the identifier
	profiles_created++;
	profile->identifier = profiles_created;

	profile->normal = 0;  // We just started - not normal yet!
	profile->frozen = 0;
	profile->normal_time = 0;
	profile->anomalies = 0;
	profile->length = pH_default_looklen;
	profile->count = 0;
	//pr_err("%s: Got here 1 (new_profile)\n", DEVICE_NAME);

	// Allocates memory for the lock
	profile->lock = kmalloc(sizeof(spinlock_t), GFP_ATOMIC);
	if (!(profile->lock) || profile->lock == NULL) {
		pr_err("%s: Unable to allocate memory for profile->lock in new_profile()\n", DEVICE_NAME);
		vfree(profile);
		profile = NULL;
		return -ENOMEM;
	}
	spin_lock_init(profile->lock);
	spin_lock_init(&(profile->freeing_lock));
	//pr_err("%s: Got here 2 (new_profile)\n", DEVICE_NAME);

	profile->train.sequences = 0;
	profile->train.last_mod_count = 0;
	profile->train.train_count = 0;
	//profile->train.current_page = 0;
	//profile->train.count_page = 0;

	// Initializes entry array to NULL
	for (i=0; i<PH_NUM_SYSCALLS; i++) {
	    profile->train.entry[i] = NULL;
	}

	/*
	for (i=0; i<PH_MAX_PAGES; i++) {
	    profile->train.pages[i] = NULL;
	}
	*/

	profile->test = profile->train;
	//pr_err("%s: Got here 3 (new_profile)\n", DEVICE_NAME);

	profile->next = NULL;
	pH_refcount_init(profile, 0);
	profile->filename = filename;
	//pr_err("%s: Got here 4 (new_profile)\n", DEVICE_NAME);

	//pH_open_seq_logfile(profile);

	// Add this new profile to the hashtable
	//hash_add(profile_hashtable, &profile->hlist, pid_vnr(task_tgid(current)));
	
	// Add this new profile to the llist
	//pr_err("%s: Locking profile list in new_profile on line 460\n", DEVICE_NAME);
	//preempt_disable();
	spin_lock(&pH_profile_list_sem);
	add_to_profile_llist(profile);
	spin_unlock(&pH_profile_list_sem);
	//preempt_enable();
	//pr_err("%s: Unlocking profile list in new_profile on line 462\n", DEVICE_NAME);
	//pr_err("%s: Got here 5 (new_profile) returning...\n", DEVICE_NAME);

	return 0;
}

/*
// Adds a syscall to the linked list in its pH_task_struct
void add_to_my_syscall_llist(pH_task_struct* t, my_syscall* s) {
	//pr_err("%s: In add_to_my_syscall_llist\n", DEVICE_NAME);
	
	if (t->syscall_llist == NULL) {
		t->syscall_llist = s;
		s->next = NULL;
	}
	else {
		s->next = t->syscall_llist;
		t->syscall_llist = s;
	}
}
*/

// One issue with this function is if the process_id goes out of use or is reused while the lock
// is held, it might return an incorrect result. Perhaps this is why my code is crashing.
pH_task_struct* llist_retrieve_process(int process_id) {
	pH_task_struct* iterator = NULL;
	
	//pr_err("%s: In llist_retrieve_process\n", DEVICE_NAME);
	
	ASSERT(spin_is_locked(&pH_task_struct_list_sem));
	//ASSERT(!spin_is_locked(&pH_profile_list_sem));
	
	iterator = pH_task_struct_list;
	
	// Checks to see if this function can execute in this instance
	if (!module_inserted_successfully || !pH_aremonitoring) {
		pr_err("%s: ERROR: llist_retrieve_process called before module has been inserted correctly\n", DEVICE_NAME);
		return NULL;
	}
	
	//pr_err("%s: In llist_retrieve_process\n", DEVICE_NAME);

	if (pH_task_struct_list == NULL) {
		return NULL;
	}
	
	//spin_lock(&pH_task_struct_list_sem);
	do {
		if (iterator->process_id == process_id) {
			//pr_err("%s: Found it! Returning\n", DEVICE_NAME);
			return iterator;
		}
		iterator = iterator->next;
	} while (iterator);
	//spin_unlock(&pH_task_struct_list_sem);
	
	//pr_err("%s: Process %d not found\n", DEVICE_NAME, process_id);
	return NULL;
}

void stack_push(pH_task_struct*, pH_seq*);

// Initializes a new pH_seq and then adds it to the stack of pH_seqs
int make_and_push_new_pH_seq(pH_task_struct* process) {
	pH_profile* profile;
	pH_seq* new_sequence;
	
	ASSERT(process != NULL);
	
	profile = process->profile;
	pH_refcount_inc(profile);
	
	// Checks for NULL profile
	if (!profile || profile == NULL) {
		pr_err("%s: profile is NULL in make_and_push_new_pH_seq\n", DEVICE_NAME);
		return -1;
	}
	
	// Allocates space for the new pH_seq
	new_sequence = kmalloc(sizeof(pH_seq), GFP_ATOMIC);
	if (!new_sequence || new_sequence == NULL) {
		pr_err("%s: Unable to allocate space for new_sequence in make_and_push_new_pH_seq\n", DEVICE_NAME);
		pH_refcount_dec(profile);
		return -ENOMEM;
	}
	
	// Initialize the new pH_seq and push it onto the stack
	//pr_err("%s: Initializing new_sequence in make_and_push_new_pH_seq...\n", DEVICE_NAME);
	new_sequence->next = NULL;
	new_sequence->prev = NULL;
	//pr_err("%s: Set new_sequence->next to NULL\n", DEVICE_NAME);
	new_sequence->length = profile->length;
	//pr_err("%s: Set new_sequence->length to %d\n", DEVICE_NAME, profile->length);
	new_sequence->last = profile->length - 1;
	//pr_err("%s: Set new_sequence->last to %d\n", DEVICE_NAME, profile->length - 1);
	stack_push(process, new_sequence);
	//pr_err("%s: Pushed new_sequence\n", DEVICE_NAME);
	//pr_err("%s: Exiting make_and_push_new_pH_seq\n", DEVICE_NAME);
	pH_refcount_dec(profile);
	return 0;
}

void free_pH_task_struct(pH_task_struct*);

/*
bool comm_matches(char* comm_from_pH_task_struct) {
	struct task_struct* t;
	
	for_each_process(t) {
		if (strcmp(t->comm, comm_from_pH_task_struct)) return TRUE;
	}
	
	return FALSE;
}

void clean_processes(void) {
	pH_task_struct* iterator;
	char* string_to_compare;
	char* temp;
	
	pr_err("%s: In clean_process\n", DEVICE_NAME);
	
	for (iterator = pH_task_struct_list; iterator != NULL; iterator = iterator->next) {
		pr_err("%s: In for\n", DEVICE_NAME);
		if (iterator->profile == NULL) continue;
		
		for (string_to_compare = iterator->profile->filename; 
			string_to_compare != '\0';
			string_to_compare = string_to_compare++)
		{
			if (*string_to_compare == '/') temp = string_to_compare + 1;
		}
		string_to_compare = temp;
		return; // Temp return
		
		if (!comm_matches(string_to_compare)) {
			pr_err("%s: Removing element...\n", DEVICE_NAME);
			free_pH_task_struct(iterator);
			pr_err("%s: Got here 1\n", DEVICE_NAME);
			iterator = iterator->prev;
			pr_err("%s: Got here 2\n", DEVICE_NAME);
		}
	}
}
*/

/*
void clean_processes(void) {
	pH_task_struct* iterator;
	
	pr_err("%s: In clean_process\n", DEVICE_NAME);
	
	for (iterator = pH_task_struct_list; iterator != NULL; iterator = iterator->next) {
		if (iterator->task_struct == NULL) {
			if (iterator == pH_task_struct_list) {
				pr_err("%s: Got here 1\n", DEVICE_NAME);
				free_pH_task_struct(iterator);
				pr_err("%s: Got here 2\n", DEVICE_NAME);
				iterator = pH_task_struct_list;
				pr_err("%s: Got here 3\n", DEVICE_NAME);
				if (iterator == NULL) {
					return;
				}
			}
			else {
				pr_err("%s: Got here 4\n", DEVICE_NAME);
				iterator = iterator->prev;
				pr_err("%s: Got here 5\n", DEVICE_NAME);
				free_pH_task_struct(iterator->next);
				pr_err("%s: Got here 6\n", DEVICE_NAME);
			}
		}
		else {
			pr_err("%s: comm is %s\n", DEVICE_NAME, iterator->task_struct->comm);
		}
	}
}
*/

// Returns true if a message was received from the user, false otherwise
bool message_received(void) {
	if (message == NULL || message[0] == '\0') {
		return FALSE;
	}
	else return TRUE;
}

// Retruns the task_struct of the userspace app
struct task_struct* get_userspace_task_struct(void) {
	if (message_received()) {
		return pid_task(find_pid_ns(userspace_pid, &init_pid_ns), PIDTYPE_PID);
	}
	return NULL;
}

int send_signal(int signal_to_send) {
	int ret;
	struct task_struct* t;
	
	t = get_userspace_task_struct();
	if (!t) {
		pr_err("%s: No such PID", DEVICE_NAME);
		return -ENODEV;
	}
	
	ret = send_sig(signal_to_send, t, SIGNAL_PRIVILEGE);
	if (ret < 0) {
		pr_err("%s: Unable to send signal\n", DEVICE_NAME);
		return ret;
	}
	
	/*
	// Switch statement to help with printing out signal sent to userspace
	char signal_sent[8];
	switch (signal_to_send) {
		case SIGSTOP:
			strcpy(signal_sent, "SIGSTOP");
			break;
		case SIGCONT:
			strcpy(signal_sent, "SIGCONT");
			break;
		case SIGTERM:
			strcpy(signal_sent, "SIGTERM");
			break;
		case SIGKILL:
			strcpy(signal_sent, "SIGKILL");
			break;
		default:
			printk(KERN_INFO "%s: %d signal sent to user space process", DEVICE_NAME, signal_to_send);
			return 0;
	}

	//printk(KERN_INFO "%s: %s signal sent to user space process", DEVICE_NAME, signal_sent);
	*/
	return 0;
}

// Function prototypes for process_syscall()
inline void pH_append_call(pH_seq*, int);
inline void pH_train(pH_task_struct*);
//void stack_print(pH_task_struct*);

// Processes a system call
int process_syscall(long syscall) {
	pH_task_struct* process;
	//my_syscall* new_syscall;
	pH_profile* profile;
	int ret;
	
	// Boolean checks
	if (!done_waiting_for_user) return 0;
	
	if (!module_inserted_successfully) return 0;
	
	if (!pH_aremonitoring) return 0;
	
	if (!pH_task_struct_list || pH_task_struct_list == NULL) return 0;

	//pr_err("%s: In process_syscall\n", DEVICE_NAME);
	
	// Check to see if a process went out of use
	//clean_processes(); // Temporarily commented out since the module isn't working at the moment
	
	// Retrieve process
	//preempt_disable();
	spin_lock(&pH_task_struct_list_sem);
	process = llist_retrieve_process(pid_vnr(task_tgid(current)));
	spin_unlock(&pH_task_struct_list_sem);
	//preempt_enable();
	if (!process) {
		// Ignore this syscall
		ret = 0;
		goto exit_before_profile;
	}
	//pr_err("%s: syscall=%d\n", DEVICE_NAME, syscall);
	//pr_err("%s: Retrieved process successfully\n", DEVICE_NAME);
	//pr_err("\n\n\n\n\n\n\n\%s: No really, the process was retrieved successfully\n*****************\n*****************\n*****************\n", DEVICE_NAME);
	
	profile = process->profile; // Store process->profile in profile for shorter reference
	pH_refcount_inc(profile);
	
	if (!profile || profile == NULL) {
		pr_err("%s: pH_task_struct corrupted: No profile\n", DEVICE_NAME);
		ret = -1;
		goto exit;
	}
	/*
	if (profile->filename == NULL) {
		pr_err("%s: profile is corrupted in process_syscall: NULL profile->filename\n", DEVICE_NAME);
		//pr_err("%s: Quitting early in process_syscall\n", DEVICE_NAME);
		//module_inserted_successfully = FALSE;
		return -1;
	}
	*/
	//pr_err("%s: Retrieved profile successfully\n", DEVICE_NAME);
	
	// Check to see if this profile is still in use
	if (!pH_profile_in_use(profile) || !(profile->lock) || profile->lock == NULL) {
		pr_err("%s: profile->lock is NULL in process_syscall\n", DEVICE_NAME);
		//vfree(profile); // Don't bother freeing, since this is the only remaining pointer
		//profile = NULL;
		ret = -1;
		goto exit;
	}
	
	/*
	if (spin_is_locked(&(profile->freeing_lock))) {
		ret = -1;
		goto exit;
	}
	*/
	
	//pr_err("%s: Locking profile->lock\n", DEVICE_NAME);
	spin_lock(profile->lock); // Grabs the lock to this profile
	
	if (profile->lock == NULL) {
		pr_err("%s: ERROR: Somehow the profile->lock was NULL anyway\n", DEVICE_NAME);
		goto exit;
	}
	
	if (profile == NULL || !pH_profile_in_use(profile)) {
		spin_unlock(profile->lock);
		ret = -1;
		goto exit;
	}
	
	if (process && (process->seq) == NULL) {
		pH_seq* temp = (pH_seq*) kmalloc(sizeof(pH_seq), GFP_ATOMIC);
		if (!temp) {
			pr_err("%s: Unable to allocate memory for temp in process_syscall\n", DEVICE_NAME);
			if (profile->lock == NULL) {
				ret = -1;
				goto exit;
			}
			spin_unlock(profile->lock);
			ret = -ENOMEM;
			goto exit;
		}

		temp->next = NULL;
		temp->length = profile->length;
		temp->last = profile->length - 1;
		
		//pr_err("%s: Got here 1\n", DEVICE_NAME);
		//process->seq = temp;
		//INIT_LIST_HEAD(&temp->seqList);
		if (process) stack_push(process, temp);
		//pr_err("%s: Got here 2\n", DEVICE_NAME);
		INIT_LIST_HEAD(&temp->seqList);
		//pr_err("%s: Successfully allocated memory for temp in process_syscall\n", DEVICE_NAME);
	}
	
	if (process) process->count++;
	if (process) pH_append_call(process->seq, syscall);
	//pr_err("%s: Successfully appended call %ld\n", DEVICE_NAME, syscall);
	
	//pr_err("%s: &(profile->count) = %p\n", DEVICE_NAME, &(profile->count));
	profile->count++;
	//pr_err("%s: profile->count = %d\n", DEVICE_NAME, profile->count);
	if (profile->lock == NULL) {
		ret = -1;
		goto exit;
	}
	spin_unlock(profile->lock);
	
	//pr_err("%s: process = %p %d\n", DEVICE_NAME, process, process != NULL);
	///pr_err("%s: profile = %p %d\n", DEVICE_NAME, profile, profile != NULL);
	
	if (process) pH_train(process);
	else {
		pr_err("%s: ERROR: process is NULL\n", DEVICE_NAME);
		ret = -1;
		goto exit;
	}
	//pr_err("%s: Trained process\n", DEVICE_NAME);
	
	/* // Since this is just for seeing if my code seems to be working, I don't need it
	// Allocate space for new_syscall
	new_syscall = kmalloc(sizeof(my_syscall), GFP_ATOMIC);
	if (!new_syscall) {
		pr_err("%s: Unable to allocate space for new_syscall\n", DEVICE_NAME);
		kfree(process->seq);
		ret = -ENOMEM;
		goto exit;
	}
	//pr_err("%s: Successfully allocated space for new_syscall\n", DEVICE_NAME);
	
	// Add new_syscall to the linked list of syscalls
	new_syscall->syscall_num = syscall;
	add_to_my_syscall_llist(process, new_syscall);
	*/
	
	//pr_err("%s: Finished processing syscall %ld\n", DEVICE_NAME, syscall);
	
	ret = 0;

exit_before_profile:
	return ret;

exit:
	pH_refcount_dec(profile);
	return ret;
}

// Adds a process to the linked list of processes
void add_process_to_llist(pH_task_struct* t) {
	//pr_err("%s: In add_process_to_llist\n", DEVICE_NAME);

	ASSERT(spin_is_locked(&pH_task_struct_list_sem));
	//ASSERT(!spin_is_locked(&pH_profile_list_sem));
	
	// Checks for NULL
	if (!t || t == NULL) {
		pr_err("%s: Received NULL pH_task_struct in add_process_to_llist\n", DEVICE_NAME);
		return;
	}
	
	//spin_lock(&pH_task_struct_list_sem);
	if (pH_task_struct_list == NULL) {
		pH_task_struct_list = t;
		t->next = NULL;
		t->prev = NULL;
	}
	else {
		/* // Old implementation
		pH_task_struct* iterator = pH_task_struct_list;
		
		while (iterator->next) iterator = iterator->next;
		
		iterator->next = t;
		t->next = NULL;
		*/
		
		t->next = pH_task_struct_list;
		pH_task_struct_list = t;
		t->prev = NULL;
		t->next->prev = t;
	}
	//spin_unlock(&pH_task_struct_list_sem);
}

// Returns a pH_profile, given a filename
pH_profile* retrieve_pH_profile_by_filename(char* filename) {
	ASSERT(spin_is_locked(&pH_profile_list_sem));
	//ASSERT(!spin_is_locked(&pH_task_struct_list_sem));
	
	pH_task_struct* process_list_iterator;
	pH_profile* profile_list_iterator = pH_profile_list;
	
	if (pH_profile_list == NULL) {
		pr_err("%s: pH_profile_list is NULL\n", DEVICE_NAME);
		return NULL;
	}
	//pr_err("%s: pH_profile_list is not NULL\n", DEVICE_NAME);
	
	// Search through profile list
	//spin_lock(&pH_profile_list_sem);
	do {
		//pr_err("%s: Filename is [%s]\n", DEVICE_NAME, profile_list_iterator->filename);
		if (strcmp(filename, profile_list_iterator->filename) == 0) {
			//pr_err("%s: Found it! Returning\n", DEVICE_NAME);
			//spin_unlock(&pH_profile_list_sem);
			return profile_list_iterator;
		}
		
		profile_list_iterator = profile_list_iterator->next;
		//pr_err("%s: Iterating\n", DEVICE_NAME);
	} while (profile_list_iterator);
	//spin_unlock(&pH_profile_list_sem);
	
	/*
	// If searching through profile list fails, search through process list
	// (this should be removed, as this should never need to happen)
	process_list_iterator = pH_task_struct_list;
	do {
		if (strcmp(filename, process_list_iterator->profile->filename) == 0) {
			return process_list_iterator->profile;
		}
		process_list_iterator = process_list_iterator->next;
	} while (process_list_iterator);
	*/
	
	//pr_err("%s: No matching profile was found\n", DEVICE_NAME);
	return NULL;
}

/**
 * This is where the definition of handle_new_process used to rest. The see the definition again,
 * go to "wells/Documents/archive/km (archive from August 10, 2017 at 1110 hours.c".
 */

void stack_pop(pH_task_struct*);

// Handler function for execves
// Since I changed my goto labels to only exit, I must always print the issue before jumping to that
// label
static long jsys_execve(const char __user *filename,
	const char __user *const __user *argv,
	const char __user *const __user *envp)
{
	char* path_to_binary;
	int current_process_id;
	int list_length;
	pH_task_struct* process;
	pH_profile* profile;
	int ret;
	bool already_had_process = FALSE;

	// Boolean checks
	if (!done_waiting_for_user) goto exit;
	
	if (!module_inserted_successfully) goto exit;
	
	if (!pH_aremonitoring) goto exit;

	pr_err("%s: In jsys_execve\n", DEVICE_NAME);
	
	current_process_id = pid_vnr(task_tgid(current)); // Grab the process ID right now
	
	//pr_err("%s: List length at start is %d\n", DEVICE_NAME, pH_task_struct_list_length());
	
	//clean_processes();
	//pr_err("%s: Back from clean_processes()\n", DEVICE_NAME);
	
	//pr_err("%s: Calling llist_retrieve_process from jsys_execve\n", DEVICE_NAME);
	//preempt_disable();
	spin_lock(&pH_task_struct_list_sem);
	process = llist_retrieve_process(current_process_id);
	spin_unlock(&pH_task_struct_list_sem);
	//preempt_enable();
	if (!process || process == NULL) {
		pr_err("%s: Unable to find process in jsys_execve\n", DEVICE_NAME);
		pr_err("%s: Continuing anyway...\n", DEVICE_NAME);
		
		// Allocate memory for this process
		process = kmalloc(sizeof(pH_task_struct), GFP_ATOMIC);
		if (!process) {
			pr_err("%s: Unable to allocate memory for process\n", DEVICE_NAME);
			goto exit;
		}
		pr_err("%s: Successfully allocated memory for process\n", DEVICE_NAME);
		
		// Initialization for entirely new process - this might not be quite correct
		process->process_id = current_process_id;
		process->task_struct = current;
		process->pid = task_pid(current);
		pr_err("%s: Pre-initialized entirely new process\n", DEVICE_NAME);
	}
	else {
		already_had_process = TRUE;
		pH_refcount_dec(process->profile);
		pr_err("%s: Decremented old profile refcount\n", DEVICE_NAME);
	}
	
	// Allocate space for path_to_binary
	path_to_binary = kmalloc(sizeof(char) * 4000, GFP_ATOMIC);
	if (!path_to_binary) {
		pr_err("%s: Unable to allocate memory for path_to_binary\n", DEVICE_NAME);
		goto exit;
	}
	pr_err("%s: Successfully allocated memory for path_to_binary\n", DEVICE_NAME);
	
	// Copy memory from userspace to kernel land
	copy_from_user(path_to_binary, filename, sizeof(char) * 4000);
	pr_err("%s: path_to_binary = [%s]\n", DEVICE_NAME, path_to_binary);
	
	// Checks to see if path_to_binary is okay - perhaps move this to handle_new_process()
	if (!path_to_binary || path_to_binary == NULL || strlen(path_to_binary) < 1 || 
		!(*path_to_binary == '~' || *path_to_binary == '.' || *path_to_binary == '/'))
	{
		pr_err("%s: In jsys_execve with corrupted path_to_binary: [%s]\n", DEVICE_NAME, path_to_binary);
		goto corrupted_path_to_binary;
	}
	pr_err("%s: My code thinks path_to_binary is not corrupted\n", DEVICE_NAME);
	
	// Emtpies stack of pH_seqs
	while (already_had_process && process->seq != NULL) {
		//pr_err("%s: In while %d\n", DEVICE_NAME, i);
		stack_pop(process);
		//pr_err("%s: &process = %p\n", DEVICE_NAME, &process);
		//pr_err("%s: After stack_pop(process);\n", DEVICE_NAME);
	}
	pr_err("%s: Emptied stack of pH_seqs\n", DEVICE_NAME);
	
	// Since we are using an existing pH_task_struct, the task_struct, pid, etc. are already
	// initialized - instead we want to wipe everything else
	//pH_reset_ALF(this_process);
	process->seq = NULL;
	//spin_lock_init(&(this_process->pH_seq_stack_sem));
	process->syscall_llist = NULL;
	process->delay = 0;
	process->count = 0;
	pr_err("%s: Initialized process\n", DEVICE_NAME);
	
	// Grab the profile from memory - if this fails, I would want to do a read, but since I am not
	// implementing that right now, then make a new profile
	pr_err("%s: Attempting to retrieve profile...\n", DEVICE_NAME);
	pr_err("%s: Locking profile list in jsys_execve on line 1070\n", DEVICE_NAME);
	//preempt_disable();
	spin_lock(&pH_profile_list_sem);
	profile = retrieve_pH_profile_by_filename(path_to_binary);
	spin_unlock(&pH_profile_list_sem);
	//preempt_enable();
	pr_err("%s: Unlocking profile list in jsys_execve on line 1072\n", DEVICE_NAME);
	pr_err("%s: Profile found: %s\n", DEVICE_NAME, profile != NULL ? "yes" : "no");
	
	/*
	// If there is no corresponding profile, make a new one - this should actually start a read
	// request, once I have got to implementing that
	if (!profile || profile == NULL) {
		profile = __vmalloc(sizeof(pH_profile), GFP_ATOMIC, PAGE_KERNEL);
		if (!profile) {
			pr_err("%s: Unable to allocate memory for profile in handle_new_process\n", DEVICE_NAME);
			goto exit;
		}
		
		new_profile(profile, path_to_binary);
		pr_err("%s: Made new profile for [%s]\n", DEVICE_NAME, path_to_binary);
		
		if (!profile || profile == NULL) {
			pr_err("%s: new_profile() made a corrupted or NULL profile\n", DEVICE_NAME);
		}
	}
	else {
		kfree(path_to_binary);
		path_to_binary = NULL;
	}
	*/
	
	if (!profile || profile == NULL) {
		add_to_read_filename_queue(path_to_binary);
		pr_err("%s: path_to_binary was added to the read filename queue\n", DEVICE_NAME);
		strcpy(output_string, READ_PROFILE_FROM_DISK); // Maybe I shouldn't do this if there is another command already
		strcat(output_string, path_to_binary);
		
		ret = send_signal(SIGCONT);
		if (ret < 0) {
			pr_err("%s: The userspace process was not woken for some reason\n", DEVICE_NAME);
			ASSERT(ret >= 0);
			return ret; // Maybe I will want to handle this more drastically
		}
		pr_err("%s: The userspace process should have received a SIGCONT signal\n", DEVICE_NAME);
		
		spin_lock(&execve_count_lock);
		pr_err("%s: Locked execve_count_lock\n", DEVICE_NAME);
	}
	else {
		kfree(path_to_binary);
		path_to_binary = NULL;
	}
	
	if (profile != NULL) {
		process->profile = profile;
		pH_refcount_inc(profile);
		ASSERT(get_refcount(profile) == 1); // I should perform this test whenever I first create a profile
	}
	
	if (!already_had_process) {
		//preempt_disable();
		spin_lock(&pH_task_struct_list_sem);
		add_process_to_llist(process);
		spin_unlock(&pH_task_struct_list_sem);
		//preempt_enable();
		pr_err("%s: process has been added to the llist\n", DEVICE_NAME);
	}
	
	successful_jsys_execves++;
	pr_err("%s: Incremented successful_jsys_execves\n", DEVICE_NAME);
	
	pr_err("%s: Returning from jsys_execve...\n", DEVICE_NAME);
	
	jprobe_return();
	return 0;
	
exit:
	kfree(path_to_binary);
	path_to_binary = NULL;
	if (process != NULL) {
		pr_err("%s: Calling free_pH_task_struct from jsys_execve()\n", DEVICE_NAME);
		free_pH_task_struct(process);
	}
	process = NULL;
	
	jprobe_return();
	return 0;
	
corrupted_path_to_binary:
	kfree(path_to_binary);
	path_to_binary = NULL;
	process = NULL;
	
	jprobe_return();
	return 0;
}

/*
void print_llist(void) {
	pH_task_struct* iterator = pH_task_struct_list;
	
	if (pH_task_struct_list == NULL) {
		return;
	}
	
	pr_err("%s: Printing linked list...\n", DEVICE_NAME);
	do {
		pr_err("%s: Output: %ld %s\n", DEVICE_NAME, iterator->process_id, iterator->profile->filename);
		
		iterator = iterator->next;
	} while (iterator);
}
*/

/*
static long j_do_fork(unsigned long clone_flags,
	unsigned long stack_start,
	unsigned long stack_size,
	int __user *parent_tidptr,
	int __user *child_tidptr,
	unsigned long tls)
{
	pH_task_struct* p;
	
	if (!module_inserted_successfully) return 0;
	
	p = kmalloc(sizeof(pH_task_struct), GFP_ATOMIC);
	if (!p) {
		pr_err("%s: Unable to allocate memory in j_do_fork\n", DEVICE_NAME);
		return -ENOMEM;
	}
	
	copy_from_user(p->tidptr, child_tidptr, sizeof(int));
	p->task_struct = NULL;
	p->pid = NULL;
	p->process_id = -1; // This can't be initialized quite yet
	//pH_reset_ALF(this_process);
	p->seq = NULL;
	//spin_lock_init(&(this_process->pH_seq_stack_sem));
	p->syscall_llist = NULL;
	p->delay = -1;
	p->count = -1;
	pr_err("%s: Initialized process\n", DEVICE_NAME);
	
	add_process_to_llist(child_process);
}
*/

// Struct required for all kretprobe structs
struct my_kretprobe_data {
	ktime_t entry_stamp;
};

// Think about what to do on for with a NULL profile
int handle_new_process_fork(char* path_to_binary, pH_profile* profile, int process_id) {
	ASSERT(profile != NULL);
	
	pH_refcount_inc(profile);
	
	pH_task_struct* this_process;
	
	//pr_err("%s: In handle_new_process for %d %s\n", DEVICE_NAME, process_id, path_to_binary);
	
	// Allocate memory for this process
	this_process = kmalloc(sizeof(pH_task_struct), GFP_ATOMIC);
	if (!this_process) {
		pr_err("%s: Unable to allocate memory for this process\n", DEVICE_NAME);
		goto no_memory;
	}
	
	// Initialize this process - check with Anil to see if these are the right values to initialize it to
	this_process->task_struct = current;
	this_process->pid = task_pid(current); // Perhaps I am calling the wrong function here
	this_process->process_id = process_id;
	//pH_reset_ALF(this_process);
	this_process->seq = NULL;
	//spin_lock_init(&(this_process->pH_seq_stack_sem));
	this_process->syscall_llist = NULL;
	this_process->delay = 0;
	this_process->count = 0;
	//pr_err("%s: Initialized process\n", DEVICE_NAME);
	
	this_process->profile = profile; // Put this profile in the pH_task_struct struct
	pH_refcount_inc(profile);

	//preempt_disable();
	spin_lock(&pH_task_struct_list_sem);
	add_process_to_llist(this_process); // Add this process to the list of processes
	spin_unlock(&pH_task_struct_list_sem);
	//preempt_enable();
	//pr_err("%s: Added this process to llist\n", DEVICE_NAME);
	
	return 0;

no_memory:	
	pr_err("%s: Ran out of memory\n", DEVICE_NAME);
	
	kfree(path_to_binary);
	path_to_binary = NULL;
	free_pH_task_struct(this_process); // Potentially at this point the process may not be in the llist, which may cause issues
	this_process = NULL;
	
	return -ENOMEM;
}

// For this to work, I might need to make the stack of pH_seq's doubly-linked
int copy_task_struct_data(pH_task_struct* old, pH_task_struct* new) {
	pH_seq* iterator;
	int i;
	
	ASSERT(old != NULL);
	ASSERT(new != NULL);
	
	for (iterator = old->seq; iterator != NULL; iterator = iterator->next) {
		; // This will get me to the last non-null element
	}
	
	for (; iterator != NULL; iterator = iterator->prev) {
		make_and_push_new_pH_seq(new);
		new->seq->last = old->seq->last;
		new->seq->length = old->seq->length;

		for (i = 0; i < PH_MAX_SEQLEN; i++) {
			new->seq->data[i] = old->seq->data[i];
		}
		
		ASSERT(new->seq != NULL);
		
		// Do I want to initialize the list_head seqList?
	}
}

// Currently a child process can only be handled if the pH_task_struct for the parent
// process is still in memory. This is because pH_profiles require the absolute path
// to the binary file, which I currently only know how to retrieve from sys_execve calls.
static int fork_handler(struct kretprobe_instance* ri, struct pt_regs* regs) {
	int retval;
	pH_task_struct* parent_process;
	pH_task_struct* child_process;
	char* path_to_binary;
	pH_profile* profile;
	
	// Boolean check
	if (!done_waiting_for_user) return 0;
	
	if (!module_inserted_successfully) return 0;
	
	//pr_err("%s: In fork_handler\n", DEVICE_NAME);
	
	retval = regs_return_value(regs);
	
	if (retval < 0) {
		// fork() returned error - did not create child process
		return retval;
	}
	
	//preempt_disable();
	spin_lock(&pH_task_struct_list_sem);
	parent_process = llist_retrieve_process(pid_vnr(task_tgid(current)));
	spin_unlock(&pH_task_struct_list_sem);
	//preempt_enable();
	if (!parent_process || parent_process == NULL) {
		//pr_err("%s: In fork_handler with NULL parent_process\n", DEVICE_NAME);
		return -1;
	}
	
	profile = parent_process->profile;
	if (!profile || profile == NULL) {
		pr_err("%s: In fork_handler with NULL parent_process->profile\n", DEVICE_NAME);
		return -1;
	}
	pH_refcount_inc(profile);
	
	path_to_binary = profile->filename;
	
	// Checks to see if path_to_binary is okay - perhaps move this to handle_new_process()
	if (!path_to_binary || path_to_binary == NULL || strlen(path_to_binary) < 1 || 
		!(*path_to_binary == '~' || *path_to_binary == '.' || *path_to_binary == '/'))
	{
		//pr_err("%s: In fork_handler with corrupted path_to_binary: [%s]\n", DEVICE_NAME, path_to_binary);
		pH_refcount_dec(profile);
		return -1;
	}
	
	// Handle the new process
	// I will want to change this out so that I copy memory over from the parent pH_task_struct
	// to the new pH_task_struct that I am creating
	handle_new_process_fork(path_to_binary, profile, retval);
	
	copy_task_struct_data(parent_process, child_process);
	
	pH_refcount_dec(profile);
	
	//pr_err("%s: Got through all of fork_handler\n", DEVICE_NAME);
	
	return 0;
}

static struct kretprobe fork_kretprobe = {
	.handler = fork_handler,
	.data_size = sizeof(struct my_kretprobe_data),
	.maxactive = 20,
};

/*
static int copy_process_handler(struct kretprobe_instance* ri, struct pt_regs* regs) {
	task_struct* retval;
	pH_task_struct* child_process;
	pH_profile* profile;
	
	retval = regs_return_value(regs);
	
	if (retval < 0 || retval == NULL) {
		return -1;
	}
	
	// Retrieve binary by using current to retrieve PID, and then grab the task struct then binary from there
	parent_process = llist_retrieve_process(pid_vnr(task_tgid(current)));
	if (!parent_process || parent_process == NULL) {
		//pr_err("%s: In copy_process_handler with NULL parent_process\n", DEVICE_NAME);
		return -1;
	}
	
	child_process = kmalloc(sizeof(pH_task_struct), GFP_ATOMIC);
	if (!child_process) {
		pr_err("%s: Unable to allocate memory for child_process\n", DEVICE_NAME);
		return -ENOMEM;
	}
	
	// To keep this simple, I do not copy any values over
	child_process->task_struct = retval;
	child_process->pid = task_pid(retval); // Perhaps I am calling the wrong function here
	child_process->process_id = -1; // This can't be initialized quite yet
	//pH_reset_ALF(this_process);
	child_process->seq = NULL;
	//spin_lock_init(&(this_process->pH_seq_stack_sem));
	child_process->syscall_llist = NULL;
	child_process->delay = 0;
	child_process->count = 0;
	pr_err("%s: Initialized process\n", DEVICE_NAME);
	
	profile = parent_process->profile;
	if (!profile || profile == NULL) {
		//pr_err("%s: In fork_handler with NULL parent_process->profile\n", DEVICE_NAME);
		return -1;
	}
	child_process->profile = profile;
	pH_refcount_inc(profile);
	
	return 0;
}
*/

/*
static int exit_handler(struct kretprobe_instance* ri, struct pt_regs* regs) {
	int retval;
	ktime_t now;
	pH_task_struct* process;
	
	if (!module_inserted_successfully) return 0;
	
	//pr_err("%s: In exit_handler for %d\n", DEVICE_NAME, pid_vnr(task_tgid(current)));
	
	process = llist_retrieve_process(pid_vnr(task_tgid(current)));
	
	if (process == NULL) return 0;
	
	//pr_err("%s: In exit_handler for %d %s\n", DEVICE_NAME, pid_vnr(task_tgid(current)), process->profile->filename);
	
	retval = regs_return_value(regs);
	now = ktime_get();
	
	free_pH_task_struct(process);
	
	return 0;
}

static struct kretprobe exit_kretprobe = {
	.handler = exit_handler,
	.data_size = sizeof(struct my_kretprobe_data),
	.maxactive = 20,
};

static int sys_rt_sigreturn_handler(struct kretprobe_instance* ri, struct pt_regs* regs) {
	pH_task_struct* process;
	
	if (!module_inserted_successfully) return 0;
	
	if (current == last_task_struct_in_sigreturn) {
		pr_err("%s: The task structs are the same\n", DEVICE_NAME);
	}
	else {
		pr_err("%s: The task structs are different\n", DEVICE_NAME);
	}
	
	pr_err("%s: In sys_rt_sigreturn_handler for %d\n", DEVICE_NAME, pid_vnr(task_tgid(current)));
	
	process = llist_retrieve_process(pid_vnr(task_tgid(current)));
	
	//if (process == NULL) return 0;
	
	// Perhaps I should look at TASK_WAKEKILL as well
	// Can a zombie process be unzombified?
	if (current->exit_state == EXIT_DEAD || current->exit_state == EXIT_ZOMBIE || current->state == TASK_DEAD) {
		pr_err("%s: Freeing task_struct...\n", DEVICE_NAME);
		free_pH_task_struct(process);
	}
	
	if (sigismember(&current->pending.signal, SIGKILL)) {
		pr_err("%s: Freeing task_struct...\n", DEVICE_NAME);
		free_pH_task_struct(process);
	}
	else {
		pr_err("%s: SIGKILL is not a member of current->pending.signal\n", DEVICE_NAME);
	}
	
	return 0;
}

static struct kretprobe sys_rt_sigreturn_kretprobe = {
	.handler = sys_rt_sigreturn_handler,
	.data_size = sizeof(struct my_kretprobe_data),
	.maxactive = 20,
};
*/

static int do_execveat_common_handler(struct kretprobe_instance* ri, struct pt_regs* regs) {
	int retval;
	pH_task_struct* process;
	
	if (!done_waiting_for_user) return 0;
	
	if (!module_inserted_successfully) return 0;
	
	pr_err("%s: In do_execveat_common_handler\n", DEVICE_NAME);
	
	retval = regs_return_value(regs);
	
	if (retval < 0) {
		pr_err("%s: execve failed\n", DEVICE_NAME);
		
		//preempt_disable();
		spin_lock(&pH_task_struct_list_sem);
		process = llist_retrieve_process(pid_vnr(task_tgid(current)));
		spin_unlock(&pH_task_struct_list_sem);
		//preempt_enable();
		pr_err("%s: Calling free_pH_task_struct from do_execveat_common_handler\n", DEVICE_NAME);
		free_pH_task_struct(process);
		process = NULL;
		
		return retval;
	}
	pr_err("%s: execve succeeded\n", DEVICE_NAME);
	
	return 0;
}

static struct kretprobe do_execveat_common_kretprobe = {
	.handler = do_execveat_common_handler,
	.data_size = sizeof(struct my_kretprobe_data),
	.maxactive = 20,
};

/*
static int do_execve_handler(struct kretprobe_instance* ri, struct pt_regs* regs) {
	int retval;
	pH_task_struct* process;
	
	if (!module_inserted_successfully) return 0;
	
	retval = regs_return_value(regs);
	
	if (retval < 0) {
		process = llist_retrieve_process(pid_vnr(task_tgid(current)));
		free_pH_task_struct(process);
		process = NULL;
		
		return retval;
	}
	
	return 0;
}

static struct kretprobe do_execve_kretprobe = {
	.handler = do_execve_handler,
	.data_size = sizeof(struct my_kretprobe_data),
	.maxactive = 20,
};
*/

static int sys_execve_return_handler(struct kretprobe_instance* ri, struct pt_regs* regs) {
	pH_task_struct* process;
	pH_profile* profile;
	
	if (!done_waiting_for_user) return 0;
	
	if (!module_inserted_successfully) return 0;
	
	pr_err("%s: In sys_execve_return_handler\n", DEVICE_NAME);
	pr_err("%s: execve_count_lock = %p\n", DEVICE_NAME, &execve_count_lock);
	pr_err("%s: pH_profile_list_sem = %p\n", DEVICE_NAME, &pH_profile_list_sem);
	pr_err("%s: output_string[2] = %p\n", DEVICE_NAME, &output_string[2]);
	pr_err("%s: output_string[2] = %s\n", DEVICE_NAME, output_string[2]);
	pr_err("%s: If all of these lines (including this one) print, then the problem is in retrieve_pH_profile_by_filename\n", DEVICE_NAME);
	
	if (!spin_is_locked(&execve_count_lock)) return 0;
	
	spin_lock(&execve_count_lock);
	spin_lock(&pH_profile_list_sem);
	profile = retrieve_pH_profile_by_filename(&output_string[2]);
	spin_unlock(&execve_count_lock);
	spin_lock(&pH_profile_list_sem);
	
	if (!profile || profile == NULL) {
		pr_err("%s: ERROR: Unable to find profile with filename [%s] in list\n", DEVICE_NAME, &output_string[2]);
		ASSERT(profile != NULL);
		return -1;
	}
	pr_err("%s: grab_profile_from_read_queue returned a profile\n", DEVICE_NAME);
	
	spin_lock(&pH_task_struct_list_sem);
	process = llist_retrieve_process(pid_vnr(task_tgid(current)));
	spin_unlock(&pH_task_struct_list_sem);
	if (!process || process == NULL) {
		pr_err("%s: Got NULL process in sys_execve_return_handler\n", DEVICE_NAME);
		return -1;
	}
	
	process->profile = profile;
	pH_refcount_inc(profile);
	ASSERT(get_refcount(profile) == 1);
	
	process_syscall(59);
	pr_err("%s: Back in sys_execve_return_handler after process_syscall\n", DEVICE_NAME);
	
	return 0;
}

static struct kretprobe sys_execve_kretprobe = {
	.handler = sys_execve_return_handler,
	.data_size = sizeof(struct my_kretprobe_data),
	.maxactive = 20,
};

// Frees profile storage
void pH_free_profile_storage(pH_profile *profile)
{   
    int i;
    
    ASSERT(profile != NULL);
    ASSERT(!pH_profile_in_use(profile));

	//pr_err("%s: In pH_free_profile_storage for %d\n", DEVICE_NAME, profile->identifier);

	// Free profile->filename
    kfree(profile->filename);
    profile->filename = NULL;
    pr_err("%s: Freed profile->filename\n", DEVICE_NAME);
    
    // Free entries
    for (i = 0; i < PH_NUM_SYSCALLS; i++) {
        if (profile->train.entry[i]) {
        	kfree(profile->train.entry[i]);
        	profile->train.entry[i] = NULL;
        }
        if (profile->test.entry[i]) {
        	kfree(profile->test.entry[i]);
        	profile->test.entry[i] = NULL;
        }
    }
    
    //pr_err("%s: Exiting pH_free_profile_storage\n", DEVICE_NAME);
}

/* // Commented out as I probably don't need this
// Returns true if the list contains a given identifier
bool profile_list_contains_identifier(int identifier) {
	pH_profile* iterator = pH_profile_list;
	
	if (pH_profile_list == NULL) {
		return FALSE;
	}
	//pr_err("%s: pH_profile_list is not NULL\n", DEVICE_NAME);
	
	do {
		if (iterator->identifier == identifier) {
			//pr_err("%s: Found it! Returning\n", DEVICE_NAME);
			
			return TRUE;
		}
		
		iterator = iterator->next;
		//pr_err("%s: Iterating\n", DEVICE_NAME);
	} while (iterator);
	
	//pr_err("%s: No matching profile was found\n", DEVICE_NAME);
	return FALSE;
}
*/

// Returns 0 on success and anything else on failure
// Calling functions (currently only pH_free_profile) MUST handle returned errors if possible
// Currently does not hold any locks, and therefore calling functions must lock appropriately
int pH_remove_profile_from_list(pH_profile *profile)
{
    pH_profile *prev_profile, *cur_profile;
    
    ASSERT(spin_is_locked(&pH_profile_list_sem));
	//ASSERT(!spin_is_locked(&pH_task_struct_list_sem));
    ASSERT(profile != NULL);
	ASSERT(!pH_profile_in_use(profile));

    //pr_err("%s: In pH_remove_profile_from_list for %d\n", DEVICE_NAME, profile->identifier);
	
	/*
	//spin_lock(&pH_profile_list_sem);
    if (pH_profile_list == NULL) {
    	err("pH_profile_list is empty (NULL) when trying to free profile %s", profile->filename);
    	//spin_unlock(&pH_profile_list_sem);
    	return -1;
    }
    else if (pH_profile_list == profile) {
    	pH_profile_list = pH_profile_list->next;
    	//spin_unlock(&pH_profile_list_sem);
    	return 0;
    }
    else {
    	prev_profile = pH_profile_list;
    	cur_profile = pH_profile_list->next;
    	while (cur_profile != NULL) {
    		if (cur_profile == profile) {
    			prev_profile->next = cur_profile->next;
    			//spin_unlock(&pH_profile_list_sem);
    			return 0;
    		}
    		
    		prev_profile = cur_profile;
            cur_profile = cur_profile->next;
    	}
    	
    	err("While freeing, couldn't find profile %s in pH_profile_list", profile->filename);
    	//spin_unlock(&pH_profile_list_sem);
    	return -1;
    }
    */
    
    if (pH_profile_list == profile) {
        pH_profile_list = profile->next;
        return 0;
    } else if (pH_profile_list == NULL) {
        err("pH_profile_list is NULL when trying to free profile %s",
            profile->filename);
        return -1;
    } else {
        prev_profile = pH_profile_list;
        cur_profile = prev_profile->next;
        while ((cur_profile != profile) && (cur_profile != NULL)) {
            prev_profile = cur_profile;
            cur_profile = prev_profile->next;
        }
        if (cur_profile == profile) {
            prev_profile->next = cur_profile->next;
            return 0;
        } else {
            err("while freeing, couldn't find profile %s in "
                "pH_profile_list", profile->filename);
            return -1;
        }
    }
}

void pH_profile_mem2disk(pH_profile*, pH_disk_profile*);

// See the big block of comment code below
// Refcounting is not required for this function
int pH_write_profile(pH_profile* profile) {
	int ret;
	pH_disk_profile* disk_profile;
	
	ASSERT(profile != NULL);
	ASSERT(!pH_profile_in_use(profile));

	pr_err("%s: In pH_write_profile for profile %d [%s]\n", DEVICE_NAME, profile->identifier, profile->filename);
	
	// Allocate space for disk_profile
	disk_profile = __vmalloc(sizeof(pH_disk_profile), GFP_ATOMIC, PAGE_KERNEL);
	if (!disk_profile) {
		pr_err("%s: Unable to allocate memory for disk profile\n", DEVICE_NAME);
		return -ENOMEM;
	}

	// Convert to disk profile - freeing of this profile should be done by calling function
	pH_profile_mem2disk(profile, disk_profile);
	
	add_to_profile_queue(disk_profile);
	
	if (!output_string || output_string == NULL) {
		pr_err("%s: output_string is NULL in pH_write_profile\n", DEVICE_NAME);
	}
	strcpy(output_string, TRANSFER_OPERATION);
	
	// The use of SIGCONT here might not be correct. Perhaps the userspace app is already running,
	// in which case sending it a signal might be a bad idea and might cause problems. I will need
	// to find out if there is any way to see if a process is currently running before sending a
	// signal. Alternatively, I could check to see if the queue was empty before the call above,
	// and only send the signal if that is the case.
	ret = send_signal(SIGCONT);
	if (ret < 0) {
		return ret;
	}
	//done_waiting_for_user = FALSE;
	
	return 0;
}

// Destructor for pH_profiles - perhaps remove use of freeing lock?
void pH_free_profile(pH_profile *profile)
{
    int ret;
    
    ASSERT(profile != NULL);
	ASSERT(!pH_profile_in_use(profile));
    
    //pr_err("%s: In pH_free_profile for %d\n", DEVICE_NAME, profile->identifier);
    
    spin_lock(&(profile->freeing_lock));
    
    if (profile->lock == NULL) {
    	return;
    }
    
    // Deals with nasty locking stuff
    spin_lock(profile->lock);
    if (profile == NULL || !pH_profile_in_use(profile)) {
    	spin_unlock(profile->lock);
    	return;
    }
    /*
    if (spin_trylock(&pH_profile_list_sem) == 0) {
    	if (profile->lock == NULL) {
			return;
		}
    	spin_unlock(profile->lock);
    	spin_lock(&pH_profile_list_sem);
    	spin_lock(profile->lock);
    	if (profile == NULL || !pH_profile_in_use(profile)) {
			spin_unlock(profile->lock);
			return;
		}
    }
    */
    
    ret = pH_remove_profile_from_list(profile);
    //ASSERT(profile_list_contains_identifier(profile->identifier));
    //spin_unlock(&pH_profile_list_sem);
    
    ASSERT(ret != 0);

    if (pH_aremonitoring) {
        pH_write_profile(profile);
    }

    pH_free_profile_storage(profile);
    if (profile->lock != NULL) spin_unlock(profile->lock);
    //pr_err("%s: Back in pH_free_profile after pH_free_profile_storage\n", DEVICE_NAME);
    //kfree(profile->lock); // Do not do this - the profile lock cannot come out from under another functions feet
    //profile->lock = NULL; // Instead, check to see if the profile is still around
    //pr_err("%s: Freed profile->lock\n", DEVICE_NAME);
    spin_unlock(&(profile->freeing_lock));
    //vfree(profile); // For now, don't free any profiles
    //profile = NULL; // This is okay, because profile was removed from the linked list above
    //pr_err("%s: Freed pH_profile (end of function)\n", DEVICE_NAME);
}

// Removes a process from the list of processes
int remove_process_from_llist(pH_task_struct* process) {
	pH_task_struct *prev_task_struct, *cur_task_struct;
	
	ASSERT(spin_is_locked(&pH_task_struct_list_sem));
	//ASSERT(!spin_is_locked(&pH_profile_list_sem));
	ASSERT(process != NULL);
	
	//pr_err("%s: In remove_process_from_llist\n", DEVICE_NAME);

	//spin_lock(&pH_task_struct_list_sem);
	if (pH_task_struct_list == NULL) {
		err("pH_task_struct_list is empty (NULL) when trying to free process %ld", process->process_id);
		//spin_unlock(&pH_task_struct_list_sem);
		return -1;
	}
	else if (pH_task_struct_list == process) {
		//pr_err("%s: pH_task_struct_list == process\n", DEVICE_NAME);
		pH_task_struct_list = pH_task_struct_list->next;
		//pr_err("%s: Got here 1\n", DEVICE_NAME);
		if (pH_task_struct_list != NULL) {
			pH_task_struct_list->prev = NULL;
			//pr_err("%s: Got here 2\n", DEVICE_NAME);
			if (pH_task_struct_list->next != NULL) {
				pH_task_struct_list->next->prev = pH_task_struct_list;
			}
		}
		//pr_err("%s: Returning from remove_process_from_llist\n", DEVICE_NAME);
		//spin_unlock(&pH_task_struct_list_sem);
		return 0;
	}
	else {
		//pr_err("%s: In else of remove_process_from_llist\n", DEVICE_NAME);
		prev_task_struct = pH_task_struct_list;
		cur_task_struct = pH_task_struct_list->next;
		while (cur_task_struct != NULL) {
			if (cur_task_struct == process) {
				//pr_err("%s: cur_task_struct == process\n", DEVICE_NAME);
				prev_task_struct->next = process->next;
				if (prev_task_struct->next != NULL) {
					prev_task_struct->next->prev = prev_task_struct;
				}
				//pr_err("%s: Returning from remove_process_from_llist\n", DEVICE_NAME);
				//spin_unlock(&pH_task_struct_list_sem);
				return 0;
			}
			
			prev_task_struct = cur_task_struct;
			cur_task_struct = cur_task_struct->next;
		}
		
		err("While freeing, couldn't find process %ld in pH_task_struct_list", process->process_id);
		//spin_unlock(&pH_task_struct_list_sem);
		return -1;
	}
}

/* // Shouldn't have any syscalls anymore, since they are not required
// Frees all of the syscalls that are stored in a process
void free_syscalls(pH_task_struct* t) {
	my_syscall* current_syscall;
	my_syscall* iterator = t->syscall_llist;
		
	while (iterator) {	
		current_syscall = iterator;
		iterator = iterator->next;
		kfree(current_syscall);
		current_syscall = NULL;
	}
}
*/

/*
// Returns true if a given profile has at least one process that matches it
bool profile_has_matching_process(pH_profile* profile) {
	pH_task_struct* iterator;
	
	spin_lock(&pH_task_struct_list_sem);
	for (iterator = pH_task_struct_list; iterator != NULL; iterator = iterator->next) {
		if (iterator->profile == profile) {
			spin_unlock(&pH_task_struct_list_sem);
			return TRUE;
		}
	}
	
	spin_unlock(&pH_task_struct_list_sem);
	return FALSE;
}
*/

/*
int free_profiles(void) {
	int profiles_with_no_matching_process = 0;
	int ret = 0;
	
	/* // Old implementation
	pH_profile* current_profile;
	pH_profile* iterator = pH_profile_list;
	
	spin_lock(&pH_profile_list_sem);
	while (iterator) {
		current_profile = iterator;
		iterator = iterator->next;
		pH_free_profile(current_profile);
		current_profile = NULL;
	}
	spin_unlock(&pH_profile_list_sem);
	*/
	
	/*
	// New implementation
	while (pH_profile_list != NULL) {
		pH_profile_list->refcount.counter = 0;
		if (!profile_has_matching_process(pH_profile_list)) profiles_with_no_matching_process++;
		pH_free_profile(pH_profile_list);
		ret++;
	}
	
	pr_err("%s: There are %d profiles with no matching processes\n", DEVICE_NAME, profiles_with_no_matching_process);
	
	return ret - 1; // For some reason just returning ret is incorrect
}
*/

// Destructor for pH_task_structs
void free_pH_task_struct(pH_task_struct* process) {
	pH_profile* profile;
	int i = 0;
	
	ASSERT(process != NULL);

	//pr_err("%s: In free_pH_task_struct for %ld %s\n", DEVICE_NAME, process->process_id, process->profile->filename);
	//pr_err("%s: process = %p\n", DEVICE_NAME, process);
	//pr_err("%s: process->seq = %p\n", DEVICE_NAME, process->seq); // This will only print NULL if this process did not make a single syscall
	
	if (pH_aremonitoring) {
		//stack_print(process);
	}
	
	// Emtpies stack of pH_seqs
	while (process->seq != NULL) {
		/*
		if (i > 1000) {
			pr_err("%s: Been in this loop for quite some time... Exiting\n", DEVICE_NAME);
			return;
		}
		*/
		
		//pr_err("%s: In while %d\n", DEVICE_NAME, i);
		stack_pop(process);
		//pr_err("%s: &process = %p\n", DEVICE_NAME, &process);
		//pr_err("%s: After stack_pop(process);\n", DEVICE_NAME);
		i++;
	}
	//pr_err("%s: Emptied stack of pH_seqs\n", DEVICE_NAME);
	//stack_print(process); // Don't bother printing right now
	//mutex_destroy(&(process->pH_seq_stack_sem)); // Leave the mutex intact?
	
	//free_syscalls(process); // Frees syscalls
	//pr_err("%s: Freed syscalls\n", DEVICE_NAME);
	
	/* // For now, don't free any profiles - later, implement freeing profiles every ten seconds
	   // (every ten seconds userspace should send a "free profiles" message, where the profile list
	   // should be locked so that no profiles can be added or removed until they are all freed)
	// This boolean test is required for when this function is called when the module is being removed
	//if (module_inserted_successfully) {
		profile = process->profile;

		if (profile != NULL) {
			pH_refcount_dec(profile);

			if (!pH_profile_in_use(profile)) {
				// Free profile
				pH_free_profile(profile);
				profile = NULL; // Okay because the profile is removed from llist in pH_free_profile
				pr_err("%s: Freed profile\n", DEVICE_NAME);
			}
		}
		else {
			pr_err("%s: ERROR: Corrupt process in free_pH_task_struct: No profile\n", DEVICE_NAME);
			ASSERT(profile != NULL);
			return;
		}
	//}
	*/
	
	// When everything else is done, remove process from llist, kfree process
	// (maybe remove the process from the llist earlier?)
	//preempt_disable();
	spin_lock(&pH_task_struct_list_sem);
	remove_process_from_llist(process);
	spin_unlock(&pH_task_struct_list_sem);
	//preempt_enable();
	kfree(process);
	process = NULL; // Okay because process is removed from llist above
	//pr_err("%s: Freed process (end of function)\n", DEVICE_NAME);
}

static long jsys_exit(int error_code) {
	pH_task_struct* process;
	
	if (!done_waiting_for_user) goto not_inserted;
	
	if (!module_inserted_successfully) goto not_inserted;
	
	//pr_err("%s: In jsys_exit for %d\n", DEVICE_NAME, pid_vnr(task_tgid(current)));
	
	//preempt_disable();
	spin_lock(&pH_task_struct_list_sem);
	process = llist_retrieve_process(pid_vnr(task_tgid(current)));
	spin_unlock(&pH_task_struct_list_sem);
	//preempt_enable();
	
	if (process == NULL) goto not_monitoring;
	
	//pr_err("%s: In jsys_exit for %d %s\n", DEVICE_NAME, pid_vnr(task_tgid(current)), process->profile->filename);
	
	//process_syscall(72); // Process this syscall before calling free_pH_task_struct on process
	//pr_err("%s: Back in jsys_exit after processing syscall\n", DEVICE_NAME);
	
	pr_err("%s: Calling free_pH_task_struct from jsys_exit\n", DEVICE_NAME);
	free_pH_task_struct(process);
	
	jprobe_return();
	return 0;
	
not_monitoring:
	//pr_err("%s: %d had no pH_task_struct associated with it\n", DEVICE_NAME, pid_vnr(task_tgid(current)));
	jprobe_return();
	return 0;
	
not_inserted:
	jprobe_return();
	return 0;
}

struct jprobe sys_exit_jprobe = {
	.entry = jsys_exit,
};

static long jdo_group_exit(int error_code) {
	pH_task_struct* process;
	struct task_struct* p;
	struct task_struct* t;
	
	if (!done_waiting_for_user) goto not_inserted;
	
	if (!module_inserted_successfully) goto not_inserted;
	
	p = current;
	
	//pr_err("%s: In jdo_group_exit for %d\n", DEVICE_NAME, pid_vnr(task_tgid(p)));
	
	/* // I don't think this should be here - it is covered elsewhere, and probably not necessary
	//preempt_disable();
	spin_lock(&pH_task_struct_list_sem);
	process = llist_retrieve_process(pid_vnr(task_tgid(current)));
	spin_unlock(&pH_task_struct_list_sem);
	//preempt_enable();
	if (process == NULL) goto not_monitoring;
	*/
	
	//pr_err("%s: In jdo_group_exit for %d %s\n", DEVICE_NAME, pid_vnr(task_tgid(p)), process->profile->filename);
	
	t = p;
	while_each_thread(p, t) {
		if (t->exit_state) continue;
		
		//preempt_disable();
		spin_lock(&pH_task_struct_list_sem);
		process = llist_retrieve_process(pid_vnr(task_tgid(current))); // Should this be t?
		spin_unlock(&pH_task_struct_list_sem);
		//preempt_enable();
		
		if (process != NULL) {
			//pr_err("%s: Calling free_pH_task_struct from jdo_group_exit\n", DEVICE_NAME);
			free_pH_task_struct(process);
		}
	}
	//preempt_disable();
	spin_lock(&pH_task_struct_list_sem);
	process = llist_retrieve_process(pid_vnr(task_tgid(current)));
	spin_unlock(&pH_task_struct_list_sem);
	//preempt_enable();
	
	if (process != NULL) {
		//pr_err("%s: Calling free_pH_task_struct from jdo_group_exit\n", DEVICE_NAME);
		free_pH_task_struct(process);
	}
	
	jprobe_return();
	return 0;
	
not_monitoring:
	//pr_err("%s: %d had no pH_task_struct associated with it\n", DEVICE_NAME, pid_vnr(task_tgid(current)));
	jprobe_return();
	return 0;
	
not_inserted:
	jprobe_return();
	return 0;
}

struct jprobe do_group_exit_jprobe = {
	.entry = jdo_group_exit,
};

/*
static int jwait_consider_task(struct wait_opts *wo, int ptrace, struct task_struct *p) {
	pH_task_struct* process;
	int exit_state = ACCESS_ONCE(p->exit_state);
	
	if (!module_inserted_successfully) goto not_inserted;
	
	pr_err("%s: In jwait_consider_task\n", DEVICE_NAME);
	
	process = llist_retrieve_process(pid_vnr(task_tgid(current)));
	
	if (exit_state == EXIT_DEAD) {
		if (process != NULL) {
			pr_err("%s: Freeing process\n", DEVICE_NAME);
		}
		else {
			pr_err("%s: No process to free\n", DEVICE_NAME);
		}
	
		free_pH_task_struct(process);
	}
	
	jprobe_return();
	return 0;

not_inserted:
	jprobe_return();
	return 0;
}

struct jprobe wait_consider_task_jprobe = {
	.entry = jwait_consider_task,
};
*/

static void jfree_pid(struct pid* pid) {
	pH_task_struct* iterator;
	int i = 0;
	bool freed_anything = FALSE;
	
	if (!done_waiting_for_user) goto exit;
	
	if (!module_inserted_successfully) goto exit;
	
	//pr_err("%s: In jfree_pid\n", DEVICE_NAME);
	
	spin_lock(&pH_task_struct_list_sem);
	for (iterator = pH_task_struct_list; iterator != NULL; iterator = iterator->next) {
		if (i > 10000) {
			pr_err("%s: ERROR: Got stuck in jfree_pid for loop\n", DEVICE_NAME);
			spin_unlock(&pH_task_struct_list_sem);
			ASSERT(i <= 10000);
			goto exit;
		}
		if (iterator->pid == pid) {
			spin_unlock(&pH_task_struct_list_sem);
			pr_err("%s: Calling free_pH_task_struct from jfree_pid\n", DEVICE_NAME);
			free_pH_task_struct(iterator);
			iterator = NULL;
			freed_anything = TRUE;
			//pr_err("%s: Done in jfree_pid\n", DEVICE_NAME);
			goto exit;
			
			/* // This used to be for freeing more than one process at a time, which may not be necessary
			pr_err("%s: Got here 1\n", DEVICE_NAME);
			if (iterator == pH_task_struct_list) {
				pr_err("%s: Got here 2\n", DEVICE_NAME);
				free_pH_task_struct(iterator);
				pr_err("%s: Got here 3\n", DEVICE_NAME);
				iterator = pH_task_struct_list;
				pr_err("%s: Got here 4\n", DEVICE_NAME);
				if (iterator == NULL) {
					spin_unlock(&pH_task_struct_list_sem);
					goto exit;
				}
			}
			else {
				pr_err("%s: Got here 5\n", DEVICE_NAME);
				iterator = iterator->prev;
				pr_err("%s: Got here 6\n", DEVICE_NAME);
				free_pH_task_struct(iterator->next);
				pr_err("%s: Got here 7\n", DEVICE_NAME);
			}
			*/
		}
		i++;
	}
	spin_unlock(&pH_task_struct_list_sem);
	
	ASSERT(freed_anything);
	
	jprobe_return();
	return;

exit:
	jprobe_return();
	return;
}

struct jprobe free_pid_jprobe = {
	.entry = jfree_pid,
};

/*
void stack_print(pH_task_struct* process) {
	//pr_err("%s: In stack print\n", DEVICE_NAME);
	
	if (!process || process == NULL) {
		pr_err("%s: In stack_print with NULL process\n", DEVICE_NAME);
		return;
	}
	
	if (!(process->profile) || process->profile == NULL) {
		pr_err("%s: In stack_print with corrupted process->profile\n", DEVICE_NAME);
		return;
	}
	
	int i;
	pH_seq* iterator = process->seq;
	//pr_err("%s: Got through variable declaration\n", DEVICE_NAME);
	
	if (process->seq == NULL) {
		if (process->profile != NULL && module_inserted_successfully) {
			//pr_err("%s: process->profile != NULL\n", DEVICE_NAME);
			pr_err("%s: Printing stack for process %s: Stack is empty\n", DEVICE_NAME, process->profile->filename);
		}
		else {
			pr_err("%s: Printing stack for process %ld: Stack is empty\n", DEVICE_NAME, process->process_id);
		}
		return;
	}
	
	i = 0;
	
	//pr_err("%s: process->seq = %p, iterator = %p\n", DEVICE_NAME, process->seq, iterator);
	
	if (process->profile != NULL && process->profile->filename != NULL) {
		pr_err("%s: Printing stack for process %s...\n", DEVICE_NAME, process->profile->filename);
	}
	else {
		pr_err("%s: Printing stack for process %ld...\n", DEVICE_NAME, process->process_id);
	}
	do {
		pr_err("%s: %d: length = %d\n", DEVICE_NAME, i, iterator->length);
		
		iterator = iterator->next;
		i++;
	} while (iterator);
	
	pr_err("%s: Stack has length %d\n", DEVICE_NAME, i);
}
*/

// Pushes a new pH_seq onto the stack
void stack_push(pH_task_struct* process, pH_seq* new_node) {
	//pH_seq* top = process->seq;
	
	ASSERT(process != NULL);
	ASSERT(new_node != NULL);

	if (process->seq == NULL) {
		new_node->next = NULL;
		new_node->prev = NULL;
		process->seq = new_node;
	}
	else {
		new_node->next = process->seq;
		process->seq = new_node;
		new_node->prev = NULL;
		new_node->next->prev = new_node;
	}
}

// Note: This implementation of pop DOES NOT return the deleted element. To do so would
// require memory is allocated for temp, and then that all of top's data is copied to temp, and
// then that temp is returned WITHOUT being freed.
void stack_pop(pH_task_struct* process) {
	pH_seq* temp;
	//pH_seq* top = process->seq;
	
	//pr_err("%s: In stack_pop\n", DEVICE_NAME);
	//pr_err("%s: top = %p\n", DEVICE_NAME, top);

	if (process->seq == NULL) {
		pr_err("%s: Stack is empty - cannot delete an element\n", DEVICE_NAME);
		return;
	}
	
	temp = process->seq;
	process->seq = process->seq->next;
	process->seq->prev = NULL;
	process->seq->next->prev = process->seq; // This line might be unecessary
	kfree(temp);
	temp = NULL;
}

pH_seq* stack_peek(pH_task_struct* process) {
	return process->seq; 
}

// This is for when a process receives a signal, NOT for when it resumes execution following
// the signal. I will need to implement a second jprobe handler for resuming execution.
static void jhandle_signal(struct ksignal* ksig, struct pt_regs* regs) {
	pH_task_struct* process;
	
	if (!done_waiting_for_user) goto not_inserted;
	
	if (!module_inserted_successfully) goto not_inserted;
	
	//pr_err("%s: In jhandle_signal\n", DEVICE_NAME);
	
	// Will this retrieve the process that the signal is being sent to, or will it retrieve the
	// process that is sending the signal?
	//preempt_disable();
	spin_lock(&pH_task_struct_list_sem);
	process = llist_retrieve_process(pid_vnr(task_tgid(current)));
	spin_unlock(&pH_task_struct_list_sem);
	//preempt_enable();
	
	if (process != NULL) {
		make_and_push_new_pH_seq(process);
	}
	
	jprobe_return();
	return;
	
not_inserted:
	jprobe_return();
	return;
}

static void jdo_signal(struct pt_regs* regs) {
	pH_task_struct* process;
	
	if (!done_waiting_for_user) goto not_inserted;
	
	if (!module_inserted_successfully) goto not_inserted;
	
	//pr_err("%s: In jdo_signal\n", DEVICE_NAME);
	
	// Will this retrieve the process that the signal is being sent to, or will it retrieve the
	// process that is sending the signal?
	//preempt_disable();
	spin_lock(&pH_task_struct_list_sem);
	process = llist_retrieve_process(pid_vnr(task_tgid(current)));
	spin_unlock(&pH_task_struct_list_sem);
	//preempt_enable();
	
	if (process != NULL) {
		make_and_push_new_pH_seq(process);
	}
	
	//pr_err("%s: Exiting jdo_signal\n", DEVICE_NAME);
	jprobe_return();
	return;
	
not_inserted:
	jprobe_return();
	return;
}

/*
static long jsys_sigreturn(struct pt_regs* regs) {
	pH_task_struct* process;
	
	if (!module_inserted_successfully) goto not_inserted;
	
	pr_err("%s: In jsys_sigreturn\n", DEVICE_NAME);
	
	process = llist_retrieve_process(pid_vnr(task_tgid(current)));
	
	if (process != NULL) {
		stack_pop(process);
	}
	
	process_syscall(383);
	pr_err("%s: Back in jsys_sigreturn after processing syscall\n", DEVICE_NAME);
	
	jprobe_return();
	return 0;

not_inserted:
	jprobe_return();
	return 0;
}
*/

static long jsys_rt_sigreturn(void) {
	pH_task_struct* process;
	
	if (!done_waiting_for_user) goto not_inserted;
	
	if (!module_inserted_successfully) goto not_inserted;
	
	last_task_struct_in_sigreturn = current;
	
	//pr_err("%s: In jsys_rt_sigreturn\n", DEVICE_NAME);
	
	process_syscall(383);
	//pr_err("%s: Back in jsys_rt_sigreturn after processing syscall\n", DEVICE_NAME);
	
	//preempt_disable();
	spin_lock(&pH_task_struct_list_sem);
	process = llist_retrieve_process(pid_vnr(task_tgid(current)));
	spin_unlock(&pH_task_struct_list_sem);
	//preempt_enable();
	
	if (current->exit_state == EXIT_DEAD || current->exit_state == EXIT_ZOMBIE || current->state == TASK_DEAD) {
		pr_err("%s: Calling free_pH_task_struct from jsys_rt_sigreturn\n", DEVICE_NAME);
		free_pH_task_struct(process);
	}
	
	if (sigismember(&current->pending.signal, SIGKILL)) {
		pr_err("%s: Calling free_pH_task_struct from jsys_rt_sigreturn\n", DEVICE_NAME);
		free_pH_task_struct(process);
	}
	else {
		//pr_err("%s: SIGKILL is not a member of current->pending.signal\n", DEVICE_NAME);
	}
	
	if (!process || process == NULL) goto not_inserted;
	
	stack_pop(process);
	
	//pr_err("%s: Got through all of jsys_rt_sigreturn\n", DEVICE_NAME);
	
	jprobe_return();
	return 0;
	
not_inserted:
	jprobe_return();
	return 0;
}

// Frees all of the pH_task_structs in one go
int free_pH_task_structs(void) {
	int ret = 0;
	
	while (pH_task_struct_list != NULL) {
		free_pH_task_struct(pH_task_struct_list);
		ret++;
	}
	
	return ret;
}

// Function responsible for module insertion
static int __init ebbchar_init(void) {
	int ret, i, j;
	
	pr_info("%s: Initializing the EBBChar LKM\n", DEVICE_NAME);

	// Try to dynamically allocate a major number for the device
	majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
	if (majorNumber<0){
	  pr_err("%s: Failed to register a major number\n", DEVICE_NAME);
	  return majorNumber;
	}
	pr_err("%s: registered correctly with major number %d\n", DEVICE_NAME, majorNumber);

	// Register the device class
	ebbcharClass = class_create(THIS_MODULE, CLASS_NAME);
	if (IS_ERR(ebbcharClass)){           // Check for error and clean up if there is
	  unregister_chrdev(majorNumber, DEVICE_NAME);
	  pr_err("%s: Failed to register device class\n", DEVICE_NAME);
	  return PTR_ERR(ebbcharClass);
	}
	pr_err("%s: device class registered correctly\n", DEVICE_NAME);

	// Register the device driver
	ebbcharDevice = device_create(ebbcharClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
	if (IS_ERR(ebbcharDevice)){          // Clean up if there is an error
	  class_destroy(ebbcharClass);      
	  unregister_chrdev(majorNumber, DEVICE_NAME);
	  pr_err("%s: Failed to create the device\n", DEVICE_NAME);
	  return PTR_ERR(ebbcharDevice);
	}
	pr_err("%s: device class created correctly\n", DEVICE_NAME); // Device was initialized
	mutex_init(&ebbchar_mutex); // Initialize the mutex dynamically
	
	/*
	handle_signal_jprobe.kp.addr = kallsyms_lookup_name("handle_signal");
	ret = register_jprobe(&handle_signal_jprobe);
	if (ret < 0) {
		pr_err("%s: register_jprobe failed (handle_signal_jprobe), returned %d\n", DEVICE_NAME, ret);
		
		mutex_destroy(&ebbchar_mutex);
		device_destroy(ebbcharClass, MKDEV(majorNumber, 0));
		class_unregister(ebbcharClass);
		class_destroy(ebbcharClass);
		unregister_chrdev(majorNumber, DEVICE_NAME);
		
		pr_err("%s: Module has (hopefully) been removed entirely\n", DEVICE_NAME);
		pr_err("%s: ...But just in case, run this command: 'sudo rmmod km'\n", DEVICE_NAME);
		
		return PTR_ERR(ebbcharDevice);
	}
	*/
	
	/*
	if (kallsyms_lookup_name("sys_rt_sigreturn") != 0) {
		pr_err("%s: Found sys_rt_sigreturn\n", DEVICE_NAME);
	}
	if (kallsyms_lookup_name("sys32_x32_rt_sigreturn") != 0) {
		pr_err("%s: Found sys32_x32_rt_sigreturn\n", DEVICE_NAME);
	}
	if (kallsyms_lookup_name("sys32_sigreturn") != 0) {
		pr_err("%s: Found sys32_sigreturn\n", DEVICE_NAME);
	}
	if (kallsyms_lookup_name("sys32_rt_sigreturn") != 0) {
		pr_err("%s: Found sys32_rt_sigreturn\n", DEVICE_NAME);
	}
	if (kallsyms_lookup_name("ptregs_sys_rt_sigreturn") != 0) {
		pr_err("%s: Found ptregs_sys_rt_sigreturn\n", DEVICE_NAME);
	}
	
	if (kallsyms_lookup_name("sys_sigreturn") == 0) {
		pr_err("%s: Failed to find symbol 'sys_sigreturn'\n", DEVICE_NAME);
		
		//sys_sigreturn_jprobe.kp.symbol_name = "sys_sigreturn";
	}
	pr_err("%s: Found symbol 'sys_sigreturn'\n", DEVICE_NAME);
	*/
	
	/* // Maybe I am unable to probe do_execveat_common? Returns -22 on registration.
	do_execveat_common_kretprobe.kp.addr = kallsyms_lookup_name("do_execveat_common");
	ret = register_kretprobe(&do_execveat_common_kretprobe);
	if (ret < 0) {
		pr_err("%s: register_kretprobe failed (do_execveat_common_kretprobe), returned %d\n", DEVICE_NAME, ret);
		
		//unregister_jprobe(&handle_signal_jprobe);
		
		mutex_destroy(&ebbchar_mutex);
		device_destroy(ebbcharClass, MKDEV(majorNumber, 0));
		class_unregister(ebbcharClass);
		class_destroy(ebbcharClass);
		unregister_chrdev(majorNumber, DEVICE_NAME);
		
		pr_err("%s: Module has (hopefully) been removed entirely\n", DEVICE_NAME);
		pr_err("%s: ...But just in case, run this command: 'sudo rmmod km'\n", DEVICE_NAME);
		
		return PTR_ERR(ebbcharDevice);
	}
	pr_err("%s: Successfully registered do_execveat_common_kretprobe\n", DEVICE_NAME);
	*/
	
	/*
	do_execve_kretprobe.kp.addr = kallsyms_lookup_name("do_execve");
	ret = register_kretprobe(&do_execve_kretprobe);
	if (ret < 0) {
		pr_err("%s: register_kretprobe failed (do_execve_kretprobe), returned %d\n", DEVICE_NAME, ret);
		
		//unregister_jprobe(&handle_signal_jprobe);
		
		mutex_destroy(&ebbchar_mutex);
		device_destroy(ebbcharClass, MKDEV(majorNumber, 0));
		class_unregister(ebbcharClass);
		class_destroy(ebbcharClass);
		unregister_chrdev(majorNumber, DEVICE_NAME);
		
		pr_err("%s: Module has (hopefully) been removed entirely\n", DEVICE_NAME);
		pr_err("%s: ...But just in case, run this command: 'sudo rmmod km'\n", DEVICE_NAME);
		
		return PTR_ERR(ebbcharDevice);
	}
	pr_err("%s: Successfully registered do_execve_kretprobe\n", DEVICE_NAME);
	*/
	
	sys_execve_kretprobe.kp.addr = kallsyms_lookup_name("sys_execve");
	ret = register_kretprobe(&sys_execve_kretprobe);
	if (ret < 0) {
		pr_err("%s: register_kretprobe failed (sys_execve_kretprobe), returned %d\n", DEVICE_NAME, ret);
		
		//unregister_jprobe(&handle_signal_jprobe);
		
		mutex_destroy(&ebbchar_mutex);
		device_destroy(ebbcharClass, MKDEV(majorNumber, 0));
		class_unregister(ebbcharClass);
		class_destroy(ebbcharClass);
		unregister_chrdev(majorNumber, DEVICE_NAME);
		
		pr_err("%s: Module has (hopefully) been removed entirely\n", DEVICE_NAME);
		pr_err("%s: ...But just in case, run this command: 'sudo rmmod km'\n", DEVICE_NAME);
		
		return PTR_ERR(ebbcharDevice);
	}
	pr_err("%s: Successfully registered sys_execve_kretprobe\n", DEVICE_NAME);
	
	/*
	free_pid_jprobe.kp.addr = kallsyms_lookup_name("free_pid");
	ret = register_jprobe(&free_pid_jprobe);
	if (ret < 0) {
		pr_err("%s: register_jprobe failed (free_pid_jprobe), returned %d\n", DEVICE_NAME, ret);
		
		//unregister_jprobe(&handle_signal_jprobe);
		
		mutex_destroy(&ebbchar_mutex);
		device_destroy(ebbcharClass, MKDEV(majorNumber, 0));
		class_unregister(ebbcharClass);
		class_destroy(ebbcharClass);
		unregister_chrdev(majorNumber, DEVICE_NAME);
		
		pr_err("%s: Module has (hopefully) been removed entirely\n", DEVICE_NAME);
		pr_err("%s: ...But just in case, run this command: 'sudo rmmod km'\n", DEVICE_NAME);
		
		return PTR_ERR(ebbcharDevice);
	}
	pr_err("%s: Successfully registered free_pid_jprobe\n", DEVICE_NAME);
	*/
	
	sys_sigreturn_jprobe.kp.addr = kallsyms_lookup_name("sys_rt_sigreturn");
	ret = register_jprobe(&sys_sigreturn_jprobe);
	if (sys_sigreturn_jprobe.kp.addr && ret < 0) {
		pr_err("%s: register_jprobe failed (sys_sigreturn_jprobe), returned %d\n", DEVICE_NAME, ret);
		
		//unregister_jprobe(&handle_signal_jprobe);
		
		mutex_destroy(&ebbchar_mutex);
		device_destroy(ebbcharClass, MKDEV(majorNumber, 0));
		class_unregister(ebbcharClass);
		class_destroy(ebbcharClass);
		unregister_chrdev(majorNumber, DEVICE_NAME);
		
		pr_err("%s: Module has (hopefully) been removed entirely\n", DEVICE_NAME);
		pr_err("%s: ...But just in case, run this command: 'sudo rmmod km'\n", DEVICE_NAME);
		
		return PTR_ERR(ebbcharDevice);
	}
	pr_err("%s: Successfully registered sys_sigreturn_jprobe\n", DEVICE_NAME);
	
	// Register do_signal_jprobe
	do_signal_jprobe.kp.addr = kallsyms_lookup_name("do_signal");
	ret = register_jprobe(&do_signal_jprobe);
	if (ret < 0) {
		pr_err("%s: register_jprobe failed (do_signal_jprobe), returned %d\n", DEVICE_NAME, ret);
		
		//unregister_jprobe(&handle_signal_jprobe);
		//unregister_jprobe(&sys_sigreturn_jprobe);
		
		mutex_destroy(&ebbchar_mutex);
		device_destroy(ebbcharClass, MKDEV(majorNumber, 0));
		class_unregister(ebbcharClass);
		class_destroy(ebbcharClass);
		unregister_chrdev(majorNumber, DEVICE_NAME);
		
		pr_err("%s: Module has (hopefully) been removed entirely\n", DEVICE_NAME);
		pr_err("%s: ...But just in case, run this command: 'sudo rmmod km'\n", DEVICE_NAME);
		
		return PTR_ERR(ebbcharDevice);
	}
	pr_err("%s: Successfully registered do_signal_jprobe\n", DEVICE_NAME);
	
	/*
	wait_consider_task_jprobe.kp.addr = kallsyms_lookup_name("wait_consider_task");
	ret = register_jprobe(&wait_consider_task_jprobe);
	if (ret < 0) {
		pr_err("%s: register_jprobe failed (wait_consider_task_jprobe), returned %d\n", DEVICE_NAME, ret);
		
		//unregister_jprobe(&handle_signal_jprobe);
		//unregister_jprobe(&sys_sigreturn_jprobe);
		
		mutex_destroy(&ebbchar_mutex);
		device_destroy(ebbcharClass, MKDEV(majorNumber, 0));
		class_unregister(ebbcharClass);
		class_destroy(ebbcharClass);
		unregister_chrdev(majorNumber, DEVICE_NAME);
		
		pr_err("%s: Module has (hopefully) been removed entirely\n", DEVICE_NAME);
		pr_err("%s: ...But just in case, run this command: 'sudo rmmod km'\n", DEVICE_NAME);
		
		return PTR_ERR(ebbcharDevice);
	}
	pr_err("%s: Successfully registered wait_consider_task_jprobe\n", DEVICE_NAME);
	
	sys_rt_sigreturn_kretprobe.kp.symbol_name = "sys_rt_sigreturn";
	ret = register_kretprobe(&sys_rt_sigreturn_kretprobe);
	if (ret < 0) {
		pr_err("%s: Failed to register sys_rt_sigreturn_kretprobe, returned %d\n", DEVICE_NAME, ret);
		
		//unregister_jprobe(&handle_signal_jprobe);
		//unregister_jprobe(&sys_sigreturn_jprobe);
		unregister_jprobe(&do_signal_jprobe);
		
		mutex_destroy(&ebbchar_mutex);
		device_destroy(ebbcharClass, MKDEV(majorNumber, 0));
		class_unregister(ebbcharClass);
		class_destroy(ebbcharClass);
		unregister_chrdev(majorNumber, DEVICE_NAME);
		
		pr_err("%s: Module has (hopefully) been removed entirely\n", DEVICE_NAME);
		pr_err("%s: ...But just in case, run this command: 'sudo rmmod km'\n", DEVICE_NAME);
		
		return PTR_ERR(ebbcharDevice);
	}
	pr_err("%s: Successfully registered sys_rt_sigreturn_kretprobe\n", DEVICE_NAME);
	*/
	
	// Register fork_kretprobe
	fork_kretprobe.kp.symbol_name = "_do_fork";
	ret = register_kretprobe(&fork_kretprobe);
	if (ret < 0) {
		pr_err("%s: Failed to register _do_fork kretprobe, returned %d\n", DEVICE_NAME, ret);
		
		//unregister_jprobe(&handle_signal_jprobe);
		//unregister_jprobe(&sys_sigreturn_jprobe);
		unregister_jprobe(&do_signal_jprobe);
		
		mutex_destroy(&ebbchar_mutex);
		device_destroy(ebbcharClass, MKDEV(majorNumber, 0));
		class_unregister(ebbcharClass);
		class_destroy(ebbcharClass);
		unregister_chrdev(majorNumber, DEVICE_NAME);
		
		pr_err("%s: Module has (hopefully) been removed entirely\n", DEVICE_NAME);
		pr_err("%s: ...But just in case, run this command: 'sudo rmmod km'\n", DEVICE_NAME);
		
		return PTR_ERR(ebbcharDevice);
	}
	
	/*
	// Regiser exit_kretprobe
	exit_kretprobe.kp.addr = (kprobe_opcode_t*) kallsyms_lookup_name("do_exit");
	ret = register_kretprobe(&exit_kretprobe);
	if (ret < 0) {
		pr_err("%s: Failed to register do_exit kretprobe, returned %d\n", DEVICE_NAME, ret);
		
		//unregister_jprobe(&handle_signal_jprobe);
		//unregister_jprobe(&sys_sigreturn_jprobe);
		unregister_jprobe(&do_signal_jprobe);
		unregister_kretprobe(&fork_kretprobe);
		
		mutex_destroy(&ebbchar_mutex);
		device_destroy(ebbcharClass, MKDEV(majorNumber, 0));
		class_unregister(ebbcharClass);
		class_destroy(ebbcharClass);
		unregister_chrdev(majorNumber, DEVICE_NAME);
		
		pr_err("%s: Module has (hopefully) been removed entirely\n", DEVICE_NAME);
		pr_err("%s: ...But just in case, run this command: 'sudo rmmod km'\n", DEVICE_NAME);
		
		return PTR_ERR(ebbcharDevice);
	}
	pr_err("%s: Registered exit_kretprobe\n", DEVICE_NAME);
	*/
	
	do_group_exit_jprobe.kp.addr = kallsyms_lookup_name("do_group_exit");
	ret = register_jprobe(&do_group_exit_jprobe);
	if (ret < 0) {
		pr_err("%s: Failed to register do_group_exit_jprobe, returned %d\n", DEVICE_NAME, ret);
		
		//unregister_jprobe(&handle_signal_jprobe);
		//unregister_jprobe(&sys_sigreturn_jprobe);
		unregister_jprobe(&do_signal_jprobe);
		unregister_kretprobe(&fork_kretprobe);
		
		mutex_destroy(&ebbchar_mutex);
		device_destroy(ebbcharClass, MKDEV(majorNumber, 0));
		class_unregister(ebbcharClass);
		class_destroy(ebbcharClass);
		unregister_chrdev(majorNumber, DEVICE_NAME);
		
		pr_err("%s: Module has (hopefully) been removed entirely\n", DEVICE_NAME);
		pr_err("%s: ...But just in case, run this command: 'sudo rmmod km'\n", DEVICE_NAME);
		
		return PTR_ERR(ebbcharDevice);
	}
	pr_err("%s: Registered do_group_exit_jprobe\n", DEVICE_NAME);
	
	
	/* // Registration of sys_exit_jprobe fails for some reason - returns -17
	sys_exit_jprobe.kp.addr = kallsyms_lookup_name("sys_exit");
	ret = register_jprobe(&sys_exit_jprobe);
	if (ret < 0) {
		pr_err("%s: Failed to register sys_exit_jprobe, returned %d\n", DEVICE_NAME, ret);
		
		//unregister_jprobe(&handle_signal_jprobe);
		//unregister_jprobe(&sys_sigreturn_jprobe);
		unregister_jprobe(&do_signal_jprobe);
		unregister_kretprobe(&fork_kretprobe);
		
		mutex_destroy(&ebbchar_mutex);
		device_destroy(ebbcharClass, MKDEV(majorNumber, 0));
		class_unregister(ebbcharClass);
		class_destroy(ebbcharClass);
		unregister_chrdev(majorNumber, DEVICE_NAME);
		
		pr_err("%s: Module has (hopefully) been removed entirely\n", DEVICE_NAME);
		pr_err("%s: ...But just in case, run this command: 'sudo rmmod km'\n", DEVICE_NAME);
		
		return PTR_ERR(ebbcharDevice);
	}
	pr_err("%s: Registered sys_exit_jprobe\n", DEVICE_NAME);
	*/

	//pr_err("%s: num_syscalls = %d\n", DEVICE_NAME, num_syscalls);
	pr_err("%s: Registering syscall jprobes...\n", DEVICE_NAME);
	for (i = 0; i < num_syscalls; i++) {
		ret = register_jprobe(&jprobes_array[i]);
		if (ret < 0) {
			pr_err("%s: register_jprobe failed (%s), returned %d\n", DEVICE_NAME, jprobes_array[i].kp.symbol_name, ret);
			
			//unregister_jprobe(&handle_signal_jprobe);
			//unregister_jprobe(&sys_sigreturn_jprobe);
			unregister_jprobe(&do_signal_jprobe);
			unregister_kretprobe(&fork_kretprobe);
			//unregister_kretprobe(&exit_kretprobe);
			
			// Should it be j <= i?
			for (j = 0; j < i; j++) {
				unregister_jprobe(&jprobes_array[j]);
			}
			
			mutex_destroy(&ebbchar_mutex);
			device_destroy(ebbcharClass, MKDEV(majorNumber, 0));
			class_unregister(ebbcharClass);
			class_destroy(ebbcharClass);
			unregister_chrdev(majorNumber, DEVICE_NAME);
			
			pr_err("%s: Module has (hopefully) been removed entirely\n", DEVICE_NAME);
			pr_err("%s: ...But just in case, run this command: 'sudo rmmod km'\n", DEVICE_NAME);
			
			return PTR_ERR(ebbcharDevice);
		}
		//pr_err("%s: %d: Successfully registered %s\n", DEVICE_NAME, i, jprobes_array[i].kp.symbol_name);
	}
	pr_err("%s: Registered all syscall probes\n", DEVICE_NAME);
	
	pr_err("%s: Successfully initialized %s\n", DEVICE_NAME, DEVICE_NAME);
	
	// Set booleans accordingly, now that initialization is complete
	module_inserted_successfully = TRUE;
	pH_aremonitoring = 1;

	return 0;
}

// Perhaps the best way to remove the module is just to reboot?
static void __exit ebbchar_exit(void){
	int i, profiles_freed, pH_task_structs_freed;
	
	// Set all booleans accordingly - this should be the first thing you do to prevent any more code from running
	module_inserted_successfully = FALSE;
	pH_aremonitoring             = 0;
	done_waiting_for_user        = FALSE;
	have_userspace_pid           = FALSE;
	binary_read                  = FALSE;
	user_process_has_been_loaded = FALSE;

	pr_err("%s: Exiting...\n", DEVICE_NAME);

	// Kill the userspace app
	if (send_signal(SIGTERM) < 0) send_signal(SIGKILL);
	
	kfree(output_string);
	pr_err("%s: vfreeing bin_receive_ptr...\n", DEVICE_NAME);
	vfree(bin_receive_ptr);

	//print_llist(); // For now, don't bother with printing the llist
	
	//unregister_jprobe(&handle_signal_jprobe);
	//unregister_jprobe(&sys_sigreturn_jprobe);
	unregister_jprobe(&do_signal_jprobe);
	
	/* // Temporarily commented out to debug this function
	// Unregister jprobes - it seems this was working just fine before, but Anil said its okay
	// if I don't bother with unregistering them
	for (i = 0; i < num_syscalls; i++) {
		unregister_jprobe(&jprobes_array[i]);
	}
	pr_err("%s: Unregistered syscall jprobes\n", DEVICE_NAME);
	*/

	// Unregister fork_kretprobe
	unregister_kretprobe(&fork_kretprobe);
	pr_err("%s: Missed probing %d instances of fork\n", DEVICE_NAME, fork_kretprobe.nmissed);
	
	/*
	// Unregister exit_kretprobe
	unregister_kretprobe(&exit_kretprobe);
	pr_err("%s: Missed probing %d instances of exit\n", DEVICE_NAME, exit_kretprobe.nmissed);
	*/
	
	//profiles_freed = pH_profile_list_length();
	
	//pr_err("%s: Freeing profiles...\n", DEVICE_NAME);
	//profiles_freed = free_profiles();
	pr_err("%s: Freeing pH_task_structs...\n", DEVICE_NAME);
	pH_task_structs_freed = free_pH_task_structs();
	
	// Miscellaneous cleanup
	mutex_destroy(&ebbchar_mutex);
	device_destroy(ebbcharClass, MKDEV(majorNumber, 0));
	class_unregister(ebbcharClass);
	class_destroy(ebbcharClass);
	unregister_chrdev(majorNumber, DEVICE_NAME);
	
	// Print lengths of lists - can't print everything until I add pH_profile_list_length() back
	//pr_err("%s: At time of module removal, pH was monitoring %d processes and had %d profiles in memory\n", DEVICE_NAME, pH_task_structs_freed, profiles_freed);
	pr_err("%s: During the uptime of the module, %d profiles were created\n", DEVICE_NAME, profiles_created);
	pr_err("%s: During the uptime of the module, there were %d successful jsys_execves\n", DEVICE_NAME, successful_jsys_execves);
	
	pr_err("%s: %s successfully removed\n", DEVICE_NAME, DEVICE_NAME);
}

static int dev_open(struct inode *inodep, struct file *filep){
	if (!mutex_trylock(&ebbchar_mutex)) {
		pr_err("%s: Device in use by another process\n", DEVICE_NAME);
		return -EBUSY;
	}
	
	output_string = kmalloc(sizeof(char) * 254, GFP_ATOMIC);
	if (!output_string) {
		pr_err("%s: Unable to allocate memory for output_string", DEVICE_NAME);
		return -EFAULT;
	}
	
	bin_receive_ptr = __vmalloc(sizeof(pH_disk_profile), GFP_ATOMIC, PAGE_KERNEL);
	if (!bin_receive_ptr) {
		pr_err("%s: Unable to allocate memory for bin_receive_ptr", DEVICE_NAME);
		return -EFAULT;
	}
	
	numberOpens++;
	pr_err("%s: Device has been opened %d time(s)\n", DEVICE_NAME, numberOpens);
	return 0;
}

static ssize_t dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset){
	pH_disk_profile* disk_profile;
	int error_count = 0;
	
	pr_err("%s: In dev_read\n", DEVICE_NAME);

	if (!buffer || buffer == NULL) {
		pr_err("%s: In dev_read with NULL buffer\n", DEVICE_NAME);
		return -EFAULT;
	}
	
	if (!binary_read) {
		pr_err("%s: This is not a binary read\n", DEVICE_NAME);
		
		// Determine number of bytes to send to userspace
		size_of_message = strlen(output_string);

		// If we are asking to perform a binary transfer, set binary_read to TRUE
		if (strcmp(output_string, TRANSFER_OPERATION) == 0 || strcmp(output_string, READ_PROFILE_FROM_DISK) == 0) {
			binary_read = TRUE;
		}			

		// Copy the data to the user
		error_count = copy_to_user(buffer, output_string, size_of_message);
		if (error_count == 0) {           // success
			pr_err("%s: Successfully sent [%s] message to the user\n", DEVICE_NAME, output_string);
			pr_err("%s: Exiting dev_read...\n", DEVICE_NAME);
			return (size_of_message = 0); // clear the position to the start and return 0
		}
		else {
			pr_err("%s: Failed to send %d bytes to the user\n", DEVICE_NAME, error_count);
			return -EFAULT;      // Failed - return a bad address message
		}
	}
	
	pr_err("%s: This is a binary read\n", DEVICE_NAME);

	binary_read = FALSE;
	
	// Cast buffer to void* and copy its value to bin_receive_ptr
	//bin_receive_ptr = (void*) buffer;
	/*
	error_count = copy_from_user(bin_receive_ptr, buffer, sizeof(pH_disk_profile));
	if (error_count != 0) {
		pr_err("%s: Failed to copy %d bytes from user in dev_read\n", DEVICE_NAME, error_count);
		return -EFAULT;
	}
	pr_err("%s: Copied buffer over from userspace\n", DEVICE_NAME);
	*/

	/*
	// Allocate space for current_profile
	current_profile = __vmalloc(sizeof(pH_profile), GFP_ATOMIC, PAGE_KERNEL);
	if (current_profile == NULL) {
		pr_err("%s: Unable to allocate memory for current_profile\n", DEVICE_NAME);
		return -ENOMEM;
	}

	// Allocate space for disk_profile
	disk_profile = __vmalloc(sizeof(pH_disk_profile), GFP_ATOMIC, PAGE_KERNEL);
	if (!disk_profile) {
		pr_err("%s: Unable to allocate memory for disk profile\n", DEVICE_NAME);
		return -ENOMEM;
	}

	// Convert to disk profile
	pH_profile_mem2disk(current_profile, disk_profile);
	vfree(current_profile);
	current_profile = NULL;
	*/

	/*
	void* temp_buffer = __vmalloc(sizeof(pH_disk_profile), GFP_ATOMIC, PAGE_KERNEL);
	if (!temp_buffer || temp_buffer == NULL) {
		pr_err("%s: Unable to allocate space for temp_buffer in dev_read\n", DEVICE_NAME);
		vfree(temp_buffer);
		return -ENOMEM;
	}
	error_count = copy_from_user(temp_buffer, buffer, sizeof(pH_disk_profile));
	if (error_count != 0) {
		pr_err("%s: Unable to copy %d bytes from the user in dev_read\n", DEVICE_NAME, error_count);
	}
	pr_err("%s: buffer is of size %d\n", DEVICE_NAME, sizeof(temp_buffer));
	
	pH_disk_profile* temp_profile = temp_buffer;
	vfree(temp_buffer);
	temp_buffer = NULL;
	temp_profile = NULL;
	*/
	
	// If NULL is returned, that signals end of queue to userspace app
	pr_err("%s: disk_profile is NULL? %d\n", DEVICE_NAME, disk_profile == NULL);
	pr_err("%s: disk_profile = %p\n", DEVICE_NAME, disk_profile);
	pr_err("%s: remove_from_profile_queue = %p\n", DEVICE_NAME, remove_from_profile_queue);
	disk_profile = remove_from_profile_queue();
	pr_err("%s: Removed a disk profile from the queue\n", DEVICE_NAME);
	if (profile_queue_is_empty()) {
		pr_err("%s: Profile queue is empty\n", DEVICE_NAME);
		strcpy(output_string, STOP_TRANSFER_OPERATION);
	}
	if (!disk_profile || disk_profile == NULL) {
		pr_err("%s: Retrieved a NULL disk profile from the queue...\n", DEVICE_NAME);
		/*
		if (profile_queue_is_empty()) {
			pr_err("%s: ...so the userspace app should stop reads\n", DEVICE_NAME);
		}
		else { // Perhaps add an intential descriptive panic here for debugging purposes?
			pr_err("%s: ...but this should not have happened (ERROR)!\n", DEVICE_NAME);
			return -EFAULT;
		}
		*/
		pr_err("%s: ...but this should not have happened (ERROR)!\n", DEVICE_NAME);
		return -EFAULT;
	}
	pr_err("%s: Successfully removed a disk profile from the queue\n", DEVICE_NAME);
	pr_err("%s: In userspace, the filename should be [%s]\n", DEVICE_NAME, disk_profile->filename);

	// Copy data to userspace
	error_count = copy_to_user(buffer, disk_profile, sizeof(pH_disk_profile));
	pr_err("%s: vfreeing disk_profile...\n", DEVICE_NAME);
	vfree(disk_profile);
	disk_profile = NULL;
	if (error_count == 0) {           // success!
		pr_err("%s: Successfully performed binary write to user space app\n", DEVICE_NAME);	  
		return 0; // clear the position to the start and return 0
	}
	else {
		pr_err("%s: Failed to send %d bytes to the user\n", DEVICE_NAME, error_count);	  
		return -EFAULT;      // Failed - return a bad address message
	}
}

int pH_profile_disk2mem(pH_disk_profile*, pH_profile*);

static ssize_t dev_write(struct file *filep, const char *buf, size_t len, loff_t *offset) {
	const char* buffer;
	int ret;
	pH_profile* profile = NULL;
	
	user_process_has_been_loaded = TRUE;
	binary_read = FALSE;
	
	pr_err("%s: In dev_write\n", DEVICE_NAME);
	
	if (numberOpens > 0) {		
		// Allocate space for buffer
		buffer = kmalloc(sizeof(char) * 254, GFP_ATOMIC);
		if (!buffer) {
			pr_err("%s: Unable to allocate memory for dev_write buffer", DEVICE_NAME);
			return len;
		}
		
		buffer = (char*) buf;
		strcpy(message, buffer);
		//kfree(buffer); // Freeing this causes an error for some reason?
		size_of_message = strlen(message); // Store the length of the stored message
		pr_err("%s: Did some setup\n", DEVICE_NAME);
		
		// If we failed to receive a message, kill the userspace app and return -1
		if (message == NULL || size_of_message < 1) {
            pr_err("%s: Failed to read the message from userspace.%d%d\n", DEVICE_NAME, message == NULL, size_of_message < 1);
            
            if (send_signal(SIGTERM) < 0) send_signal(SIGKILL);
            
            pr_err("%s: Userspace process killed\n", DEVICE_NAME);
            
            return -1;
        }
        
        pr_err("%s: Received message [%s] from userspace app\n", DEVICE_NAME, message);
		
		/*
		// If we have the PID of the userspace process, suspend the process
		if (have_userspace_pid) {			
			if (profile_queue_is_empty()) {
				// Send SIGSTOP signal to the userspace app
				ret = send_signal(SIGSTOP);
				if (ret < 0) return ret;
			
				// We are done waiting for the user now
				done_waiting_for_user = TRUE;
			
				return 0; // Depending on the situation, we may want to process what the user sent us before returning
			}
		}
		*/
		
		// If you do not have the userspace pid, then you must be getting it right now
		if (!have_userspace_pid) {
			// Convert the string message to a long and store it in userspace_pid
			kstrtol(message, 10, &userspace_pid);
			have_userspace_pid = TRUE;
			pr_err("%s: Received %ld PID from userspace\n", DEVICE_NAME, userspace_pid);
		}
		
		if (output_string[0] == 'r' && output_string[1] == 'b') {
			pr_err("%s: In READ_PROFILE_FROM_DISK if\n", DEVICE_NAME);
			
			if (strcmp("success", message) != 0) {
				pr_err("%s: Received non-success message from userspace [%s]\n", DEVICE_NAME, message);
				
				// Send SIGSTOP signal to the userspace app
				ret = send_signal(SIGSTOP);
				if (ret < 0) return ret;
				
				if (strcmp(message, "Failed to find disk profile") == 0) {
					profile = __vmalloc(sizeof(pH_profile), GFP_ATOMIC, PAGE_KERNEL);
					if (!profile || profile == NULL) {
						pr_err("%s: Unable to allocate memory for profile in dev_write\n", DEVICE_NAME);
						return len;
					}
					
					if (spin_is_locked(&execve_count_lock)) {
						spin_unlock(&execve_count_lock);
						pr_err("%s: Unlocked execve_count_lock\n", DEVICE_NAME);
					}
				}
				
				// Depending on the situation, we may want to process what the user sent us before returning
				return 0;
			}
			
			if (buffer == NULL) {
				pr_err("%s: Received NULL from userspace\n", DEVICE_NAME);
				pr_err("%s: This is either an error or no matching disk profile.\n", DEVICE_NAME);
				pr_err("%s: Deal with this as you will, I am returning.\n", DEVICE_NAME);
			
				// Send SIGSTOP signal to the userspace app
				ret = send_signal(SIGSTOP);
				if (ret < 0) return ret;
			
				// Depending on the situation, we may want to process what the user sent us before returning
				return 0;
			}
		
			profile = __vmalloc(sizeof(pH_profile), GFP_ATOMIC, PAGE_KERNEL);
			if (!profile || profile == NULL) {
				pr_err("%s: Unable to allocate memory for profile in dev_write\n", DEVICE_NAME);
				return len;
			}
		
			pr_err("%s: Copying from disk to mem...\n", DEVICE_NAME);
			pH_profile_disk2mem((pH_disk_profile*) buffer, profile);
		
			pr_err("%s: Adding to profile list...\n", DEVICE_NAME);
			add_to_profile_llist(profile);
			
			if (spin_is_locked(&execve_count_lock)) {
				spin_unlock(&execve_count_lock);
				pr_err("%s: Unlocked execve_count_lock\n", DEVICE_NAME);
			}
		}
		pr_err("%s: After READ_PROFILE_FROM_DISK if\n", DEVICE_NAME);
		
		// If we have the PID of the userspace process, suspend the process
		if (profile_queue_is_empty()) {
			// Send SIGSTOP signal to the userspace app
			ret = send_signal(SIGSTOP);
			if (ret < 0) return ret;
		
			// We are done waiting for the user now
			done_waiting_for_user = TRUE;
			return 0;
			
			// Depending on the situation, we may want to process what the user sent us before returning
			if (strcmp("success", message) == 0) {
				pr_err("%s: Received non-success message from userspace [%s]\n", DEVICE_NAME, message);
				return 0;
			}
			pr_err("%s: Received success message from userspace\n", DEVICE_NAME);
		}
	}

	return 0;
}

// This shares some code with ebbchar_exit, so perhaps I will want to use a helper function for
// both of them to limit duplicated code
static int dev_release(struct inode *inodep, struct file *filep){
	// Set all booleans to FALSE
	module_inserted_successfully = FALSE;
	pH_aremonitoring             = 0;
	done_waiting_for_user        = FALSE;
	have_userspace_pid           = FALSE;
	binary_read                  = FALSE;
	user_process_has_been_loaded = FALSE;
	
	pr_err("%s: Releasing device...\n", DEVICE_NAME);
	
	// Deallocate memory for appropriate pointers
	kfree(output_string);
	output_string = NULL;
	pr_err("%s: vfreeing bin_receive_ptr...\n", DEVICE_NAME);
	vfree(bin_receive_ptr);
	bin_receive_ptr = NULL;
	
	while (!profile_queue_is_empty()) {
		pr_err("%s: vfreeing return from remove_from_profile_queue...\n", DEVICE_NAME);
		vfree(remove_from_profile_queue());
	}
	
	pr_err("%s: Freeing pH_task_structs...\n", DEVICE_NAME);
	free_pH_task_structs();
	
	// Unlock the mutex
	mutex_unlock(&ebbchar_mutex);
	
	pr_err("%s: Device has been released (please reinsert for further testing)\n", DEVICE_NAME);
	
	return 0;
}

inline void pH_append_call(pH_seq* s, int new_value) {
	if (s->last < 0) { pr_err("%s: s->last is not initialized!\n", DEVICE_NAME); return; }
	ASSERT(s->length != 0);
	
	s->last = (s->last + 1) % (s->length);
	s->data[s->last] = new_value;
}

int pH_add_seq_storage(pH_profile_data *data, int val)
{
    int i;
    
    /*
    for (i = 0; i < data->count_page; i++) {
    	
    	
    	for (j = 0; j < PH_NUM_SYSCALLS; j++) {
			data->entry[val][j] = 0;
		}
    }
    pr_err("%s: Iterated over data->entry[val]\n", DEVICE_NAME);
    */
    
    /*
    for (i = 0; i < PH_NUM_SYSCALLS; i++) {
    	data->entry[val][i] = kmalloc(sizeof(pH_seqflags), GFP_ATOMIC);
    	if (!data->entry[val][i]) {
    		pr_err("%s: Unable to allocate memory in pH_add_seq_storage\n", DEVICE_NAME);
    		return -ENOMEM;
    	}
    }
    pr_err("%s: Iterated over data->entry[val]\n", DEVICE_NAME);
    */
    
    data->entry[val] = kmalloc(sizeof(pH_seqflags) * PH_NUM_SYSCALLS, GFP_ATOMIC);
    if (!data->entry[val]) {
    	pr_err("%s: Unable to allocate memory in pH_add_seq_storage\n", DEVICE_NAME);
    	return -ENOMEM;
    }
    
    for (i = 0; i < PH_NUM_SYSCALLS; i++) {
    	data->entry[val][i] = 0;
    }
    //pr_err("%s: Iterated over data->entry[val]\n", DEVICE_NAME);
    
    return 0;
}

void pH_add_seq(pH_seq *s, pH_profile_data *data)
{
	int i, cur_call, prev_call, cur_idx;
	u8 *seqdata = s->data;
	int seqlen = s->length;
	//pr_err("%s: Initialized variables for pH_add_seq\n", DEVICE_NAME);

	if (!data || data == NULL) {
		pr_err("%s: ERROR: data is NULL in pH_add_seq\n", DEVICE_NAME);
		return;
	}
	
	ASSERT(seqlen != 0);

	cur_idx = s->last;
	cur_call = seqdata[cur_idx];
	//pr_err("%s: Initialized cur_idx and cur_call\n", DEVICE_NAME);

	for (i = 1; i < seqlen; i++) {
		//pr_err("%s: PH_NUM_SYSCALLS = %d\n", DEVICE_NAME, PH_NUM_SYSCALLS); // PH_NUM_SYSCALLS = 361
		//pr_err("%s: i=%d cur_call=%d prev_call=%d cur_idx=%d\n", DEVICE_NAME, i, cur_call, prev_call, cur_idx);
		if (data->entry[cur_call] == NULL) {
			//pr_err("%s: data->entry[cur_call] == NULL\n", DEVICE_NAME);
			if (pH_add_seq_storage(data, cur_call)) {
				pr_err("%s: pH_add_seq_storage returned a non-zero value\n", DEVICE_NAME);
				return;
			}
		}
		//pr_err("%s: Made it through if\n", DEVICE_NAME);
		prev_call = seqdata[(cur_idx + seqlen - i) % seqlen];
		//pr_err("%s: Set prev_call to %d\n", DEVICE_NAME, prev_call);
		
		//pr_err("%s: The range for cur_call is %p to %p\n", DEVICE_NAME, &(data->entry[cur_call]), &(data->entry[cur_call][PH_NUM_SYSCALLS-1]));
		
		if (cur_call < 0 || cur_call > PH_NUM_SYSCALLS) {
			pr_err("%s: cur_call is out of bounds\n", DEVICE_NAME);
		}
		if (prev_call < 0 || prev_call > PH_NUM_SYSCALLS) {
			pr_err("%s: prev_call is out of bounds\n", DEVICE_NAME);
		}
		if (data->entry[cur_call][prev_call] < 0 || data->entry[cur_call][prev_call] > 256) {
			pr_err("%s: Value is not in the interval [0, 256] (%d)\n", DEVICE_NAME, data->entry[cur_call][prev_call]);
		}
		if (!pH_aremonitoring) {
			return;
		}
		data->entry[cur_call][prev_call] |= (1 << (i - 1));
		//pr_err("%s: data->entry[cur_call][prev_call] = %d\n", DEVICE_NAME, data->entry[cur_call][prev_call]);
		
		/*
		Here we have a chunk of code where we replicate the above line in a bunch of
		shorter lines to help with debugging
		*/
		/*
		pH_seqflags** entry;
		int *cur_call_array;
		pH_seqflags *cur_seqflags;
		int i_minus_one;
		int after_shift_op;
		pr_err("%s: Declared required variables for test code\n", DEVICE_NAME);
		
		entry = data->entry;
		pr_err("%s: Initialized entry (entry = %p, data->entry = %p)\n", DEVICE_NAME, entry, data->entry);
		cur_call_array = entry[cur_call];
		pr_err("%s: Initialized cur_call_array (cur_call_array = %p, entry[cur_call] = %p)\n", DEVICE_NAME, cur_call_array, data->entry[cur_call]);
		cur_seqflags = &(cur_call_array[prev_call]);
		pr_err("%s: data->entry[cur_call][prev_call] = %d\n", DEVICE_NAME, data->entry[cur_call][prev_call]);
		pr_err("%s: Initialized required variables for test code\n", DEVICE_NAME);

		//int cur_seqflags_value = (int) *cur_seqflags;
		//pr_err("%s: Got cur_seqflags_value\n", DEVICE_NAME);
		
		//cur_seqflags = &(data->entry[cur_call][prev_call]);

		pr_err("%s: data->entry[cur_call][prev_call] address is %p\n", DEVICE_NAME, &(data->entry[cur_call][prev_call]));
		pr_err("%s: cur_seqflags address is %p\n", DEVICE_NAME, cur_seqflags);
		pr_err("%s: cur_seqflags value is %d\n", DEVICE_NAME, *cur_seqflags);
		
		i_minus_one = i - 1;
		//pr_err("%s: i - 1 = %d\n", DEVICE_NAME, i_minus_one);
		after_shift_op = 1 << i_minus_one;
		//pr_err("%s: 1 << (i - 1) = %d\n", DEVICE_NAME, after_shift_op);
		
		*cur_seqflags = *cur_seqflags | after_shift_op;
		pr_err("%s: data->entry[cur_call][prev_call] = %d\n", DEVICE_NAME, data->entry[cur_call][prev_call]);
		pr_err("%s: cur_seqflags = %d\n", DEVICE_NAME, *cur_seqflags);
		pr_err("%s: Successfully got through entire expansion of trouble line\n", DEVICE_NAME);
		*/
	}
}

int pH_test_seq(pH_seq *s, pH_profile_data *data)
{
	int i, cur_call, prev_call, cur_idx;
	u8 *seqdata = s->data;
	int seqlen = s->length;
	int mismatches = 0;

	ASSERT(seqlen != 0);

	cur_idx = s->last;
	cur_call = seqdata[cur_idx];

	// If the current syscall has not been encountered, everything (seqlen-1) is a mismatch
	if (data->entry[cur_call] == NULL)
		    return (seqlen - 1);

	// Iterates over seqlen-1 times - skips 0th position because it was checked above
	for (i = 1; i < seqlen; i++) {
	    // Retrieves the previous call
	    prev_call = seqdata[(cur_idx + seqlen - i) % seqlen];
	    
	    if ((data->entry[cur_call][prev_call] & (1 << (i - 1))) == 0) {
	            mismatches++;
	    }
	}

	return mismatches;
}

inline void pH_train(pH_task_struct *s)
{
    pH_seq *seq = s->seq;
    pH_profile *profile = s->profile;
    pH_profile_data *train = &(profile->train);

	//pr_err("%s: In pH_train\n", DEVICE_NAME);

    train->train_count++;
    if (pH_test_seq(seq, train)) {
        if (profile->frozen) {
                profile->frozen = 0;
                action("%d (%s) normal cancelled", current->pid, profile->filename);
        }
        pH_add_seq(seq, train);
        train->sequences++; 
        train->last_mod_count = 0;

        //pH_log_sequence(profile, seq);
    
    } else {
        unsigned long normal_count; 
        
        train->last_mod_count++;
        
        if (profile->frozen) {
                //mutex_unlock(&(profile->lock));
                return;
        }

        normal_count = train->train_count - train->last_mod_count; 

        if ((normal_count > 0) && ((train->train_count * pH_normal_factor_den) > (normal_count * pH_normal_factor))) {
                action("%d (%s) frozen", current->pid, profile->filename);
                profile->frozen = 1;
                //profile->normal_time = xtime.tv_sec + pH_normal_wait;
        }
    }
}

void pH_profile_data_mem2disk(pH_profile_data *mem, pH_disk_profile_data *disk)
{
        //int i, j;

        disk->sequences = mem->sequences;
        disk->last_mod_count = mem->last_mod_count;
        disk->train_count = mem->train_count;

		/*
        for (i = 0; i < PH_NUM_SYSCALLS; i++) {
                if (mem->entry[i] == NULL) {
                        disk->empty[i] = 1;
                        for (j = 0; j < PH_NUM_SYSCALLS; j++) {
                                disk->entry[i][j] = 0;
                        }
                } else {
                        disk->empty[i] = 0;
                        //memcpy(disk->entry[i], mem->entry[i], PH_NUM_SYSCALLS);
                }
        }
        */
}

// I will eventually want to uncomment the commented lines below and run them without
// any issues
void pH_profile_mem2disk(pH_profile *profile, pH_disk_profile *disk_profile)
{
    /* make sure magic is less than PH_FILE_MAGIC_LEN! */
    strcpy(disk_profile->magic, PH_FILE_MAGIC);
    disk_profile->normal = profile->normal;
	pr_err("%s: original normal is %d\n", DEVICE_NAME, profile->normal);
    disk_profile->frozen = profile->frozen;
    pr_err("%s: original frozen is %d\n", DEVICE_NAME, profile->frozen);
    disk_profile->normal_time = profile->normal_time;
    disk_profile->length = profile->length;
    pr_err("%s: original length is %d\n", DEVICE_NAME, profile->length);
    disk_profile->count = profile->count;
    disk_profile->anomalies = profile->anomalies;
    pr_err("%s: original anomalies is %d\n", DEVICE_NAME, profile->anomalies);
    strncpy(disk_profile->filename, profile->filename, PH_MAX_DISK_FILENAME);

    //pH_profile_data_mem2disk(&(profile->train), &(disk_profile->train));
    //pH_profile_data_mem2disk(&(profile->test), &(disk_profile->test));
}

int pH_profile_data_disk2mem(pH_disk_profile_data *disk, pH_profile_data *mem)
{
    int i;

    mem->sequences = disk->sequences;
    mem->last_mod_count = disk->last_mod_count;
    mem->train_count = disk->train_count;

    for (i = 0; i < PH_NUM_SYSCALLS; i++) {
        if (disk->empty[i]) {
                mem->entry[i] = NULL;
        } else {
                if (pH_add_seq_storage(mem, i))
                        return -1;
                memcpy(mem->entry[i], disk->entry[i], PH_NUM_SYSCALLS);
        }
    }
    
    return 0;
}

int pH_profile_disk2mem(pH_disk_profile *disk_profile, pH_profile *profile)
{
    profile->normal = disk_profile->normal;
    profile->frozen = disk_profile->frozen;
    profile->normal_time = disk_profile->normal_time;
    profile->length = disk_profile->length;
    profile->count = disk_profile->count;
    profile->anomalies = disk_profile->anomalies;

    if (pH_profile_data_disk2mem(&(disk_profile->train),
                                 &(profile->train)))
            return -1;

    if (pH_profile_data_disk2mem(&(disk_profile->test),
                                 &(profile->test)))
            return -1;

    return 0;
}

module_init(ebbchar_init);
module_exit(ebbchar_exit);
