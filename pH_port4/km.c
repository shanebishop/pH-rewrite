/*
URL for cloning: https://github.com/shanebishop/pH-rewrite.git

Notes:
-Know when to use retreive_pH_profile_by_filename instead of retreive_pH_profile_by_pid
-When retrieving the PID of a process, use pid_vnr(task_tgid(tsk));, where tsk is the task_struct of 
the particular process
-Make sure that syscalls are still processed even while waiting to hear back from the user
-Make sure to update filenames and stuff when done (including ebbchar_init, ebbchar_exit, and 
ebbchar_mutex)
-Never use booleans to stop code from running after a fatal error, instead use panic() with a detailed
eror message (code should ONLY stop running on panic or rmmod)
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
#define TRUE  (1 == 1)
#define FALSE !TRUE

static int    majorNumber;
//static char   message[256] = {0};
//static short  size_of_message;
//static int    numberOpens = 0;
static struct class*  ebbcharClass  = NULL;
static struct device* ebbcharDevice = NULL;

const char *PH_FILE_MAGIC="pH profile 0.18\n";

static DEFINE_MUTEX(ebbchar_mutex);

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
	my_syscall* syscall_llist;
	long process_id;
	pH_locality alf;
	pH_seq* seq;
	spinlock_t pH_seq_stack_sem;
	int delay;
	unsigned long count;
	pH_profile* profile; // Pointer to appropriate profile
} pH_task_struct;

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
pH_task_struct* pH_task_struct_list = NULL; // List of processes currently being monitored
struct jprobe jprobes_array[num_syscalls];  // Array of jprobes (is this obsolete?)
bool module_inserted_successfully = FALSE;
spinlock_t pH_profile_list_sem;             // Lock for list of profiles
spinlock_t pH_task_struct_list_sem;         // Lock for process list
int profiles_created = 0;                   // Number of profiles that have been created
int successful_jsys_execves = 0;            // Number of successful jsys_execves

// Returns true if the process is being monitored, false otherwise
inline bool pH_monitoring(pH_task_struct* process) {
        return process->profile != NULL;
}

// Returns true if the profile is in use, false otherwise
inline bool pH_profile_in_use(pH_profile *profile)
{
        return (atomic_read(&(profile->refcount)) > 0);
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
inline void pH_refcount_init(pH_profile *profile, int i)
{
        profile->refcount.counter = i;
}

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

// Returns the length of the process list
int pH_task_struct_list_length(void) {
	pH_task_struct* iterator;
	int i;
	
	spin_lock(&pH_task_struct_list_sem);
	for (i = 0, iterator = pH_task_struct_list; 
		iterator != NULL; 
		i++, iterator = iterator->next) 
	{
		;
	}
	spin_unlock(&pH_task_struct_list_sem);
	
	return i;
}

// Adds an alloc'd profile to the profile list
void add_to_profile_llist(pH_profile* p) {
	pr_err("%s: In add_to_profile_llist\n", DEVICE_NAME);
	
	// Checks for adding a NULL profile
	if (!p || p == NULL) {
		pr_err("%s: In add_to_profile_llist with a NULL profile\n", DEVICE_NAME);
		return;
	}
	
	spin_lock(&pH_profile_list_sem);
	if (pH_profile_list == NULL) {
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
		
		p->next = pH_profile_list;
		pH_profile_list = p;
	}
	spin_unlock(&pH_profile_list_sem);
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

	// Allocates memory for the lock
	profile->lock = kmalloc(sizeof(spinlock_t), GFP_ATOMIC);
	if (!(profile->lock) || profile->lock == NULL) {
		pr_err("%s: Unable to allocate memory for profile->lock in new_profile()\n", DEVICE_NAME);
		return -ENOMEM;
	}
	spin_lock_init(profile->lock);

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

	profile->next = NULL;
	pH_refcount_init(profile, 0);
	profile->filename = filename;

	//pH_open_seq_logfile(profile);

	// Add this new profile to the hashtable
	//hash_add(profile_hashtable, &profile->hlist, pid_vnr(task_tgid(current)));
	
	// Add this new profile to the llist
	add_to_profile_llist(profile);

	return 0;
}

// Adds a syscall to the linked list in its pH_task_struct
void add_to_my_syscall_llist(pH_task_struct* t, my_syscall* s) {
	//pr_err("%s: In add_to_my_syscall_llist\n", DEVICE_NAME);
	
	if (t->syscall_llist == NULL) {
		t->syscall_llist = s;
		s->next = NULL;
	}
	else {
		/* // Old implementation
		my_syscall* iterator = t->syscall_llist;
		
		while (iterator->next) iterator = iterator->next;
		
		iterator->next = s;
		s->next = NULL;
		*/
		
		s->next = t->syscall_llist;
		t->syscall_llist = s;
	}
}

// One issue with this function is if the process_id goes out of use or is reused while the lock
// is held, it might return an incorrect result. Perhaps this is why my code is crashing.
pH_task_struct* llist_retrieve_process(int process_id) {
	pH_task_struct* iterator = pH_task_struct_list;
	
	// Checks to see if this function can execute in this instance
	if (!module_inserted_successfully || !pH_aremonitoring) {
		pr_err("%s: ERROR: llist_retrieve_process called before module has been inserted correctly\n", DEVICE_NAME);
		return NULL;
	}
	
	//pr_err("%s: In llist_retrieve_process\n", DEVICE_NAME);

	if (pH_task_struct_list == NULL) {
		return NULL;
	}
	
	spin_lock(&pH_task_struct_list_sem);
	do {
		if (iterator->process_id == process_id) {
			//pr_err("%s: Found it! Returning\n", DEVICE_NAME);
			spin_unlock(&pH_task_struct_list_sem);
			return iterator;
		}
		iterator = iterator->next;
	} while (iterator);
	spin_unlock(&pH_task_struct_list_sem);
	
	//pr_err("%s: Process %d not found\n", DEVICE_NAME, process_id);
	return NULL;
}

void stack_push(pH_task_struct*, pH_seq*);

// Initializes a new pH_seq and then adds it to the stack of pH_seqs
int make_and_push_new_pH_seq(pH_task_struct* process) {
	pH_profile* profile;
	pH_seq* new_sequence;
	
	// Checks for NULL process
	if (!process || process == NULL) {
		pr_err("%s: process is NULL in make_and_push_new_pH_seq\n", DEVICE_NAME);
		return 0;
	}
	
	profile = process->profile;
	
	// Checks for NULL profile
	if (!profile || profile == NULL) {
		pr_err("%s: profile is NULL in make_and_push_new_pH_seq\n", DEVICE_NAME);
		return -1;
	}
	
	// Allocates space for the new pH_seq
	new_sequence = kmalloc(sizeof(pH_seq), GFP_ATOMIC);
	if (!new_sequence || new_sequence == NULL) {
		pr_err("%s: Unable to allocate space for new_sequence in make_and_push_new_pH_seq\n", DEVICE_NAME);
		return -ENOMEM;
	}
	
	// Initialize the new pH_seq and push it onto the stack
	//pr_err("%s: Initializing new_sequence in make_and_push_new_pH_seq...\n", DEVICE_NAME);
	new_sequence->next = NULL;
	//pr_err("%s: Set new_sequence->next to NULL\n", DEVICE_NAME);
	new_sequence->length = profile->length;
	//pr_err("%s: Set new_sequence->length to %d\n", DEVICE_NAME, profile->length);
	new_sequence->last = profile->length - 1;
	//pr_err("%s: Set new_sequence->last to %d\n", DEVICE_NAME, profile->length - 1);
	stack_push(process, new_sequence);
	//pr_err("%s: Pushed new_sequence\n", DEVICE_NAME);
	//pr_err("%s: Exiting make_and_push_new_pH_seq\n", DEVICE_NAME);
	return 0;
}

// Function prototypes for process_syscall()
inline void pH_append_call(pH_seq*, int);
inline void pH_train(pH_task_struct*);
//void stack_print(pH_task_struct*);

// Processes a system call
int process_syscall(long syscall) {
	pH_task_struct* process;
	my_syscall* new_syscall;
	pH_profile* profile;
	
	// Boolean checks
	if (!module_inserted_successfully) return 0;
	
	if (!pH_aremonitoring) return 0;
	
	if (!pH_task_struct_list || pH_task_struct_list == NULL) return 0;

	//pr_err("%s: In process_syscall\n", DEVICE_NAME);
	
	// Retrieve process
	process = llist_retrieve_process(pid_vnr(task_tgid(current)));
	if (!process) {
		// Ignore this syscall
		return 0;
	}
	//pr_err("%s: syscall=%d\n", DEVICE_NAME, syscall);
	//pr_err("%s: Retrieved process successfully\n", DEVICE_NAME);
	
	if (process) profile = process->profile; // Store process->profile in profile for shorter reference
	else {
		pr_err("%s: ERROR: process is NULL\n", DEVICE_NAME);
		return -1;
	}
	
	if (!profile || profile == NULL) {
		pr_err("%s: pH_task_struct corrupted: No profile\n", DEVICE_NAME);
		return -1;
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
		return -1;
	}
	
	//pr_err("%s: Locking profile->lock\n", DEVICE_NAME);
	spin_lock(profile->lock); // Grabs the lock to this profile
	
	if (process && (process->seq) == NULL) {
		pH_seq* temp = (pH_seq*) kmalloc(sizeof(pH_seq), GFP_ATOMIC);
		if (!temp) {
			pr_err("%s: Unable to allocate memory for temp in process_syscall\n", DEVICE_NAME);
			spin_unlock(profile->lock);
			return -ENOMEM;
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
	//pr_err("%s: Successfully appended call %d\n", DEVICE_NAME, syscall);
	
	//pr_err("%s: &(profile->count) = %p\n", DEVICE_NAME, &(profile->count));
	profile->count++;
	//pr_err("%s: profile->count = %d\n", DEVICE_NAME, profile->count);
	spin_unlock(profile->lock);
	
	//pr_err("%s: process = %p %d\n", DEVICE_NAME, process, process != NULL);
	///pr_err("%s: profile = %p %d\n", DEVICE_NAME, profile, profile != NULL);
	
	if (process) pH_train(process);
	else {
		pr_err("%s: ERROR: process is NULL\n", DEVICE_NAME);
		return -1;
	}
	//pr_err("%s: Trained process\n", DEVICE_NAME);
	
	// Allocate space for new_syscall
	new_syscall = kmalloc(sizeof(my_syscall), GFP_ATOMIC);
	if (!new_syscall) {
		pr_err("%s: Unable to allocate space for new_syscall\n", DEVICE_NAME);
		kfree(process->seq);
		return -ENOMEM;
	}
	//pr_err("%s: Successfully allocated space for new_syscall\n", DEVICE_NAME);
	
	// Add new_syscall to the linked list of syscalls
	new_syscall->syscall_num = syscall;
	add_to_my_syscall_llist(process, new_syscall);
	
	//pr_err("%s: Finished processing syscall %ld\n", DEVICE_NAME, syscall);
	
	return 0;
}

// Adds a process to the linked list of processes
void add_process_to_llist(pH_task_struct* t) {
	// Checks for NULL
	if (!t || t == NULL) {
		pr_err("%s: Received NULL pH_task_struct in add_process_to_llist\n", DEVICE_NAME);
		return;
	}
	
	spin_lock(&pH_task_struct_list_sem);
	if (pH_task_struct_list == NULL) {
		pH_task_struct_list = t;
		t->next = NULL;
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
	}
	spin_unlock(&pH_task_struct_list_sem);
}

// Returns a pH_profile, given a filename
pH_profile* retrieve_pH_profile_by_filename(char* filename) {
	pH_task_struct* process_list_iterator;
	pH_profile* profile_list_iterator = pH_profile_list;
	
	if (pH_task_struct_list == NULL || pH_profile_list == NULL) {
		return NULL;
	}
	pr_err("%s: pH_profile_list is not NULL\n", DEVICE_NAME);
	
	// Search through profile list
	spin_lock(&pH_profile_list_sem);
	do {
		if (strcmp(filename, profile_list_iterator->filename) == 0) {
			//pr_err("%s: Found it! Returning\n", DEVICE_NAME);
			spin_unlock(&pH_profile_list_sem);
			return profile_list_iterator;
		}
		
		profile_list_iterator = profile_list_iterator->next;
		//pr_err("%s: Iterating\n", DEVICE_NAME);
	} while (profile_list_iterator);
	spin_unlock(&pH_profile_list_sem);
	
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

void free_pH_task_struct(pH_task_struct*);

// Helper function for jsys_execve and fork_handler, as both instances require similar code
int handle_new_process(char* path_to_binary, pH_profile* profile, int process_id) {
	pH_task_struct* this_process;
	
	//pr_err("%s: In handle_new_process for %d %s\n", DEVICE_NAME, process_id, path_to_binary);
	
	// Allocate memory for this process
	this_process = kmalloc(sizeof(pH_task_struct), GFP_ATOMIC);
	if (!this_process) {
		pr_err("%s: Unable to allocate memory for this process\n", DEVICE_NAME);
		goto no_memory;
	}
	
	// Initialize this process - check with Anil to see if these are the right values to initialize it to
	this_process->process_id = process_id;
	//pH_reset_ALF(this_process);
	this_process->seq = NULL;
	//spin_lock_init(&(this_process->pH_seq_stack_sem));
	this_process->syscall_llist = NULL;
	this_process->delay = 0;
	this_process->count = 0;
	//pr_err("%s: Initialized process\n", DEVICE_NAME);
	
	if (!profile || profile == NULL) {
		// Retrieve the corresponding profile
		profile = retrieve_pH_profile_by_filename(path_to_binary);
		//pr_err("%s: Attempted to retrieve profile\n", DEVICE_NAME);
		
		// If there is no corresponding profile, make a new one
		if (!profile || profile == NULL) {
			profile = __vmalloc(sizeof(pH_profile), GFP_ATOMIC, PAGE_KERNEL);
			if (!profile) {
				pr_err("%s: Unable to allocate memory for profile in handle_new_process\n", DEVICE_NAME);
				goto no_memory;
			}
			
			new_profile(profile, path_to_binary);
			pr_err("%s: Made new profile for %s\n", DEVICE_NAME, path_to_binary);
			
			if (!profile || profile == NULL) {
				pr_err("%s: new_profile() made a corrupted or NULL profile\n", DEVICE_NAME);
			}
		}
		else {
			kfree(path_to_binary);
			path_to_binary = NULL;
		}
	}
	
	pH_refcount_inc(profile); // Increment refcount
	
	this_process->profile = profile; // Put this profile in the pH_task_struct struct

	add_process_to_llist(this_process); // Add this process to the list of processes
	//pr_err("%s: Added this process to llist\n", DEVICE_NAME);
	
	return 0;

no_memory:
	pr_err("%s: Ran out of memory\n", DEVICE_NAME);
	
	kfree(path_to_binary);
	path_to_binary = NULL;
	free_pH_task_struct(this_process);
	this_process = NULL;
	
	return -ENOMEM;
}

// Handler function for execves
static long jsys_execve(const char __user *filename,
	const char __user *const __user *argv,
	const char __user *const __user *envp)
{
	char* path_to_binary;
	int current_process_id;

	// Boolean checks
	if (!module_inserted_successfully) goto not_inserted;
	
	if (!pH_aremonitoring) goto not_monitoring;

	//pr_err("%s: In jsys_execve\n", DEVICE_NAME);
	
	current_process_id = pid_vnr(task_tgid(current)); // Grab the process ID right now
	
	// Allocate space for path_to_binary
	path_to_binary = kmalloc(sizeof(char) * 4000, GFP_ATOMIC);
	if (!path_to_binary) {
		pr_err("%s: Unable to allocate memory for path_to_binary\n", DEVICE_NAME);
		goto no_memory;
	}
	
	// Copy memory from userspace to kernel land
	copy_from_user(path_to_binary, filename, sizeof(char) * 4000);
	//pr_err("%s: path_to_binary = %s\n", DEVICE_NAME, path_to_binary);
	
	// Checks to see if path_to_binary is okay - perhaps move this to handle_new_process()
	if (!path_to_binary || path_to_binary == NULL || strlen(path_to_binary) < 1 || 
		!(*path_to_binary == '~' || *path_to_binary == '.' || *path_to_binary == '/'))
	{
		//pr_err("%s: In jsys_execve with corrupted path_to_binary: [%s]\n", DEVICE_NAME, path_to_binary);
		goto corrupted_path_to_binary;
	}
	
	// Handle the new process
	handle_new_process(path_to_binary, NULL, current_process_id);
	
	process_syscall(59); // Process this system call
	//pr_err("%s: Back in jsys_execve after processing syscall\n", DEVICE_NAME);
	
	successful_jsys_execves++; // Increment successful_jsys_execves
	
	jprobe_return();
	return 0;
	
no_memory:
	pr_err("%s: Ran out of memory\n", DEVICE_NAME);
	
	kfree(path_to_binary);
	path_to_binary = NULL;
	
	jprobe_return();
	return 0;
	
not_inserted:
	//pr_err("%s: Module was not inserted successfully\n", DEVICE_NAME);
	jprobe_return();
	return 0;
	
not_monitoring:
	//pr_err("%s: Not monitoring\n", DEVICE_NAME);
	jprobe_return();
	return 0;

corrupted_path_to_binary:
	kfree(path_to_binary);
	path_to_binary = NULL;
	
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

// Struct required for all kretprobe structs
struct my_kretprobe_data {
	ktime_t entry_stamp;
};

// Currently a child process can only be handled if the pH_task_struct for the parent
// process is still in memory. This is because pH_profiles require the absolute path
// to the binary file, which I currently only know how to retrieve from sys_execve calls.
static int fork_handler(struct kretprobe_instance* ri, struct pt_regs* regs) {
	int retval;
	ktime_t now;
	pH_task_struct* parent_process;
	char* path_to_binary;
	pH_profile* profile;
	
	// Boolean check
	if (!module_inserted_successfully) return 0;
	
	//pr_err("%s: In fork_handler\n", DEVICE_NAME);
	
	retval = regs_return_value(regs);
	now = ktime_get();
	
	if (retval < 0) return 0; // fork() returned error - did not create child process
	
	// Retrieve binary by using current to retrieve PID, and then grab the task struct then binary from there
	parent_process = llist_retrieve_process(pid_vnr(task_tgid(current)));
	if (!parent_process || parent_process == NULL) {
		//pr_err("%s: In fork_handler with NULL parent_process\n", DEVICE_NAME);
		return -1;
	}
	
	profile = parent_process->profile;
	if (!profile || profile == NULL) {
		//pr_err("%s: In fork_handler with NULL parent_process->profile\n", DEVICE_NAME);
		return -1;
	}
	
	path_to_binary = profile->filename;
	
	// Checks to see if path_to_binary is okay - perhaps move this to handle_new_process()
	if (!path_to_binary || path_to_binary == NULL || strlen(path_to_binary) < 1 || 
		!(*path_to_binary == '~' || *path_to_binary == '.' || *path_to_binary == '/'))
	{
		pr_err("%s: In fork_handler with corrupted path_to_binary: [%s]\n", DEVICE_NAME, path_to_binary);
		return -1;
	}
	
	// Handle the new process
	handle_new_process(path_to_binary, profile, retval);
	
	return 0;
}

static struct kretprobe fork_kretprobe = {
	.handler = fork_handler,
	.data_size = sizeof(struct my_kretprobe_data),
	.maxactive = 20,
};

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
	.handler = /*(kprobe_opcode_t*)*/ exit_handler,
	.data_size = sizeof(struct my_kretprobe_data),
	.maxactive = 20,
};

static int sys_rt_sigreturn_handler(struct kretprobe_instance* ri, struct pt_regs* regs) {
	int retval;
	ktime_t now;
	pH_task_struct* process;
	
	if (!module_inserted_successfully) return 0;
	
	pr_err("%s: In sys_rt_sigreturn_handler for %d\n", DEVICE_NAME, pid_vnr(task_tgid(current)));
	
	process = llist_retrieve_process(pid_vnr(task_tgid(current)));
	
	if (process == NULL) return 0;
	
	retval = regs_return_value(regs);
	now = ktime_get();
	
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

// Frees profile storage
void pH_free_profile_storage(pH_profile *profile)
{
    int i;

	pr_err("%s: In pH_free_profile_storage for %d\n", DEVICE_NAME, profile->identifier);

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
    
    pr_err("%s: Exiting pH_free_profile_storage\n", DEVICE_NAME);
}

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

// Returns 0 on success and anything else on failure
// Calling functions (currently only pH_free_profile) MUST handle returned errors if possible
// Currently does not hold any locks, and therefore calling functions must lock appropriately
int pH_remove_profile_from_list(pH_profile *profile)
{
    pH_profile *prev_profile, *cur_profile;
    
    // NULL check
	if (!profile || profile == NULL) return 0;
	
	// Only remove a profile if the refcount == 0
	if (atomic_read(&(profile->refcount)) != 0) {
		pr_err("%s: ERROR: Trying to remove a profile that is in use\n", DEVICE_NAME);
		return -1;
	}

    pr_err("%s: In pH_remove_profile_from_list for %d\n", DEVICE_NAME, profile->identifier);
	
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

// Destructor for pH_profiles
void pH_free_profile(pH_profile *profile)
{
    int ret;
    
    pr_err("%s: In pH_free_profile for %d\n", DEVICE_NAME, profile->identifier);
    
    // Checks for NULL
    if (!profile || profile == NULL) {
        err("no profile to free!");
        return;
    }
    
    // Deals with nasty locking stuff
    spin_lock(profile->lock);
    if (spin_trylock(&pH_profile_list_sem) == 0) {
    	spin_unlock(profile->lock);
    	spin_lock(&pH_profile_list_sem);
    	spin_lock(profile->lock);
    }
    
    ret = pH_remove_profile_from_list(profile);
    if (profile_list_contains_identifier(profile->identifier)) {
    	pr_err("%s: ERROR: After removing profile, profile with identifer is still in list!\n", DEVICE_NAME);
    	spin_unlock(profile->lock);
    	// Cause an intentional crash
    	panic("After removing profile, profile with identifer is still in list");
    	return;
    }
    spin_unlock(&pH_profile_list_sem);
    
    if (ret != 0) {
    	pr_err("%s: ERROR: pH_remove_profile_from_list was unsuccessful in pH_free_profile!\n", DEVICE_NAME);
    	spin_unlock(profile->lock);
    	// Cause an intentional crash
    	panic("pH_remove_profile_from_list was unsuccessful in pH_free_profile");
    	return;
    }

    if (pH_aremonitoring) {
        //pH_write_profile(profile);
    }

    pH_free_profile_storage(profile);
    spin_unlock(profile->lock);
    pr_err("%s: Back in pH_free_profile after pH_free_profile_storage\n", DEVICE_NAME);
    kfree(profile->lock);
    profile->lock = NULL;
    pr_err("%s: Freed profile->lock\n", DEVICE_NAME);
    //vfree(profile); // For now, don't free any profiles
    //profile = NULL; // This is okay, because profile was removed from the linked list above
    pr_err("%s: Freed pH_profile (end of function)\n", DEVICE_NAME);
}

// Removes a process from the list of processes
int remove_process_from_llist(pH_task_struct* process) {
	pH_task_struct *prev_task_struct, *cur_task_struct;
	
	pr_err("%s: In remove_process_from_llist\n", DEVICE_NAME);

	spin_lock(&pH_task_struct_list_sem);
	if (pH_task_struct_list == NULL) {
		err("pH_task_struct_list is empty (NULL) when trying to free process %ld", process->process_id);
		spin_unlock(&pH_task_struct_list_sem);
		return -1;
	}
	else if (pH_task_struct_list == process) {
		pH_task_struct_list = pH_task_struct_list->next;
		pr_err("%s: Returning from remove_process_from_llist\n", DEVICE_NAME);
		spin_unlock(&pH_task_struct_list_sem);
		return 0;
	}
	else {
		prev_task_struct = pH_task_struct_list;
		cur_task_struct = pH_task_struct_list->next;
		while (cur_task_struct != NULL) {
			if (cur_task_struct == process) {
				prev_task_struct->next = process->next;
				pr_err("%s: Returning from remove_process_from_llist\n", DEVICE_NAME);
				spin_unlock(&pH_task_struct_list_sem);
				return 0;
			}
			
			prev_task_struct = cur_task_struct;
			cur_task_struct = cur_task_struct->next;
		}
		
		err("While freeing, couldn't find process %ld in pH_task_struct_list", process->process_id);
		spin_unlock(&pH_task_struct_list_sem);
		return -1;
	}
}

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

void stack_pop(pH_task_struct*);

// Destructor for pH_task_structs
void free_pH_task_struct(pH_task_struct* process) {
	pH_profile* profile;
	int i = 0;
	
	// Checks for NULL
	if (!process || process == NULL) {
		pr_err("%s: process is NULL in free_pH_task_struct\n", DEVICE_NAME);
		return;
	}

	pr_err("%s: In free_pH_task_struct for %d %s\n", DEVICE_NAME, process->process_id, process->profile->filename);
	pr_err("%s: process = %p\n", DEVICE_NAME, process);
	pr_err("%s: process->seq = %p\n", DEVICE_NAME, process->seq);
	
	if (pH_aremonitoring) {
		//stack_print(process);
	}
	
	// Emtpies stack of pH_seqs
	while (process->seq != NULL) {
		if (i > 1000) {
			pr_err("%s: Been in this loop for quite some time... Exiting\n", DEVICE_NAME);
			return;
		}
		
		//pr_err("%s: In while %d\n", DEVICE_NAME, i);
		stack_pop(process);
		//pr_err("%s: &process = %p\n", DEVICE_NAME, &process);
		//pr_err("%s: After stack_pop(process);\n", DEVICE_NAME);
		i++;
	}
	pr_err("%s: Emptied stack of pH_seqs\n", DEVICE_NAME);
	//stack_print(process); // Don't bother printing right now
	//mutex_destroy(&(process->pH_seq_stack_sem)); // Leave the mutex intact?
	
	free_syscalls(process); // Frees syscalls
	pr_err("%s: Freed syscalls\n", DEVICE_NAME);
	
	// This boolean test is required for when this function is called when the module is being removed
	//if (module_inserted_successfully) {
		profile = process->profile;

		if (profile != NULL) {
			pH_refcount_dec(profile);

			if (profile->refcount.counter < 1) {
				profile->refcount.counter = 0;
	
				// Free profile
				pH_free_profile(profile);
				profile = NULL; // Okay because the profile is removed from llist in pH_free_profile
				pr_err("%s: Freed profile\n", DEVICE_NAME);
			}
		}
		else {
			panic("%s: Corrupt process in free_pH_task_struct: No profile\n", DEVICE_NAME);
		}
	//}
	
	// When everything else is done, remove process from llist, kfree process
	remove_process_from_llist(process);
	kfree(process);
	process = NULL; // Okay because process is removed from llist above
	pr_err("%s: Freed process (end of function)\n", DEVICE_NAME);
}

static long jsys_exit(int error_code) {
	pH_task_struct* process;
	
	if (!module_inserted_successfully) goto not_inserted;
	
	pr_err("%s: In jsys_exit for %d\n", DEVICE_NAME, pid_vnr(task_tgid(current)));
	
	process = llist_retrieve_process(pid_vnr(task_tgid(current)));
	
	if (process == NULL) goto not_monitoring;
	
	pr_err("%s: In jsys_exit for %d %s\n", DEVICE_NAME, pid_vnr(task_tgid(current)), process->profile->filename);
	
	//process_syscall(72); // Process this syscall before calling free_pH_task_struct on process
	//pr_err("%s: Back in jsys_exit after processing syscall\n", DEVICE_NAME);
	
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

static long jdo_group_exit(int error_code) {
	pH_task_struct* process;
	struct task_struct* p;
	struct task_struct* t;
	
	if (!module_inserted_successfully) goto not_inserted;
	
	p = current;
	
	pr_err("%s: In jdo_group_exit for %d\n", DEVICE_NAME, pid_vnr(task_tgid(p)));
	
	process = llist_retrieve_process(pid_vnr(task_tgid(p)));
	if (process == NULL) goto not_monitoring;
	
	pr_err("%s: In jdo_group_exit for %d %s\n", DEVICE_NAME, pid_vnr(task_tgid(p)), process->profile->filename);
	
	t = p;
	while_each_thread(p, t) {
		if (t->exit_state) continue;
		
		process = llist_retrieve_process(pid_vnr(task_tgid(t)));
		
		if (process != NULL) {
			free_pH_task_struct(process);
		}
	}
	process = llist_retrieve_process(pid_vnr(task_tgid(p)));
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
	
	if (process == NULL) {
		pr_err("%s: ERROR: process is NULL in stack_push\n", DEVICE_NAME);
		return;
	}
	
	if (new_node == NULL) {
		pr_err("%s: ERROR: new_node is NULL in stack_push\n", DEVICE_NAME);
		return;
	}

	if (process->seq == NULL) {
		new_node->next = NULL;
		process->seq = new_node;
	}
	else {
		new_node->next = process->seq;
		process->seq = new_node;
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
	
	//mutex_lock(&(process->pH_seq_stack_sem));
	temp = process->seq;
	//pr_err("%s: temp = %p top = %p\n", DEVICE_NAME, temp, top);
	process->seq = process->seq->next;
	//pr_err("%s: Set top to top->next\n", DEVICE_NAME);
	//pr_err("%s: Is temp null? %d\n", DEVICE_NAME, temp == NULL);
	//pr_err("%s: temp->length = %d\n", DEVICE_NAME, temp->length);
	//pr_err("%s: Freeing temp... (temp = %p)\n", DEVICE_NAME, temp);
	kfree(temp);
	//pr_err("%s: Freed temp\n", DEVICE_NAME);
	temp = NULL;
	//mutex_unlock(&(process->pH_seq_stack_sem));
	//pr_err("%s: Done stack_pop\n", DEVICE_NAME);
}

pH_seq* stack_peek(pH_task_struct* process) {
	return process->seq; 
}

// This is for when a process receives a signal, NOT for when it resumes execution following
// the signal. I will need to implement a second jprobe handler for resuming execution.
static void jhandle_signal(struct ksignal* ksig, struct pt_regs* regs) {
	pH_task_struct* process;
	
	if (!module_inserted_successfully) goto not_inserted;
	
	//pr_err("%s: In jhandle_signal\n", DEVICE_NAME);
	
	// Will this retrieve the process that the signal is being sent to, or will it retrieve the
	// process that is sending the signal?
	process = llist_retrieve_process(pid_vnr(task_tgid(current)));
	
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
	
	if (!module_inserted_successfully) goto not_inserted;
	
	//pr_err("%s: In jdo_signal\n", DEVICE_NAME);
	
	// Will this retrieve the process that the signal is being sent to, or will it retrieve the
	// process that is sending the signal?
	process = llist_retrieve_process(pid_vnr(task_tgid(current)));
	
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

// Finish implementing me! And also finish cleaning up the new additions to ebbchar_init!
// Try me with a kretprobe as well
static long jsys_rt_sigreturn(void) {
	pH_task_struct* process;
	
	if (!module_inserted_successfully) goto not_inserted;
	
	pr_err("%s: In jsys_rt_sigreturn\n", DEVICE_NAME);
	
	process = llist_retrieve_process(pid_vnr(task_tgid(current)));
	
	if (!process || process == NULL) goto not_inserted;
	
	stack_pop(process);
	
	//process_syscall(383); // Currently not 
	//pr_err("%s: Back in jsys_rt_sigreturn after processing syscall\n", DEVICE_NAME);

	if (current->exit_state) {
		pr_err("%s: Freeing task_struct...\n", DEVICE_NAME);
		free_pH_task_struct(process);
	}
	
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
	
	//handle_signal_jprobe.kp.addr = kallsyms_lookup_name("handle_signal");
	
	/*
	if (kallsyms_lookup_name("handle_signal") == 0) {
		pr_err("%s: Unable to look up symbol for handle_signal_jprobe\n", DEVICE_NAME);
		
		mutex_destroy(&ebbchar_mutex);
		device_destroy(ebbcharClass, MKDEV(majorNumber, 0));
		class_unregister(ebbcharClass);
		class_destroy(ebbcharClass);
		unregister_chrdev(majorNumber, DEVICE_NAME);
		
		pr_err("%s: Module has (hopefully) been removed entirely\n", DEVICE_NAME);
		pr_err("%s: ...But just in case, run this command: 'sudo rmmod km'\n", DEVICE_NAME);
		
		return PTR_ERR(ebbcharDevice);
	}

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
	
	// Regiser exit_kretprobe
	exit_kretprobe.kp.addr = (kprobe_opcode_t*) kallsyms_lookup_name("do_exit");
	
	if (kallsyms_lookup_name("do_exit") == 0) {
		pr_err("%s: Did not find symbol 'do_exit'\n", DEVICE_NAME);
		
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
	pr_err("%s: Found symbol 'do_exit'\n", DEVICE_NAME);
	
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

	//pr_err("%s: num_syscalls = %d\n", DEVICE_NAME, num_syscalls);
	for (i = 0; i < num_syscalls; i++) {
		ret = register_jprobe(&jprobes_array[i]);
		if (ret < 0) {
			pr_err("%s: register_jprobe failed (%s), returned %d\n", DEVICE_NAME, jprobes_array[i].kp.symbol_name, ret);
			
			//unregister_jprobe(&handle_signal_jprobe);
			//unregister_jprobe(&sys_sigreturn_jprobe);
			unregister_jprobe(&do_signal_jprobe);
			unregister_kretprobe(&fork_kretprobe);
			unregister_kretprobe(&exit_kretprobe);
			
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
	
	spin_lock_init(&pH_profile_list_sem);
	spin_lock_init(&pH_task_struct_list_sem);
	
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
	pH_aremonitoring = 0;
	module_inserted_successfully = FALSE;

	pr_err("%s: Exiting...\n", DEVICE_NAME);

	//print_llist(); // For now, don't bother with printing the llist
	
	//unregister_jprobe(&handle_signal_jprobe);
	//unregister_jprobe(&sys_sigreturn_jprobe);
	unregister_jprobe(&do_signal_jprobe);
	
	// Unregister jprobes - it seems this was working just fine before, but Anil said its okay
	// if I don't bother with unregistering them
	for (i = 0; i < num_syscalls; i++) {
		unregister_jprobe(&jprobes_array[i]);
	}
	pr_err("%s: Unregistered syscall jprobes\n", DEVICE_NAME);

	// Unregister fork_kretprobe
	unregister_kretprobe(&fork_kretprobe);
	pr_err("%s: Missed probing %d instances of fork\n", DEVICE_NAME, fork_kretprobe.nmissed);
	
	// Unregister exit_kretprobe
	unregister_kretprobe(&exit_kretprobe);
	pr_err("%s: Missed probing %d instances of exit\n", DEVICE_NAME, exit_kretprobe.nmissed);
	
	profiles_freed = pH_profile_list_length();
	
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
	
	// Print lengths of lists
	pr_err("%s: At time of module removal, pH was monitoring %d processes and had %d profiles in memory\n", DEVICE_NAME, pH_task_structs_freed, profiles_freed);
	pr_err("%s: During the uptime of the module, %d profiles were created\n", DEVICE_NAME, profiles_created);
	pr_err("%s: During the uptime of the module, there were %d successful jsys_execves\n", DEVICE_NAME, successful_jsys_execves);
	
	pr_err("%s: %s successfully removed\n", DEVICE_NAME, DEVICE_NAME);
}

static int dev_open(struct inode *inodep, struct file *filep){
	return 0;
}

static ssize_t dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset){
	return 0;
}

static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset){
	return 0;
}

static int dev_release(struct inode *inodep, struct file *filep){
	return 0;
}

inline void pH_append_call(pH_seq* s, int new_value) {
	if (s->last < 0) { pr_err("%s: s->last is not initialized!\n", DEVICE_NAME); return; }
	if (s->length == 0) {
		pr_err("%s: In pH_append_call with s->length = 0. This will cause a division error.\n", DEVICE_NAME);
		panic("In pH_append_call with s->length = 0");
		return;
	}
	
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
	
	if (seqlen == 0) {
		pr_err("%s: In pH_add_seq with s->length = 0\n", DEVICE_NAME);
		panic("In pH_add_seq with s->length = 0");
		return;
	}

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

	if (seqlen == 0) {
		pr_err("%s: In pH_test_seq with s->length = 0\n", DEVICE_NAME);
		panic("In pH_test_seq with s->length = 0");
		return;
	}

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

module_init(ebbchar_init);
module_exit(ebbchar_exit);
