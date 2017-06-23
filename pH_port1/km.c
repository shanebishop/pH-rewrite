/*
Notes:
-Know when to use retrieve_pH_profile_by_filename instead of retrieve_pH_profile_by_pid
-When retrieving the PID of a process, use pid_vnr(task_tgid(tsk));, where tsk is the task_struct of the particular process
-Make sure that syscalls are still processed even while waiting to hear back from the user
-Make sure to update filenames and stuff when done (including ebbchar_init, ebbchar_exit, and ebbchar_mutex)
*/
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/init.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/mutex.h>

#include <asm/unistd.h>      // For system call numbers
#include <linux/hashtable.h> // For hashtables
#include <linux/slab.h>      // For kmalloc
#include <linux/vmalloc.h>   // For vmalloc
#include <linux/ctype.h>     // For types
#include <linux/random.h>    // For randomness
#include <linux/freezer.h>   // For freezing userspace processes

#include "system_call_prototypes.h"
#include "ebbcharmutex.h"

MODULE_LICENSE("GPL");               

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

typedef struct pH_seq {
	int last; // seq is a circular array; this is its end
	int length;
	u8 data[PH_MAX_SEQLEN]; // Current sequence being filled or processed - initialized to PH_EMPTY_SYSCALL initially
	struct list_head seqList;
} pH_seq;

typedef struct pH_profile_data {
	int sequences;					// # sequences that have been inserted NOT the number of lookahead pairs
	unsigned long last_mod_count;	// # syscalls since last modification
	unsigned long train_count;		// # syscalls seen during training
	void *pages[PH_MAX_PAGES];
	int current_page;				// pages[current_page] contains free space
	int count_page;					// How many arrays have been allocated in the current page
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
	struct file *seq_logfile;
	struct semaphore lock;
	pH_seq seq;
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
struct syscall_pair {
	unsigned long first_syscall;
	unsigned long second_syscall;
};

typedef struct my_syscall {
	struct my_syscall* next;
	unsigned long syscall_num;
} my_syscall;

typedef struct pH_task_struct { // My own version of a pH_task_state
	struct hlist_node hlist; // Must be first field
	struct pH_task_struct* next; // For linked lists
	my_syscall* syscall_llist;
	long process_id;
	pH_locality alf;
	pH_seq* seq;
	int delay;
	unsigned long count;
	pH_profile* profile; // Pointer to appropriate profile
} pH_task_struct;

const char *PH_FILE_MAGIC="pH profile 0.18\n";

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

// My own global declarations
//#define num_syscalls 12 // Holds current temp number of syscalls (not to be confused with PH_NUM_SYSCALLS)
#define num_kretprobes 1
#define SIGNAL_PRIVILEGE 1
#define SYSCALLS_PER_WRITE 10

// Commands for user space code
#define READ_ASCII 'r'
#define WRITE_ASCII 'w'
#define ADD_BINARY 'b'
#define FIND_A_BINARY 'f'

//struct jprobe jprobes_array[num_syscalls]; // Array of jprobes
struct kretprobe kretprobes_array[num_kretprobes]; // Array of kretprobes
DECLARE_HASHTABLE(profile_hashtable, 8); // Declare profile hashtable
long userspace_pid;                      // The PID of the userspace process
const char TRANSFER_OPERATION[2] = {'t', '\0'}; // Constant for transfer operation
char* output_string;                     // The string that will be sent to the userspace code
int syscalls_this_write;                 // Number of syscalls that have been encountered since last write to usersapce
//pH_profile* current_profile;           // The current pH_profile
void* bin_receive_ptr;                   // The pointer for binary writes
pH_task_struct* llist_start = NULL;      // The start of the linked list of pH_task_structs
ktime_t start_time;	                     // The time at which the module was loaded
bool done_waiting_for_user = FALSE;
bool have_userspace_pid    = FALSE;
bool have_bin_receive_ptr  = FALSE;
bool binary_read           = FALSE;
bool user_process_has_been_loaded = FALSE;

static int     dev_open(struct inode *i, struct file *f) {}
static int     dev_release(struct inode *i, struct file *f) {}
static ssize_t dev_read(struct file *f, char *c, size_t s, loff_t *l) {}
static ssize_t dev_write(struct file *f, const char *c, size_t s, loff_t *l) {}

static struct file_operations fops =
{
	.open = dev_open,
	.read = dev_read,
	.write = dev_write,
	.release = dev_release,
};

// Returns a pH_profile using a filename string as the lookup
pH_profile* retrieve_pH_profile_by_filename(char* filename) {
	pH_profile* profile;
	pH_profile* temp;
	int bkt;
	
	if (hash_empty(profile_hashtable)) return NULL;
	
	hash_for_each(profile_hashtable, bkt, profile, hlist) {
		temp = (pH_profile*) profile;
		if (strcmp(temp->filename, filename) == 0) {
			return temp;
		}
	}
	
	return NULL;
}

inline void pH_refcount_init(pH_profile *, int);

// Makes a new pH_profile and stores it in profile
// profile must be allocated before this function is called
int new_profile(pH_profile* profile, char* filename) {
	int i;

	profile->identifier = pid_vnr(task_tgid(current));

    profile->normal = 0;  // We just started - not normal yet!
    profile->frozen = 0;
    profile->normal_time = 0;
    profile->anomalies = 0;
    profile->length = pH_default_looklen;
    profile->count = 0;
    //init_MUTEX(&(profile->lock));
    
    profile->train.sequences = 0;
    profile->train.last_mod_count = 0;
    profile->train.train_count = 0;
    profile->train.current_page = 0;
    profile->train.count_page = 0;
    
    for (i=0; i<PH_NUM_SYSCALLS; i++) {
            profile->train.entry[i] = NULL;
    }

    for (i=0; i<PH_MAX_PAGES; i++) {
            profile->train.pages[i] = NULL;
    }

    profile->test = profile->train;
    
    profile->next = NULL;
    pH_refcount_init(profile, 0);
    profile->filename = filename;
    
    //pH_open_seq_logfile(profile);
    
    // Add this new profile to the hashtable
    hash_add(profile_hashtable, &profile->hlist, pid_vnr(task_tgid(current)));
    
    return 0;
}

pH_task_struct* llist_retrieve_process(int process_id) {
	pH_task_struct* iterator = llist_start;
	
	if (!llist_start || llist_start == NULL) {
		return NULL;
	}
	
	do {
		if (iterator->process_id == process_id) return iterator;
		iterator = iterator->next;
	} while (iterator);
	
	return NULL;
}

// Function prototypes for process_syscall()
inline void pH_append_call(pH_seq *s, int new_value);
int pH_test_seq(pH_seq *, pH_profile_data *);
//void pH_stop_normal(pH_task_state);
inline void pH_add_anomaly_count(pH_task_struct*, int val);
void pH_start_normal(pH_task_struct*);
inline void pH_delay_task(int, pH_task_struct*);
inline void pH_reset_ALF(pH_task_struct *);
inline void pH_reset_train(pH_profile*);
inline int pH_LFC(pH_task_struct*);
inline void pH_process_normal(pH_profile *, pH_seq *, pH_task_struct*, long syscall);
inline void pH_refcount_inc(pH_profile *);
void print_llist(void);
void add_to_my_syscall_llist(pH_task_struct*, my_syscall*);
inline void pH_train(pH_task_struct *);

// Process system calls
int process_syscall(long syscall) {
	int LFC;
	pH_profile *profile;
	pH_task_struct* process;
	
	done_waiting_for_user = TRUE; // Temp line for debugging - remove this
	
	// If still waiting for the userpace process, return
	if (!done_waiting_for_user) { /*printk(KERN_INFO "Waiting for user");*/ return 0; }
	
	// If pH_aremonitoring is FALSE, exit this function
	if (!pH_aremonitoring) { pr_err("%s: Not monitoring\n", DEVICE_NAME); return 0; }
	
	process = llist_retrieve_process(pid_vnr(task_tgid(current)));
	if (process == NULL) {
		// Ignore this syscall
		return 0;
	}
	
	profile = process->profile; // Store process->profile in profile for shorter reference
	
	if (!profile || profile == NULL) {
		pr_err("%s: pH_task_struct corrupted: No profile.\n", DEVICE_NAME);
		return -1;
	}
	pr_err("%s: Retrieved profile successfully\n", DEVICE_NAME);
	
	if ((process->seq) == NULL) {
		pH_seq* temp = (pH_seq*) vmalloc(sizeof(pH_seq));
		if (!temp) {
			pr_err("%s: Unable to allocate memory for temp in process_syscall\n", DEVICE_NAME);
			return -ENOMEM;
		}
		
		process->seq = temp;
		INIT_LIST_HEAD(&temp->seqList);
	}
	
	process->seq->length = profile->length;
	process->seq->last = profile->length - 1;
	
	process->count++;
    pH_append_call(process->seq, syscall);
	pr_err("%s: Successfully appended call\n", DEVICE_NAME);
	
	profile->count++;
	
    pH_train(process);
    // xtime is no longer in modern linux kernels; I will need to come up with a workaround for this
    if (profile->frozen /*&& (xtime.tv_sec > profile->normal_time)*/) {
		pH_start_normal(process);
    }
	pr_err("%s: Trained process\n", DEVICE_NAME);

    pH_process_normal(profile, process->seq, procss, syscall);
	pr_err("%s: Processed as normal\n", DEVICE_NAME);

    LFC = pH_LFC(process);
    if (LFC > pH_tolerize_limit) {
            pH_reset_train(profile);
            // To stop anom_limit from kicking in...
            profile->anomalies = 0;
    }
    
    my_syscall* new_syscall = kmalloc(sizeof(my_syscall), GFP_KERNEL);
    if (!new_syscall) {
    	pr_err("%s: Unable to allocate memory for new_syscall\n", DEVICE_NAME);
    	return -ENOMEM;
    }
    
    new_syscall->syscall_num = syscall;
    add_to_my_syscall_llist(process, new_syscall);
	pr_err("%s: Successfully added new_syscall to the llist\n", DEVICE_NAME);
    
    //print_llist(); // Uncomment to print llists
	
	return 0;
}

void add_to_my_syscall_llist(pH_task_struct* t, my_syscall* s) {
	if (t->syscall_llist == NULL) {
		t->syscall_llist = s;
		s->next = NULL;
	}
	else {
		my_syscall* iterator = t->syscall_llist;
		
		while (iterator->next) iterator = iterator->next;
		
		iterator->next = s;
		s->next = NULL;
	}
}

void add_to_llist(pH_task_struct* t) {	
	if (llist_start == NULL) {
		llist_start = t;
		t->next = NULL;
	}
	else {
		pH_task_struct* iterator = llist_start;
		
		while (iterator->next) iterator = iterator->next;
		
		iterator->next = t;
		t->next = NULL;
	}
}

void print_llist(void) {
	int i = 0;
	pH_task_struct* iterator = llist_start;
	my_syscall* syscall_iterator;
	
	if (llist_start == NULL) {
		return;
	}
	
	pr_err("%s: Printing linked list...\n", DEVICE_NAME);
	do {
		pr_err("%s: Output: %ld %s\n", DEVICE_NAME, iterator->process_id, iterator->profile->filename);
		
		/* // Uncomment to print llist of system calls for this process		
		syscall_iterator = iterator->syscall_llist;
		
		while (syscall_iterator) {
			pr_info("%s: %d: %d", DEVICE_NAME, i, syscall_iterator->syscall_num);
			i++;
			syscall_iterator = syscall_iterator->next;
		}
		*/
				
		iterator = iterator->next;
	} while (iterator);
}

void pH_start_monitoring(pH_task_struct *, pH_profile *);

// Proxy routine for sys_execve
// First look for profile in profiles in memory, then on disk, and then make a new one
static long jsys_execve(const char __user *filename,
	const char __user *const __user *__argv,
	const char __user *const __user *__envp)
{
	pH_profile* profile;
	pH_task_struct* this_process;
	char* path_to_binary;
	
	pr_err("%s: In jsys_execve\n", DEVICE_NAME);
	
	// Allocate space for path_to_binary
	path_to_binary = kmalloc(sizeof(char) * (strlen(filename) + 1), GFP_KERNEL);
	if (!path_to_binary) {
		pr_err("%s: Unable to allocate memory for path_to_binary\n", DEVICE_NAME);
		goto no_memory;
	}
	pr_err("%s: Successfully allocated memory for path_to_binary\n", DEVICE_NAME);
	
	// Copy memory from userspace to kernel land
	memcpy(path_to_binary, filename, sizeof(char) * (strlen(filename) + 1));
	pr_err("%s: Successfully copied memory from userspace to kernel land\n", DEVICE_NAME);
	
	// Allocate memory for this process
	this_process = (pH_task_struct*) kmalloc(sizeof(pH_task_struct), GFP_KERNEL);
	if (!this_process) {
		pr_err("%s: Unable to allocate memory for this_process\n", DEVICE_NAME);
		goto no_memory;
	}
	pr_err("%s: Successfully allocated memory for this_process\n", DEVICE_NAME);
	
	// Intialize this_process - check with Anil to see if these are the right values to initialize it to
	this_process->process_id = pid_vnr(task_tgid(current));
	pH_reset_ALF(this_process);
	this_process->seq = NULL;
	this_process->syscall_llist = NULL;
	this_process->delay = 0;
	this_process->count = 0;
	pr_err("%s: Initialized process\n", DEVICE_NAME);
	
	// Retrieve the corresponding profile
	profile = retrieve_pH_profile_by_filename(path_to_binary);
	pr_err("%s: Attempted to retrieve profile\n", DEVICE_NAME);
	
	// If there is no corresponding profile, make a new one
	if (!profile || profile == NULL) {
		profile = (pH_profile*) vmalloc(sizeof(pH_profile));
		if (!profile) {
			pr_err("%s: Unable to allocate memory for profile in process_syscall\n", DEVICE_NAME);
			goto no_memory;
		}
		new_profile(profile, path_to_binary);
		pr_err("%s: Made new profile\n", DEVICE_NAME);
		
		if (!profile || profile == NULL) {
			pr_err("%s: Somehow the profile is still NULL\n", DEVICE_NAME);
		}
		else {
			pH_start_monitoring(this_process, profile);
		}
	}
	else {
		kfree(path_to_binary);
	}
	
	this_process->profile = (pH_profile*) profile;
	
	// Add this_process to the linked list
	add_to_llist(this_process);
	pr_err("%s: Added this_process to linked list\n", DEVICE_NAME);

	process_syscall(59);
	
	jprobe_return(); // Execution must always reach this line in jprobe handlers
	return 0;

not_a_path:
	pr_info("%s: In jsys_execve(): Not a path\n", DEVICE_NAME);
	jprobe_return();
	return 0;
	
no_memory:
	pr_info("%s: In jsys_execve(): Ran out of memory\n", DEVICE_NAME);
	jprobe_return();
	return 0;

ignore_binary:
	pr_info("%s: In jsys_execve(): Ignoring binary\n", DEVICE_NAME);
	jprobe_return();
	return 0;
}

// Struct required for all kretprobe structs
struct my_kretprobe_data {
	ktime_t entry_stamp;
};

static int fork_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	int retval;
	//struct my_data *data;
	//s64 delta;
	ktime_t now;
	pH_task_struct* process;
	
	retval = regs_return_value(regs);
	//data = (struct my_data *)ri->data;

	now = ktime_get();
	//delta = ktime_to_ns(ktime_sub(now, data->entry_stamp));
	//printk(KERN_INFO "%s: _do_fork returned %d", DEVICE_NAME, retval);
	
	/*
	process = (pH_task_struct*) kmalloc(sizeof(pH_task_struct), GFP_KERNEL);
	if (!process) {
		pr_alert("%s: Unable to allocate memory for process in fork_handler", DEVICE_NAME);
	}
	hash_add(proc_hashtable, &process->hlist, retval);
	*/
	
	return 0;
}

static struct kretprobe fork_kretprobe = {
	.handler = fork_handler,
	.data_size = sizeof(struct my_kretprobe_data),
	.maxactive = 20,
};


static int __init ebbchar_init(void){
	int ret, i;
	
	pr_info("%s: Initiating %s\n", DEVICE_NAME, DEVICE_NAME);
	
	pH_aremonitoring = 1;
	
	pH_delay_factor = 3;
	
	//pH_loglevel = PH_LOG_IO; // Temp line for maximum output
	
	// Initialize kretprobes_array
	kretprobes_array[0] = fork_kretprobe;
	
	// Initialize hashtables
	hash_init(profile_hashtable);
	hash_init(proc_hashtable);
	
	syscalls_this_write = 0;
	
	// Try to dynamically allocate a major number for the device
	majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
	if (majorNumber<0){
	  printk(KERN_ALERT "%s: Failed to register a major number\n", DEVICE_NAME);
	  return majorNumber;
	}
	printk(KERN_INFO "%s: registered correctly with major number %d\n", DEVICE_NAME, majorNumber);
	
	// Register the device class
	ebbcharClass = class_create(THIS_MODULE, CLASS_NAME);
	if (IS_ERR(ebbcharClass)){           // Check for error and clean up if there is
	  unregister_chrdev(majorNumber, DEVICE_NAME);
	  printk(KERN_ALERT "%s: Failed to register device class\n", DEVICE_NAME);
	  return PTR_ERR(ebbcharClass);
	}
	printk(KERN_INFO "%s: device class registered correctly\n", DEVICE_NAME);

	// Register the device driver
	ebbcharDevice = device_create(ebbcharClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
	if (IS_ERR(ebbcharDevice)){         // Clean up if there is an error
	  class_destroy(ebbcharClass);      // Repeated code but the alternative is goto statements
	  unregister_chrdev(majorNumber, DEVICE_NAME);
	  printk(KERN_ALERT "%s: Failed to create the device\n", DEVICE_NAME);
	  return PTR_ERR(ebbcharDevice);
	}
	printk(KERN_INFO "%s: device class created correctly\n", DEVICE_NAME); // Device was initialized
	mutex_init(&ebbchar_mutex); // Initialize the mutex dynamically

	// Iterates over all of the system calls
	for (i = 0; i < num_syscalls; i++) {
		// Register the jprobe
		ret = register_jprobe(&jprobes_array[i]);
		if (ret < 0) {
			pr_err("%s: register_jprobe failed, returned %d\n", DEVICE_NAME, ret);
			return -1;
		}
	}
	
	// Register kretprobes
	for (i = 0; i < num_kretprobes; i++) {
		kretprobes_array[i].kp.symbol_name = "_do_fork";
		ret = register_kretprobe(&kretprobes_array[i]);
		if (ret < 0) {
			printk(KERN_INFO "%s: Failed to register _do_fork kretprobe, returned %d\n", DEVICE_NAME, ret);
			return -1;
		}
	}
	
	start_time = ktime_get();
	
	return 0;
}

static void __exit ebbchar_exit(void){
	int i;

	print_llist();

	// Unregister the jprobes
	for (i = 0; i < num_syscalls; i++) {
		unregister_jprobe(&jprobes_array[i]);
	}

	// Unregister the kretprobes
	for (i = 0; i < num_kretprobes; i++) {
		unregister_kretprobe(&kretprobes_array[i]);

		// nmissed > 0 suggests the maxactive was set too low
		printk(KERN_INFO "%s: Missed probing %d instances of %s\n", DEVICE_NAME, kretprobes_array[i].nmissed, kretprobes_array[i].kp.symbol_name);
	}
	
	mutex_destroy(&ebbchar_mutex);
	device_destroy(ebbcharClass, MKDEV(majorNumber, 0));
	class_unregister(ebbcharClass);
	class_destroy(ebbcharClass);
	unregister_chrdev(majorNumber, DEVICE_NAME);
	pr_info("%s: Goodbye from the LKM!\n", DEVICE_NAME);
}

int pH_add_seq_storage(pH_profile_data *data, int val)
{
        pH_seqflags *page;

        if (data->count_page >= PH_COUNT_PAGE_MAX) {
                data->current_page++;
                data->count_page = 0;
        }

        if (data->current_page >= PH_MAX_PAGES)
                return -1;

        if (data->count_page == 0) {
                page = (pH_seqflags *) __get_free_page(GFP_USER);
                if (page)
                        data->pages[data->current_page] = page;
                else
                        return -1;
        } else {
                page = data->pages[data->current_page];
        }

        data->entry[val] = page + (data->count_page * PH_NUM_SYSCALLS);
        data->count_page++;
        
        return 0;
}

inline void pH_refcount_init(pH_profile *profile, int i)
{
        profile->refcount.counter = i;
}

inline int pH_LFC(pH_task_struct *s)
{
        return (s->alf.total);
}

void pH_open_seq_logfile(pH_profile *profile)
{
        char *seq_filename = (char *) kmalloc(4000, GFP_KERNEL);
        int len;

        if (!seq_filename)
                return;
		
		len = strlen(profile->filename);

        if (profile->filename && (len < PAGE_SIZE - 5)) {
                strcpy(seq_filename, profile->filename);
                strcpy(seq_filename + len, ".seq");
        } else {
                profile->seq_logfile = NULL;
        }
        kfree(seq_filename);
}

inline void pH_append_call(pH_seq *s, int new_value)
{
        if (s->last < 0) { pr_err("%s: s->last is not initialized!\n", DEVICE_NAME); return; }
        
        s->last = (s->last + 1) % (s->length);
        s->data[s->last] = new_value;
}

void pH_add_seq(pH_seq *s, pH_profile_data *data)
{
        int i, cur_call, prev_call, cur_idx;
        u8 *seqdata = s->data;
        int seqlen = s->length;
        
        cur_idx = s->last;
        cur_call = seqdata[cur_idx];
        for (i = 1; i < seqlen; i++) {
                if (data->entry[cur_call] == NULL) {
                        if (pH_add_seq_storage(data, cur_call)) return;
                }
                prev_call = seqdata[(cur_idx + seqlen - i) % seqlen];
                data->entry[cur_call][prev_call] |= (1 << (i - 1));
        }
}

inline void pH_log_sequence(pH_profile *profile, pH_seq *seq)
{
        if (profile->seq_logfile && pH_log_sequences) {
                pH_seq_logrec rec;
                
                rec.count = profile->count;
                rec.pid = current->pid;
                //rec.time = xtime;
                rec.seq = *seq;
        }
}

inline void pH_train(pH_task_struct *s)
{
        pH_seq *seq = s->seq;
        pH_profile *profile = s->profile;
        pH_profile_data *train = &(profile->train);

        train->train_count++;
        if (pH_test_seq(seq, train)) { 
                if (profile->frozen) {
                        profile->frozen = 0;
                        action("%d (%s) normal cancelled",
                               current->pid, profile->filename);
                }
                pH_add_seq(seq,train);  
                train->sequences++; 
                train->last_mod_count = 0;

                pH_log_sequence(profile, seq);
        } else {
                unsigned long normal_count; 
                
                train->last_mod_count++;
                
                if (profile->frozen)
                        return;

                normal_count = train->train_count -  
                        train->last_mod_count; 

                if ((normal_count > 0) &&
                    ((train->train_count * pH_normal_factor_den) >
                     (normal_count * pH_normal_factor))) {
                        action("%d (%s) frozen",
                               current->pid, profile->filename);
                        profile->frozen = 1;
                        //profile->normal_time = xtime.tv_sec + pH_normal_wait;
                } 
        }
}

int pH_test_seq(pH_seq *s, pH_profile_data *data)
{
	int i, cur_call, prev_call, cur_idx;
	u8 *seqdata = s->data;
	int seqlen = s->length;
	int mismatches = 0;

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

inline void pH_reset_ALF(pH_task_struct *s)
{
        int i;

        for (i=0; i<PH_LOCALITY_WIN; i++) {
                s->alf.win[i]=0;
        }
        s->alf.total = 0;
        s->alf.max = 0;
        s->alf.first = PH_LOCALITY_WIN - 1;

        /* if there are no anomalies, we don't delay, so zero it now */
        s->delay = 0;
}

void pH_stop_normal(pH_profile *p, pH_task_struct *s)
{
        p->normal = 0;
        pH_reset_ALF(s);
}

inline void pH_add_anomaly_count(pH_task_struct *s, int val)
{
        int i = (s->alf.first + 1) % PH_LOCALITY_WIN;

        if (val > 0) {
                s->profile->anomalies++;
                if (s->alf.win[i] == 0) {
                        s->alf.win[i] = 1;
                        s->alf.total++;
                        if (s->alf.total > s->alf.max)
                                s->alf.max = s->alf.total;
                }
        } else if (s->alf.win[i] > 0) {
                s->alf.win[i] = 0;
                s->alf.total--;
        }
        s->alf.first = i;
}

int pH_copy_train_to_test(pH_profile *profile)
{
        pH_profile_data *train = &(profile->train);
        pH_profile_data *test = &(profile->test);
        int i;

        test->sequences = train->sequences;
        test->last_mod_count = train->last_mod_count;
        test->train_count = train->train_count;

        test->current_page = 0;
        test->count_page = 0;

        for (i = 0; i < PH_NUM_SYSCALLS; i++) {
                if (train->entry[i] == NULL) {
                        test->entry[i] = NULL;
                }
                else {
                        if (pH_add_seq_storage(test, i)) {
                                return -1;
						}
                        memcpy(test->entry[i], train->entry[i], PH_NUM_SYSCALLS);
                }
        }
        
        return 0;
}

void pH_start_normal(pH_task_struct *s)
{
        pH_profile *profile = s->profile;
        pH_profile_data *train = &(profile->train);
        pH_profile_data *test = &(profile->test);
        
        pH_reset_ALF(s);
        
        if (pH_copy_train_to_test(profile))
                return;

        profile->anomalies = 0;
        profile->normal = 1;
        profile->frozen = 0;
        train->last_mod_count = 0;
        train->train_count = 0;
        state("%d now has %lu training calls and %lu since last change", 
               current->pid, test->train_count, test->last_mod_count); 
        state("Starting normal monitoring in %d (%s) at %lu (%lu, %lu) " 
               "with %d sequences", current->pid, profile->filename,
               profile->count, s->count, pH_syscall_count,
               test->sequences); 
}

inline void pH_process_normal(pH_profile *profile, pH_seq *seq, pH_task_struct* s, long syscall)
{
	int anomalies;
	pH_profile_data *test = &(profile->test);

	if (profile->normal) {
		anomalies = pH_test_seq(seq, test);
		if (anomalies) {
			action("Anomalous %ld (%d misses), PID %d (%s), "
				"count %lu", syscall, anomalies, current->pid,
				profile->filename, s->count);
			if (profile->anomalies > pH_anomaly_limit) {
				pH_stop_normal(profile, s);
				state("Anomaly limit %d exceeded for %d (%s) "
					"at %lu, normal reset",
					pH_anomaly_limit, current->pid,
					profile->filename, s->count);
			}
		}
	}
	else {
		anomalies = 0;
	}

	pH_add_anomaly_count(s, anomalies);
}

void pH_free_profile_data(pH_profile_data *data)
{
        int i;

        data->current_page = 0;
        data->count_page = 0;

        for (i=0; i<PH_NUM_SYSCALLS; i++)
                data->entry[i] = NULL;

        for (i = 0; i <PH_MAX_PAGES; i++) {
                if (data->pages[i]) {
                        free_page((unsigned long) data->pages[i]);
                        data->pages[i] = NULL;
                }
        }
}

void pH_reset_profile_data(pH_profile_data *data)
{
        data->last_mod_count = 0;
        data->train_count = 0;
        data->sequences = 0;
        
        pH_free_profile_data(data);
}

inline void pH_reset_train(pH_profile *profile)
{
        pH_profile_data *train = &(profile->train);
        
        pH_reset_profile_data(train);
}

inline void pH_refcount_inc(pH_profile *profile)
{
        atomic_inc(&(profile->refcount));
}

void pH_start_monitoring(pH_task_struct *s, pH_profile *profile)
{
        int i;

        if (profile != NULL) {
			if (s->seq == NULL) {
				pH_seq *temp = (pH_seq *) vmalloc(sizeof(pH_seq));
				s->seq = temp;
				INIT_LIST_HEAD(&temp->seqList);
			}
            s->seq->length = profile->length;
            s->seq->last = profile->length - 1;
            
            // FIXME: move length to profiles!

            for (i=0; i<PH_MAX_SEQLEN; i++) {
                    s->seq->data[i] = PH_EMPTY_SYSCALL;
            }
            
            pH_refcount_inc(profile);
            
            s->profile = profile;
        } else {
                pr_err("Trying to start, but no PROFILE!");
        }
}


module_init(ebbchar_init);
module_exit(ebbchar_exit);
