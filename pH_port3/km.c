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
#define PH_NUM_SYSCALLS 256 // Size of array
#define PH_COUNT_PAGE_MAX (PAGE_SIZE / PH_NUM_SYSCALLS)
#define PH_MAX_PAGES (PH_NUM_SYSCALLS / PH_COUNT_PAGE_MAX)
#define PH_MAX_SEQLEN 9
#define PH_MAX_DISK_FILENAME 256
#define PH_LOCALITY_WIN 128
#define PH_FILE_MAGIC_LEN 20
#define PH_EMPTY_SYSCALL 255 // Note: This value is used as the "no system call" marker in sequences"

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

typedef int pH_seqflags;

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

typedef struct pH_locality {
	u8 win[PH_LOCALITY_WIN];
	int first;
	int total;
	int max;
} pH_locality;

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
	int delay;
	unsigned long count;
	pH_profile* profile; // Pointer to appropriate profile
} pH_task_struct;

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
//int pH_loglevel = PH_LOG_ACTION;
int pH_log_sequences = 0;
int pH_suspend_execve = 0; /* min LFC to suspend execve's, 0 = no suspends */
int pH_suspend_execve_time = 3600 * 24 * 2;  /* time to suspend execve's */
int pH_normal_wait = 7 * 24 * 3600;/* seconds before putting normal to work */

// My global variables
pH_task_struct* llist_start = NULL;
pH_profile* profile_llist_start = NULL;
struct jprobe jprobes_array[num_syscalls];

void add_to_profile_llist(pH_profile* p) {
	if (profile_llist_start == NULL) {
		profile_llist_start = p;
		p->next = NULL;
	}
	else {
		pH_profile* iterator = profile_llist_start;
		
		while (iterator->next) iterator = iterator->next;
		
		iterator->next = p;
		p->next = NULL;
	}
}

// Makes a new pH_profile and stores it in profile
// profile must be allocated before this function is called
int new_profile(pH_profile* profile, char* filename) {
	int i;

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

	//profile->next = NULL;
	//pH_refcount_init(profile, 0);
	profile->filename = filename;

	//pH_open_seq_logfile(profile);

	// Add this new profile to the hashtable
	//hash_add(profile_hashtable, &profile->hlist, pid_vnr(task_tgid(current)));
	
	// Add this new profile to the llist
	add_to_profile_llist(profile);

	return 0;
}

void add_to_my_syscall_llist(pH_task_struct* t, my_syscall* s) {
	pr_err("%s: In add_to_my_syscall_llist\n", DEVICE_NAME);
	
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

pH_task_struct* llist_retrieve_process(int process_id) {
	pH_task_struct* iterator = llist_start;
	
	if (llist_start == NULL) {
		return NULL;
	}
	
	do {
		if (iterator->process_id == process_id) return iterator;
		iterator = iterator->next;
	} while (iterator);
	
	return NULL;
}

inline void pH_append_call(pH_seq*, int);

int process_syscall(long syscall) {
	pH_task_struct* process;
	my_syscall* new_syscall;
	pH_profile* profile;
	
	//pr_err("%s: syscall=%d\n", DEVICE_NAME, syscall);
	
	// Retrieve process
	process = llist_retrieve_process(pid_vnr(task_tgid(current)));
	if (!process) {
		// Ignore this syscall
		return 0;
	}
	pr_err("%s: Retrieved process successfully\n", DEVICE_NAME);
	
	profile = process->profile; // Store process->profile in profile for shorter reference
	
	if (!profile || profile == NULL) {
		pr_err("%s: pH_task_struct_corrupted: No profile\n", DEVICE_NAME);
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
	
	// Allocate space for new_syscall
	new_syscall = kmalloc(sizeof(my_syscall), GFP_KERNEL);
	if (!new_syscall) {
		pr_err("%s: Unable to allocate space for new_syscall\n", DEVICE_NAME);
		return -ENOMEM;
	}
	pr_err("%s: Successfully allocated space for new_syscall\n", DEVICE_NAME);
	
	// Add new_syscall to the linked list of syscalls
	new_syscall->syscall_num = syscall;
	add_to_my_syscall_llist(process, new_syscall);
	
	return 0;
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

pH_profile* retrieve_pH_profile_by_filename(char* filename) {
	if (profile_llist_start == NULL) {
		return NULL;
	}
	
	pH_profile* iterator = profile_llist_start;
	
	do {
		if (strcmp(filename, iterator->filename) == 0) {
			return iterator;
		}
		
		iterator = iterator->next;
	} while (iterator);
	
	return NULL;
}

static long jsys_execve(const char __user *filename,
	const char __user *const __user *argv,
	const char __user *const __user *envp)
{
	char* path_to_binary;
	pH_task_struct* this_process;
	pH_profile* profile;
	
	if (!pH_aremonitoring) { goto not_monitoring; }

	pr_err("%s: In jsys_execve\n", DEVICE_NAME);
	
	// Allocate space for path_to_binary
	path_to_binary = kmalloc(sizeof(char) * 4000, GFP_KERNEL);
	if (!path_to_binary) {
		pr_err("%s: Unable to allocate memory for path_to_binary\n", DEVICE_NAME);
		goto no_memory;
	}
	
	// Copy memory from userspace to kernel land
	copy_from_user(path_to_binary, filename, sizeof(char) * 4000);
	pr_err("%s: path_to_binary = %s\n", DEVICE_NAME, path_to_binary);
	
	// Allocate memory for this_process
	this_process = kmalloc(sizeof(pH_task_struct), GFP_KERNEL);
	if (!this_process) {
		pr_err("%s: Unable to allocate memory for this_process\n", DEVICE_NAME, path_to_binary);
		goto no_memory;
	}
	
	// Initialize this process - check with Anil to see if these are the right values to initialize it to
	this_process->process_id = pid_vnr(task_tgid(current));
	//pH_reset_ALF(this_process);
	this_process->seq = NULL;
	this_process->syscall_llist = NULL;
	this_process->delay = 0;
	this_process->count = 0;
	pr_err("%s: Initialized process\n", DEVICE_NAME);
	
	// Retrieve the corresponding profile
	profile = retrieve_pH_profile_by_filename(path_to_binary);
	
	// If there is no corresponding profile, make a new one
	if (!profile) {
		profile = vmalloc(sizeof(pH_profile));
		if (!profile) {
			pr_err("%s: Unable to allocate memory for profile in jsys_execve\n", DEVICE_NAME, path_to_binary);
			goto no_memory;
		}
		
		new_profile(profile, path_to_binary);
		pr_err("%s: Made new profile\n", DEVICE_NAME);
		
		if (!profile) {
			pr_err("%s: new_profile() made a corrupted or NULL profile\n", DEVICE_NAME, path_to_binary);
		}
	}
	
	this_process->profile = profile;
	
	add_to_llist(this_process);
	pr_err("%s: Added this process to llist\n", DEVICE_NAME);
	
	process_syscall(59);
	pr_err("%s: Processed syscall\n", DEVICE_NAME);
	
	jprobe_return();
	return 0;
	
no_memory:
	pr_err("%s: Ran out of memory\n", DEVICE_NAME);
	jprobe_return();
	return 0;

not_monitoring:
	pr_err("%s: Not monitoring\n", DEVICE_NAME);
	jprobe_return();
	return 0;
}

/*
static struct jprobe sys_execve_jprobe = {
	.entry = jsys_execve,
	.kp = {
		.symbol_name = "sys_execve",
	},
};
*/

void print_llist(void) {
	pH_task_struct* iterator = llist_start;
	
	if (llist_start == NULL) {
		return;
	}
	
	pr_err("%s: Printing linked list...\n", DEVICE_NAME);
	do {
		pr_err("%s: Output: %ld %s\n", DEVICE_NAME, iterator->process_id, iterator->profile->filename);
		
		iterator = iterator->next;
	} while (iterator);
}

static int __init ebbchar_init(void){
	int ret, i;
	
	printk(KERN_INFO "%s: Initializing the EBBChar LKM\n", DEVICE_NAME);
	
	pH_aremonitoring = 1;
	
	for (i = 0; i < num_syscalls; i++) {
		ret = register_jprobe(&jprobes_array[i]);
		if (ret < 0) {
			pr_err("%s: register_jprobe failed, returned %d\n", DEVICE_NAME, ret);
			return -1;
		}
	}

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
	if (IS_ERR(ebbcharDevice)){          // Clean up if there is an error
	  class_destroy(ebbcharClass);      // Repeated code but the alternative is goto statements
	  unregister_chrdev(majorNumber, DEVICE_NAME);
	  printk(KERN_ALERT "%s: Failed to create the device\n", DEVICE_NAME);
	  return PTR_ERR(ebbcharDevice);
	}
	printk(KERN_INFO "%s: device class created correctly\n", DEVICE_NAME); // Device was initialized
	mutex_init(&ebbchar_mutex); // Initialize the mutex dynamically
	return 0;
}

static void __exit ebbchar_exit(void){
	int i;
	
	print_llist();
	
	for (i = 0; i < num_syscalls; i++) {
		unregister_jprobe(&jprobes_array[i]);
	}
	
	mutex_destroy(&ebbchar_mutex);
	device_destroy(ebbcharClass, MKDEV(majorNumber, 0));
	class_unregister(ebbcharClass);
	class_destroy(ebbcharClass);
	unregister_chrdev(majorNumber, DEVICE_NAME);
	printk(KERN_INFO "EBBChar: Goodbye from the LKM!\n");
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
	if (s->last < 0) { pr_err("%s: s->last is not initialized\n", DEVICE_NAME); return; }
	
	s->last = (s->last + 1) % (s->length);
	s->data[s->last] = new_value;
}

module_init(ebbchar_init);
module_exit(ebbchar_exit);
