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
	int delay;
	unsigned long count;
	pH_profile* profile; // Pointer to appropriate profile
} pH_task_struct;

static void jhandle_signal(struct ksignal*, struct pt_regs*);

struct jprobe handle_signal_jprobe = {
	.entry = jhandle_signal,
};

static long jsys_sigreturn(struct pt_regs*);

struct jprobe sys_sigreturn_jprobe = {
	.entry = jsys_sigreturn,
	.kp = {
		.symbol_name = "sys_sigreturn",
	},
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
//int pH_loglevel = PH_LOG_ACTION;
int pH_log_sequences = 0;
int pH_suspend_execve = 0; /* min LFC to suspend execve's, 0 = no suspends */
int pH_suspend_execve_time = 3600 * 24 * 2;  /* time to suspend execve's */
int pH_normal_wait = 7 * 24 * 3600;/* seconds before putting normal to work */

// My global variables
pH_task_struct* llist_start = NULL;
struct jprobe jprobes_array[num_syscalls];
bool module_inserted_successfully = FALSE;

void add_to_profile_llist(pH_profile* p) {
	if (pH_profile_list == NULL) {
		pH_profile_list = p;
		p->next = NULL;
	}
	else {
		pH_profile* iterator = pH_profile_list;
		
		while (iterator->next) iterator = iterator->next;
		
		iterator->next = p;
		p->next = NULL;
	}
}

// Makes a new pH_profile and stores it in profile
// profile must be allocated before this function is called
int new_profile(pH_profile* profile, char* filename) {
	int i;

	if (!profile || profile == NULL) {
		pr_err("%s: ERROR: NULL profile was passed to new_profile()\n", DEVICE_NAME);
		return -1;
	}
	
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
	//profile->train.current_page = 0;
	//profile->train.count_page = 0;

	for (i=0; i<PH_NUM_SYSCALLS; i++) {
	    profile->train.entry[i] = NULL;
	}

	/*
	for (i=0; i<PH_MAX_PAGES; i++) {
	    profile->train.pages[i] = NULL;
	}
	*/

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

// Function prototypes for process_syscall
inline void pH_append_call(pH_seq*, int);
inline void pH_train(pH_task_state*);

int process_syscall(long syscall) {
	pH_task_struct* process;
	my_syscall* new_syscall;
	pH_profile* profile;
	
	if (!module_inserted_successfully) return 0;
	
	if (!pH_aremonitoring) return 0;
	
	// Retrieve process
	process = llist_retrieve_process(pid_vnr(task_tgid(current)));
	if (!process) {
		// Ignore this syscall
		return 0;
	}
	//pr_err("%s: syscall=%d\n", DEVICE_NAME, syscall);
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
	
	pH_train(process);
	pr_err("%s: Trained process\n", DEVICE_NAME);
	
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
	pH_profile* iterator = pH_profile_list;
	
	if (pH_profile_list == NULL) {
		return NULL;
	}
	
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
	
	if (!module_inserted_successfully) { goto not_inserted; }
	
	if (!pH_aremonitoring) goto not_monitoring;

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
	else {
		kfree(path_to_binary);
	}
	
	this_process->profile = profile;
	
	add_to_llist(this_process);
	pr_err("%s: Added this process to llist\n", DEVICE_NAME);
	
	process_syscall(59);
	pr_err("%s: Back in jsys_execve after processing syscall\n", DEVICE_NAME);
	
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
	
not_inserted:
	pr_err("%s: Module was not inserted successfully\n", DEVICE_NAME);
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

// Struct required for all kretprobe structs
struct my_kretprobe_data {
	ktime_t entry_stamp;
};

static int fork_handler(struct kretprobe_instance* ri, struct pt_regs* regs) {
	int retval;
	ktime_t now;
	pH_task_struct* process;
	
	if (!module_inserted_successfully) return 0;
	
	pr_err("%s: In fork_handler\n", DEVICE_NAME);
	
	retval = regs_return_value(regs);
	now = ktime_get();
	
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
	
	pr_err("%s: In exit_handler for %d\n", DEVICE_NAME, pid_vnr(task_tgid(current)));
	
	process = llist_retrieve_process(pid_vnr(task_tgid(current)));
	
	if (process == NULL) return 0;
	
	pr_err("%s: In exit_handler for %d %s\n", DEVICE_NAME, pid_vnr(task_tgid(current)), process->profile->filename);
	
	retval = regs_return_value(regs);
	now = ktime_get();
	
	free_pH_task_struct(process);
	
	return 0;
}

static int exit_entry_handler(struct kretprobe_instance* ri, struct pt_regs* regs) {
	pH_task_struct* process;
	
	if (!module_inserted_successfully) return 0;
	
	pr_err("%s: In exit_handler for %d\n", DEVICE_NAME, pid_vnr(task_tgid(current)));
	
	process = llist_retrieve_process(pid_vnr(task_tgid(current)));
	
	if (process == NULL) return 0;
	
	pr_err("%s: In exit_handler for %d %s\n", DEVICE_NAME, pid_vnr(task_tgid(current)), process->profile->filename);
	
	free_pH_task_struct(process);
	
	return 0;
}

static struct kretprobe exit_kretprobe = {
	.entry_handler = exit_entry_handler,
	.handler = exit_handler,
	.data_size = sizeof(struct my_kretprobe_data),
	.maxactive = 20,
};

void pH_free_profile_storage(pH_profile* profile) {
	int i;
	
	pr_err("%s: In pH_free_profile_storage\n", DEVICE_NAME);
	
	kfree(profile->filename);
	profile->filename = NULL;
	
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
}

void pH_remove_profile_from_list(pH_profile* profile) {
	pH_profile *prev_profile, *cur_profile;
	
	if (!profile || profile == NULL) return;
	
	pr_err("%s: In pH_remove_profile_from_list\n", DEVICE_NAME);
	
	if (pH_profile_list == NULL) {
		err("pH_profile_list is empty (NULL) when trying to free profile %s", profile->filename);
	}
	else if (pH_profile_list == profile) {
		pH_profile_list = pH_profile_list->next;
	}
	else {
		prev_profile = pH_profile_list;
		cur_profile = pH_profile_list->next;
		while (cur_profile != NULL) {
			if (cur_profile == profile) [
				prev_profile->next = profile->next;
				
				return;
			}
				
			prev_profile = cur_profile;
			cur_profile = cur_profile->next;
		}
		
		err("While freeing, couldn't find profile %s in pH_profile_list", profile->filename);
	}
}

void pH_free_profile(pH_profile* profile) {
	pr_err("%s: In pH_free_profile\n", DEVICE_NAME);
	
	if (profile == NULL) {
		err("No profile to free!");
	}
	
	pH_remove_profile_from_list(profile);
	
	//pH_close_logfile(profile->seq_logfile);
	profile->seq_logfile = NULL;
	
	if (pH_aremonitoring) {
		//pH_write_profile(profile);
	}
	
	pH_free_profile_storage(profile);
	vfree(profile);
	profile = NULL; // This is okay, becsue profile was removed from the linked list above
}
				
void remove_process_from_llist(pH_task_struct* process) {
	pH_task_struct *prev_process, *cur_process;
	
	if (!process || process == NULL) return;
	
	pr_err("%s: In pH_remove_profile_from_list\n", DEVICE_NAME);
	
	if (llist_start == NULL) {
		err("pH_profile_list is empty (NULL) when trying to free profile %s", profile->filename);
	}
	else if (llist_start == profile) {
		llist_start = llist_start->next;
	}
	else {
		prev_process = llist_start;
		cur_process = llist_start->next;
		while (cur_process != NULL) {
			if (cur_process == profile) [
				prev_process->next = profile->next;
				
				return;
			}
				
			prev_process = cur_process;
			cur_process = cur_process->next;
		}
		
		err("While freeing, couldn't find process %ld in llist_start", process->process_id);
	}
}
				
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
				
void free_profiles(void) {
	pH_profile* current_profile;
	pH_profile* iterator = pH_profile_list;
	
	while (iterator) {
		current_profile = iterator;
		iterator = iterator->next;
		kfree(current_profile);
		current_profile = NULL;
	}
}

void stack_pop(pH_task_struct*);
				
void free_pH_task_struct(pH_task_struct* process) {
	pH_profile* profile;
	
	if (!process || process == NULL) {
		pr_err("%s: process is NULL in free_pH_task_struct\n", DEVICE_NAME);
		return;
	}
	
	while (process->seq != NULL) {
		stack_pop(process);
	}
	
	free_syscall(process);
	
	profile = process->profile;
	
	if (profile != NULL) {
		atomic_dec(&(process->refcount));
		
		if (profile->refcount.counter < 1) {
			profile->refcount.counter = 0;
			
			// Free profile
			pH_free_profile(profile);
			profile = NULL; // Okay becasue the profile is removed from llist in pH_free_profile
		}
	}
	
	// When everything is done, remove process from llist, vfree process
	remove_process_from_llist(process);
	vfree(process);
	process = NULL;
}
				
static long jsys_exit(int error_code) {
	pH_task_struct* process;
	
	if (!module_inserted_successfully) goto not_inserted;
	
	process = llist_retrieve_process(pid_vnr(task_tgid(current)));
	
	if (process == NULL) goto not_monitoring;
	
	process_syscall(73); // Process this syscall before calling free_pH_task_struct on process
	
	free_pH_task_struct(process);
	
	jprobe_return();
	return 0;

not_monitoring:
	pr_err("%s: %d had no pH_task_struct assosicated with it\n", DEVICE_NAME, pid_vnr(task_tgid(current)));
	jprobe_return();
	return 0;

not_inserted:
	jprobe_return();
	return 0;
}
				
void stack_push(pH_task_struct* process, pH_seq* new_node) {
	pH_seq* top = process->seq;
	
	if (top == NULL) {
		new_node->next = NULL;
		top = new_node;
	}
	else {
		new_node->next = top;
		top = new_node;
	}
}
				
void stack_pop(pH_task_struct* process) {
	pH_seq* temp;
	pH_seq* top = process->seq;
	
	if (top == NULL) {
		pr_err("%s: Stack is empty - cannot delete an element\n", DEVICE_NAME);
		return;
	}
	
	temp = top;
	top = top->next;
	kfree(temp);
	temp = NULL;
}
				
pH_seq* stack_peek(pH_task_struct* process) {
	return process->seq;
}
				
static void jhandle_signal(struct ksignal* ksig, struct pt_regs* regs) {
	pH_seq* new_sequence;
	pH_task_struct* process;
	
	if (!module_inserted_successfully) goto not_inserted;
	
	new_sequence = kmalloc(sizeof(pH_seq), GFP_KERNEL);
	
	process = llist_retrieve_process(pid_vnr(task_tgid(current)));
	
	if (process != NULL) {
		stack_push(process, new_sequence);
	}
	else {
		kfree(new_sequence);
	}
	
	jprobe_return();
	return 0;
	
not_inserted:
	jprobe_return();
	return;
}
				
static long jsys_sigreturn(struct pt_regs* regs) {
	pH_task_struct* process);
	
	if (!module_inserted_successfully) goto not_inserted;
	
	process = llist_retrieve_process(pid_vnr(task_tgid(current)));
	
	if (process != NULL) {
		stack_pop(process);
	}
	
	process_syscall(383);
	
	jprobe_return();
	return 0;
	
not_inserted:
	jprobe_return();
	return;
}
				
void free_pH_task_structs(void) {
	while (llist_start != NULL) {
		free_pH_task_struct(llist_start);
	}
}
				
static int __init ebbchar_init(void){
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
	
	// Register fork_kretprobe
	fork_kretprobe.kp.symbol_name = "_do_fork";
	ret = register_kretprobe(&fork_kretprobe);
	if (ret < 0) {
		pr_err("%s: Failed to register _do_fork kretprobe, returned %d\n", DEVICE_NAME, ret);
		
		mutex_destroy(&ebbchar_mutex);
		device_destroy(ebbcharClass, MKDEV(majorNumber, 0));
		class_unregister(ebbcharClass);
		class_destroy(ebbcharClass);
		unregister_chrdev(majorNumber, DEVICE_NAME);

		pr_err("%s: Module has (hopefully) been removed entirely\n", DEVICE_NAME);
		pr_err("%s: ...But just in case, run this command: 'sudo rmmod km'\n", DEVICE_NAME);

		return PTR_ERR(ebbcharDevice);
	}
	
	// Register exit_kretprobe
	exit_kretprobe.kp.addr = (kprobe_opcode_t*) kallsyms_lookup_name("do_exit");
	ret = register_kretprobe(&exit_kretprobe);
	if (ret < 0) {
		pr_err("%s: Failed to register do_exit kretprobe, returned %d\n", DEVICE_NAME, ret);
		
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
	
	for (i = 0; i < num_syscalls; i++) {
		ret = register_jprobe(&jprobes_array[i]);
		if (ret < 0) {
			pr_err("%s: register_jprobe failed (%s), returned %d\n", DEVICE_NAME, jprobes_array[i].kp.symbol_name, ret);
			
			unregister_kretprobe(&fork_kretprobe);
			unregister_kretprobe(&exit_kretprobe);
			
			// Should it be j <= i?
			for (j = 0; j < i; j++) {
				unregister_jprobe(&jprobes_array[i]);
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
	}
	
	pr_err("%s: Sucessfully initialized %s\n", DEVICE_NAME, DEVICE_NAME);
	module_successfully_inserted = TRUE;
	pH_aremonitoring = 1;
	
	return 0;
}

// Perhaps the best way to remove the module is just to reboot?
static void __exit ebbchar_exit(void){
	int i;
	
	pr_err("%s: Exiting...\n", DEVICE_NAME);
	
	//print_llist(); // For now, don't bother with printing the llist
	
	for (i = 0; i < num_syscalls; i++) {
		unregister_jprobe(&jprobes_array[i]);
	}
	
	unregister_kretprobe(&fork_kretprobe);
	pr_err("%s: Missed probing %d instances of fork\n", DEVICE_NAME, fork_kretprobe.nmissed);
	unregister_kretprobe(&exit_kretprobe);
	pr_err("%s: Missed probing %d instances of exit\n", DEVICE_NAME, exit_kretprobe.nmissed);
	
	pr_err("%s: Freeing profiles...\n", DEVICE_NAME);
	free_profiles();
	pr_err("%s: Freeing pH_task_structs...\n", DEVICE_NAME);
	free_pH_task_structs();
	
	mutex_destroy(&ebbchar_mutex);
	device_destroy(ebbcharClass, MKDEV(majorNumber, 0));
	class_unregister(ebbcharClass);
	class_destroy(ebbcharClass);
	unregister_chrdev(majorNumber, DEVICE_NAME);
	pr_err("EBBChar: Goodbye from the LKM!\n");
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

int pH_add_seq_storage(pH_profile_data *data, int val)
{
        pH_seqflags *page;
	int i, j;

	/*
        if (data->count_page >= PH_COUNT_PAGE_MAX) {
                data->current_page++;
                data->count_page = 0;
        }

        if (data->current_page >= PH_MAX_PAGES)
                return -1;

        if (data->count_page == 0) {
                page = (pH_seqflags *) kmalloc(PAGE_SIZE, GFP_KERNEL);
                if (page)
                        data->pages[data->current_page] = page;
                else
                        return -1;
        } else {
                page = data->pages[data->current_page];
        }

        data->entry[val] = page + (data->count_page * PH_NUM_SYSCALLS);
	*/
	
	data->entry[val] = kmalloc(sizeof(pH_seqflags) * PH_NUM_SYSCALLS, GFP_KERNEL);
	if (!data->entry[val] {
		pr_err("%s: Unable to allocate memory in pH_add_seq_storage\n", DEVICE_NAME);
		return -ENOMEM;
	}
	    
	for (i = 0; i < PH_NUM_SYSCALLS; i++) {
		data->entry[val][i] = 0;
	}
        
        return 0;
}

void pH_add_seq(pH_seq *s, pH_profile_data *data)
{
        int i, cur_call, prev_call, cur_idx;
        u8 *seqdata = s->data;
        int seqlen = s->length;
	pr_err("%s: Initialized variables for pH_add_seq\n", DEVICE_NAME);
	
	if (!data || data == NULL) {
		pr_err("%s: ERROR: data is NULL in pH_add_seq\n", DEVICE_NAME);
		return;
	}
        
        cur_idx = s->last;
        cur_call = seqdata[cur_idx];
	pr_err("%s: Initialized cur_idx and cur_call\n", DEVICE_NAME);
	
        for (i = 1; i < seqlen; i++) {
		pr_err("%s: i=%d cur_call=%d prev_call=%d cur_idx=%d\n", DEVICE_NAME, i, cur_call, prev_call, cur_idx);
                if (data->entry[cur_call] == NULL) {
                        pr_err("%s: data->entry[cur_call] == NULL\n", DEVICE_NAME);
			if (pH_add_seq_storage(data, cur_call))
                                return;
                }
		prev_call = seqdata[(cur_idx + seqlen - i) % seqlen];
		pr_err("%s: Set prev_call\n", DEVICE_NAME);

		data->entry[cur_call][prev_call] |= (1 << (i - 1));
		pr_err("%s: Set data->entry values\n", DEVICE_NAME);

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

inline void pH_train(pH_task_state *s)
{
        pH_seq *seq = s->seq;
        pH_profile *profile = s->profile;
        pH_profile_data *train = &(profile->train);

        train->train_count++;
        if (pH_test_seq(seq, train)) { 
                if (profile->frozen) {
                        profile->frozen = 0;
                        action("%d (%s) normal cancelled", current->pid, profile->filename);
                }
                pH_add_seq(seq,train);  
                train->sequences++; 
                train->last_mod_count = 0;

                //pH_log_sequence(profile, seq);
	} else {
                unsigned long normal_count; 
                
                train->last_mod_count++;
                
                if (profile->frozen)
                        return;

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
