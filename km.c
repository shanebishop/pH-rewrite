/*
Notes:
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
#include <linux/slab.h>      // For kmalloc and kfree
#include <linux/vmalloc.h>   // For vmalloc
#include <linux/ioctl.h>     // For ioctls

#include "system_call_prototypes.h"
#include "ebbcharmutex.h"       

MODULE_LICENSE("GPL");           
MODULE_AUTHOR("Shane Bishop");
MODULE_DESCRIPTION("Kernel module for pH");  
MODULE_VERSION("0.1");                

typedef struct pH_seq {
        int last;
        int length;
        u8 data[PH_MAX_SEQLEN];
	struct list_head seqList;
} pH_seq;

typedef struct pH_profile_data {
	int sequences;			// # sequences that have been inserted NOT the number of lookahead pairs
	unsigned long last_mod_count;	// # syscalls since last modification
	unsigned long train_count;	// # syscalls seen during training
	void *pages[PH_MAX_PAGES];
	int current_page;		// pages[current_page] contains free space
	int count_page;			// How many arrays have been allocated in the current page
	pH_seqflags *entry[PH_NUM_SYSCALLS];
} pH_profile_data;

typedef struct pH_profile pH_profile;

struct pH_profile {
	// My new fields
	struct hlist_node hlist; // Must be first field
	int identifier;
	
	// Anil's old fields
	int normal;		// Is test profile normal?
	int frozen;		// Is train profile frozen (potential normal)?
	time_t normal_time;	// When will forzen become true normal?
	int length;
	unsigned long count;	// Number of calls seen by this profile
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

typedef struct pH_task_state {
	pH_locality alf;
	pH_seq *seq;
	int delay;
	unsigned long count;
	pH_profile *profile;     /* pointer to appropriate profile */
} pH_task_state;

// My own structs
struct syscall_pair {
	unsigned long first_syscall;
	unsigned long second_syscall;
};

struct hash_struct {
	struct hlist_node hlist;
	int entry;
	int identifier;
};

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
#define num_syscalls 11                    // Holds current temp number of syscalls (not to be confused with PH_NUM_SYSCALLS)
struct jprobe jprobes_array[num_syscalls]; // Array of jprobes
#define num_kretprobes 1
struct kretprobe kretprobes_array[num_kretprobes]; // Array of kretprobes
DECLARE_HASHTABLE(proc_hashtable, 8);      // Declare hashtable
long userspace_pid;                        // The PID of the userspace process
char* output_string;
#define SIGNAL_PRIVILEGE 1
bool done_waiting_for_user = FALSE;
bool have_userspace_pid    = FALSE;
#define SYSCALLS_PER_WRITE 10
int syscalls_this_write;
pH_profile* current_profile;
bool have_bin_receive_ptr = FALSE;
const void* bin_receive_ptr;
bool binary_read = FALSE;

// Function prototypes required for dev_* functions
void pH_profile_mem2disk(pH_profile*, pH_disk_profile*);
int send_signal(int);
pH_profile* retrieve_pH_profile(int);

static int dev_open(struct inode *inodep, struct file *filep){
   //printk(KERN_INFO "%s: dev_open called", DEVICE_NAME);
   if(!mutex_trylock(&ebbchar_mutex)){                  // Try to acquire the mutex (returns 0 on fail)
	printk(KERN_ALERT "%s: Device in use by another process", DEVICE_NAME);
	return -EBUSY;
   }
   numberOpens++;
   printk(KERN_INFO "%s: Device has been opened %d time(s)\n", DEVICE_NAME, numberOpens);
   return 0;
}

/*
static ssize_t dev_ioctl(struct file* f, unsigned int cmd, unsigned long arg) {
	return -1; // Temporarily treat this as an error - fix this
	
	int rc;
	struct pH_profile *profile;
	pH_disk_profile* disk_profile = NULL;
	
	printk(KERN_INFO "%s: In dev_ioctl", DEVICE_NAME);
	
	if (syscalls_this_write < SYSCALLS_PER_WRITE) {
		printk(KERN_INFO "%s: Not enough syscalls processed yet", DEVICE_NAME);
		return -1;
	}
	
	syscalls_this_write = 0;
	
	profile = retrieve_pH_profile(current->pid);
	disk_profile = (pH_disk_profile*) kmalloc(sizeof(pH_disk_profile), GFP_KERNEL); // Use vmalloc?
	if (!disk_profile) {
		printk(KERN_INFO "%s: Unable to allocate memory for disk_profile in process_syscall", DEVICE_NAME);
		return -ENOMEM;
	}
	
	pH_profile_mem2disk(profile, disk_profile);
	
	switch (cmd) {
		case SEND_DATA:
			printk(KERN_INFO "%s: Retrieving data from user space code", DEVICE_NAME);
			rc = copy_from_user(disk_profile, (void*) arg, sizeof(disk_profile));
			//return -1; // Temporarily treat this as an error - fix this
			break;
		case RETRIEVE_DATA:
			printk(KERN_INFO "%s: Sending data to user space code", DEVICE_NAME);
			return -1; // Temporarily treat this as an error - fix this
			break;
		default:
			printk(KERN_INFO "%s: An unknown error occurred in dev_ioctl", DEVICE_NAME);
			return -1;
			break;
	}
	
	// Is there anything else I need to do in this function?
	
	return 0; // Only return 0 here, otherwise return something else on not success
}
*/

static int dev_release(struct inode *inodep, struct file *filep){
   mutex_unlock(&ebbchar_mutex); // release the mutex (i.e., lock goes up)
   //printk(KERN_INFO "%s: Device successfully closed\n", DEVICE_NAME);
   return 0;
}

static ssize_t dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset){
	pH_profile* current_profile;
	pH_disk_profile* disk_profile;
	int error_count = 0;
	
	printk(KERN_INFO "%s: In dev_read", DEVICE_NAME);

	if (!binary_read) {
		printk(KERN_INFO "%s: In !binary_read", DEVICE_NAME);
		//size_of_message = strlen(output_string);

		error_count = copy_to_user(buffer, output_string, size_of_message);

		if (error_count==0){          // success!
		  //printk(KERN_INFO "%s: Sent %s (%d characters) to the user\n", DEVICE_NAME, output_string, size_of_message);
		  return (size_of_message=0); // clear the position to the start and return 0
		}
		else {
		  printk(KERN_INFO "%s: Failed to send %d characters to the user\n", DEVICE_NAME, error_count);
		  return -EFAULT;      // Failed - return a bad address message
		}
	}
	
	printk(KERN_INFO "%s: In binary_read", DEVICE_NAME);
	
	bin_receive_ptr = (void*) buffer;

	current_profile = vmalloc(sizeof(pH_profile));
	if (current_profile == NULL) {
		printk(KERN_INFO "%s: Unable to allocate memory for current_profile", DEVICE_NAME);
		return -ENOMEM;
	}

	disk_profile = vmalloc(sizeof(pH_disk_profile));
	if (!disk_profile) {
		printk(KERN_INFO "%s: Unable to allocate memory for disk profile", DEVICE_NAME);
		vfree(current_profile);
		return -ENOMEM;
	}

	pH_profile_mem2disk(current_profile, disk_profile);
	printk(KERN_INFO "%s: Done conversion", DEVICE_NAME);

	printk(KERN_INFO "%s: Copying to user...", DEVICE_NAME);
	int error_count = copy_to_user(bin_receive_ptr, disk_profile, sizeof(pH_disk_profile*));
	if (error_count==0){           // success!
	  printk(KERN_INFO "%s: Successfully performed binary write to user space app\n", DEVICE_NAME);
	  return 0; // clear the position to the start and return 0
	}
	else {
	  printk(KERN_INFO "%s: Failed to send %d characters to the user\n", DEVICE_NAME, error_count);
	  return -EFAULT;      // Failed - return a bad address message
	}
}

static ssize_t dev_write(struct file *filep, const char *buf, size_t len, loff_t *offset){
	const char* buffer;
	int ret;
	
	printk(KERN_INFO "%s: In dev_write", DEVICE_NAME);
	
	binary_read = FALSE;
	
	if (numberOpens > 0) {
		printk(KERN_INFO "%s: In numberOpens > 0", DEVICE_NAME);
		
		if (have_userspace_pid) {
			printk(KERN_INFO "%s: In !have_bin_receive_ptr", DEVICE_NAME);
			/*
			bin_receive_ptr = kmalloc(sizeof(const void*), GFP_KERNEL);
			if (!bin_receive_ptr) {
				printk(KERN_INFO "%s: Unable to allocate memory for bin_receive_ptr", DEVICE_NAME);
				return -ENOMEM;
			}
			bin_receive_ptr = (const void*) buf;
			//printk(KERN_INFO "Performed cast operation successfully");
			have_bin_receive_ptr = TRUE;
			//printk(KERN_INFO "Set have_bin_receive_ptr to true successfully");
			*/
			
			// Send SIGSTOP signal to the userspace app
			int ret = send_signal(SIGSTOP);
			if (ret < 0) return ret;
			
			// We are done waiting for the user now
			done_waiting_for_user = TRUE;
			
			return 0;
		}
		
		buffer = kmalloc(sizeof(char) * 254, GFP_KERNEL);
		if (!buffer) {
			printk(KERN_INFO "%s: Unable to allocate memory for dev_write buffer", DEVICE_NAME);
			return -ENOMEM;
		}
		buffer = (const char*) buf;
		//printk(KERN_INFO "Performed cast successfully");
		
		//sprintf(message, "%s", buffer, len);   // appending received string with its length
		strcpy(message, buffer);
		//printk(KERN_INFO "Copied from buffer to message");
		//kfree(buffer); // Freeing this causes an error for some reason?
		//printk(KERN_INFO "Freed buffer");
		size_of_message = strlen(message);     // store the length of the stored message
		//printk(KERN_INFO "Did string manipulation successfully");
		
		if (message == NULL || size_of_message < 1) {
            printk(KERN_INFO "%s: Failed to read the message from userspace.%d%d\n", DEVICE_NAME, message == NULL, size_of_message < 1);
            
            if (send_signal(SIGTERM) < 0) send_signal(SIGKILL);
            
            printk(KERN_INFO "Userspace process killed");
            
            return -1;
        }
	
		//printk(KERN_INFO "%s: Received %s (%zu characters) from the user\n", DEVICE_NAME, message, len);
		
		// If you do not have the userspace pid, then you must be getting it right now
		if (!have_userspace_pid) {
			//printk(KERN_INFO "%s: In !have_userspace_pid", DEVICE_NAME);
			
			kstrtol(message, 10, &userspace_pid);
			have_userspace_pid = TRUE;

			//binary_read = TRUE;
			//strcpy(output_string, "t");
			ret = send_signal(SIGSTOP);
			if (ret < 0) return ret;
			//done_waiting_for_user = FALSE;
			done_waiting_for_user = TRUE;
			printk(KERN_INFO "Ready for binary_read");

			return 0;
		}
		/*
		else {
			// Allocate space for the profile
			pH_profile* profile = kmalloc(sizeof(pH_profile), GFP_KERNEL);
			new_profile(profile);
			
			// Add this new profile to the hashtable
			//hash_add(proc_hashtable, &profile->hlist, current->pid);
			current_profile = profile;
		   
			//binary_read = TRUE;
			strcpy(output_string, "t");
			//printk(KERN_INFO "Ready for binary_read");
		}
		*/
		
		// Send SIGSTOP signal to the userspace app
		int ret = send_signal(SIGSTOP);
		if (ret < 0) return ret;
		
		// We are done waiting for the user now
		done_waiting_for_user = TRUE;
	}

	return len;
}

static struct file_operations fops =
{
   .open = dev_open,
   .read = dev_read,
   .write = dev_write,
   //.unlocked_ioctl = dev_ioctl,
   .release = dev_release,
};

pH_profile* retrieve_pH_profile(int key) {
	pH_profile* pH_profile;
	
	hash_for_each_possible(proc_hashtable, pH_profile, hlist, key) {
		if (pH_profile->identifier == key) {
			return pH_profile;
		}
	}
	
	return NULL;
}

inline struct syscall_pair pH_append_call(pH_seq *s, int new_value);

// Returns true if a message was received from the user, false otherwise
bool message_received(void) {
    if (message == NULL || message[0] == '\0') {
        return FALSE;
    } else return TRUE;
}

// Returns the task_struct of the userspace app
struct task_struct* get_userspace_task_struct(void) {
	if (message_received()) {
		return pid_task(find_pid_ns(userspace_pid, &init_pid_ns), PIDTYPE_PID);
	}
	return NULL;
}

// Sends a signal to the userspace app
int send_signal(int signal_to_send) {
	// Retrieve the usersapce task_struct
	struct task_struct* t = get_userspace_task_struct();
	if (t == NULL) {
		printk(KERN_INFO "%s: No such PID", DEVICE_NAME);
		return -ENODEV;
	}
	
	// Send the signal
	int ret = send_sig(signal_to_send, t, SIGNAL_PRIVILEGE);
	if (ret < 0) {
		printk(KERN_INFO "%s: Unable to send signal", DEVICE_NAME);
		return ret;
	}

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
	return 0;
}

void pH_profile_mem2disk(pH_profile*, pH_disk_profile*);

// Process system calls
int process_syscall(long syscall) {
	int i;
	
	// If still waiting for the userpace process, return
	if (!done_waiting_for_user) return -1;
	
	syscalls_this_write++;
	printk(KERN_INFO "%s: Syscall was received. %d", DEVICE_NAME, syscalls_this_write);
	
	struct pH_profile *profile;
	
	profile = retrieve_pH_profile(current->pid);
	
	if (profile != NULL) {
	    pH_seq* seq = &profile->seq;
	}
	else {
	    if (message == NULL || message[0] == '\0') {
	        printk(KERN_INFO "%s: Message was null", DEVICE_NAME);
	        return -1;
	    }

		// Allocate space for the profile
		profile = kmalloc(sizeof(pH_profile), GFP_KERNEL);

		// Initialize the profile
		//profile->hlist = ;
	    //profile->identifier = ;

        profile->normal = 0;  /* we just started - not normal yet! */
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
        //pH_refcount_init(profile, 0);
        //profile->filename = filename; // Make sure to fix this line
        
        //pH_open_seq_logfile(profile);

        profile->next = NULL;
        
        // Add this new profile to the hashtable
        hash_add(proc_hashtable, &profile->hlist, current->pid);
        current_profile = profile;
	}
	
	//if (syscalls_this_write >= SYSCALLS_PER_WRITE) {
		binary_read = TRUE;
		strcpy(output_string, "t");
		int ret = send_signal(SIGCONT);
		if (ret < 0) return ret;
		done_waiting_for_user = FALSE;
		printk(KERN_INFO "Ready for binary_read");
	//}
	
	/*
	// Prepare output_string
	strcpy(output_string, "w");
	char syscall_num_as_string[256];
	sprintf(syscall_num_as_string, "%d", syscall);
	strcat(output_string, syscall_num_as_string);
	
	// Send SIGCONT signal
	int ret = send_signal(SIGCONT);
	if (ret < 0) return ret;
	
	// We are now waiting for the userspace program
	done_waiting_for_user = FALSE;
	*/
	
	//pr_info("JProbe Example: Syscall seems to have been processed correctly.\n");
	
	return 0;
}

/* Proxy routine having the same arguments as actual routine */
static long jopen_exec(const char* name)
{
	//pr_info("jprobe: name = %s\n", name);

	jprobe_return();
	return 0;
}

// Proxy routine for do_execve
static long jdo_execve(struct filename *filename,
	const char __user *const __user *__argv,
	const char __user *const __user *__envp) {
	//pr_info("JProbe Example: filename = %s\n", filename->name);
	
	jprobe_return();
	return 0;
}

// Proxy routine for sys_execve
static long jsys_execve(const char __user *filename,
	const char __user *const __user *__argv,
	const char __user *const __user *__envp) {
	//pr_info("JProbes Example: filename = %s\n", filename);
	//pr_info("New execve system call");

	process_syscall(59);
	
	/*
	// Prepare output_string
	strcpy(output_string, "w");
	strcat(output_string, filename);
	
	// Send SIGCONT signal
	int ret = send_signal(SIGCONT);
	if (ret < 0) return ret;
	
	// We are no waiting for the userspace program
	done_waiting_for_user = FALSE;
	*/
	
	jprobe_return();
	return 0;
}

// Proxy routine for fork
static long jsys_fork(void) {
	//pr_info("JProbes Example: Fork system call was probed");
	jprobe_return();
	return 0;
}

// Proxy routine for read
static long jsys_read(unsigned int fd, char __user *buf, size_t count) {
	//pr_info("JProbes Example: Read system call was probed");
	jprobe_return();
	return 0;
}

// Proxy routine for write
static long jsys_write(unsigned int fd, const char __user *buf,
	size_t count) {
	//pr_info("JProbes Example: Write system call was probed");
	jprobe_return();
	return 0;
}

// Proxy routine for open
static long jsys_open(const char __user *filename,
	int flags, umode_t mode) {
	//pr_info("JProbes Example: Open system call was probed");
	jprobe_return();
	return 0;				
}

// Proxy routine for close
static long jsys_close(unsigned int fd) {
	//pr_info("JProbes Example: Close system call was probed");
	jprobe_return();
	return 0;
}

// Proxy routine for lseek
static long jsys_lseek(unsigned int fd, off_t offset,
	unsigned int whence) {
	//pr_info("JProbes Example: lseek system call was probed");
	jprobe_return();
	return 0;
} 

// Proxy routine for llseek
static long jsys_llseek(unsigned int fd, unsigned long offset_high,
	unsigned long offset_low, loff_t __user *result,
	unsigned int whence) {
	//pr_info("JProbes Example: llseek system call was probed");
	jprobe_return();
	return 0;
}

// Proxy routine for getpid
static long jsys_getpid(void) {
	//pr_info("JProbes Example: getpid system call was probed");
	jprobe_return();
	return 0;
}

// JProbe structs for system calls
static struct jprobe open_exec_jprobe = {
	.entry = jopen_exec,
	.kp = {
		.symbol_name = "open_exec",
	},
};

static struct jprobe do_execve_jprobe = {
	.entry = jdo_execve,
	.kp = {
		.symbol_name = "do_execve",
	},
};

static struct jprobe sys_execve_jprobe = {
	.entry = jsys_execve,
	.kp = {
		.symbol_name = "sys_execve",
	},
};

static struct jprobe sys_fork_jprobe = {
	.entry = jsys_fork,
	.kp = {
		.symbol_name = "sys_fork",
	},
};

static struct jprobe sys_read_jprobe = {
	.entry = jsys_read,
	.kp = {
		.symbol_name = "sys_read",
	},
};

static struct jprobe sys_write_jprobe = {
	.entry = jsys_write,
	.kp = {
		.symbol_name = "sys_write",
	},
};

static struct jprobe sys_open_jprobe = {
	.entry = jsys_open,
	.kp = {
		.symbol_name = "sys_open",
	},
};

static struct jprobe sys_close_jprobe = {
	.entry = jsys_close,
	.kp = {
		.symbol_name = "sys_close",
	},
};

static struct jprobe sys_lseek_jprobe = {
	.entry = jsys_lseek,
	.kp = {
		.symbol_name = "sys_lseek",
	},
};

static struct jprobe sys_llseek_jprobe = {
	.entry = jsys_llseek,
	.kp = {
		.symbol_name = "sys_llseek",
	},
};

static struct jprobe sys_getpid_jprobe = {
	.entry = jsys_getpid,
	.kp = {
		.symbol_name = "sys_getpid",
	},
};

// Struct required for all kretprobe structs
struct my_kretprobe_data {
	ktime_t entry_stamp;
};

static int fork_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	//int retval = regs_return_value(regs);
	//struct my_data *data = (struct my_data *)ri->data;
	//s64 delta;
	ktime_t now;

	now = ktime_get();
	//delta = ktime_to_ns(ktime_sub(now, data->entry_stamp));
	//printk(KERN_INFO "%s: _do_fork returned %d", DEVICE_NAME, retval);
	return 0;
}

static struct kretprobe fork_kretprobe = {
	.handler = fork_handler,
	.data_size = sizeof(struct my_kretprobe_data),
	.maxactive = 20,
};


static int __init ebbchar_init(void){
   int ret, i;
	
	pr_info("%s: Initiating %s", DEVICE_NAME, DEVICE_NAME);
	
	// Initialize jprobes_array
	jprobes_array[0] = open_exec_jprobe;
	jprobes_array[1] = do_execve_jprobe;
	jprobes_array[2] = sys_execve_jprobe;
	jprobes_array[3] = sys_fork_jprobe;
	jprobes_array[4] = sys_read_jprobe;
	jprobes_array[5] = sys_write_jprobe;
	jprobes_array[6] = sys_open_jprobe;
	jprobes_array[7] = sys_close_jprobe;
	jprobes_array[8] = sys_lseek_jprobe;
	jprobes_array[9] = sys_llseek_jprobe;
	jprobes_array[10] = sys_getpid_jprobe;
	
	// Initialize kretprobes_array
	kretprobes_array[0] = fork_kretprobe;
	
	hash_init(proc_hashtable);
	
	syscalls_this_write = 0;
	
	// Allocate memory for current_profile
	current_profile = kmalloc(sizeof(pH_profile), GFP_KERNEL);
	if (current_profile == NULL) {
		printk(KERN_INFO "%s: Unable to allocate memory for current_profile", DEVICE_NAME);
		return -ENOMEM;
	}

	// Allocate memory for output_string
	output_string = kmalloc(sizeof(char) * 254, GFP_KERNEL);
	if (output_string == NULL) {
		printk(KERN_INFO "%s: Unable to allocate memory for output_string", DEVICE_NAME);
		return -ENOMEM;
	}

	// Try to dynamically allocate a major number for the device
   majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
   if (majorNumber<0){
      printk(KERN_ALERT "%s: Failed to register a major number\n", DEVICE_NAME);
      return majorNumber;
   }
   //printk(KERN_INFO "EBBChar: registered correctly with major number %d\n", majorNumber);

   // Register the device class
   ebbcharClass = class_create(THIS_MODULE, CLASS_NAME);
   if (IS_ERR(ebbcharClass)){           // Check for error and clean up if there is
      unregister_chrdev(majorNumber, DEVICE_NAME);
      printk(KERN_ALERT "%s: Failed to register device class\n", DEVICE_NAME);
      return PTR_ERR(ebbcharClass);     // Correct way to return an error on a pointer
   }
   //printk(KERN_INFO "EBBChar: device class registered correctly\n");

   // Register the device driver
   ebbcharDevice = device_create(ebbcharClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
   if (IS_ERR(ebbcharDevice)){          // Clean up if there is an error
      class_destroy(ebbcharClass);      // Repeated code but the alternative is goto statements
      unregister_chrdev(majorNumber, DEVICE_NAME);
      printk(KERN_ALERT "%s: Failed to create the device\n", DEVICE_NAME);
      return PTR_ERR(ebbcharDevice);
   }
   //printk(KERN_INFO "EBBChar: device class created correctly\n"); // Made it! device was initialized
   mutex_init(&ebbchar_mutex);          // Initialize the mutex dynamically

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
	
	return 0;
}

static void __exit ebbchar_exit(void){
	int i;

	// Deallocate all previously allocated memory - don't forget to do this for hashtables!
	if (output_string != NULL) kfree(output_string);
	printk(KERN_INFO "Freed output_string");
	if (current_profile != NULL) kfree(current_profile);
	printk(KERN_INFO "Freed current_profile");
	//if (bin_receive_ptr != NULL) kfree(bin_receive_ptr); // For some reason this causes an error?
	//printk(KERN_INFO "Freed bin_receive_ptr");
   
    if (send_signal(SIGTERM) < 0) {
    	send_signal(SIGKILL); // If this signal fails, that's too bad - we still need to exit
    }
   
	for (i = 0; i < num_syscalls; i++) {
		unregister_jprobe(&jprobes_array[i]);
		//pr_info("jprobe at %p unregistered\n", jprobes_array[i].kp.addr);
	}
	
	for (i = 0; i < num_kretprobes; i++) {
		unregister_kretprobe(&kretprobes_array[i]);
	
		// nmissed > 0 suggests the maxactive was set too low
		printk(KERN_INFO "%s: Missed probing %d instances of %s\n", DEVICE_NAME, kretprobes_array[i].nmissed, kretprobes_array[i].kp.symbol_name);
	}
	
	mutex_destroy(&ebbchar_mutex);                       // destroy the dynamically-allocated mutex
    device_destroy(ebbcharClass, MKDEV(majorNumber, 0)); // remove the device
    class_unregister(ebbcharClass);                      // unregister the device class
    class_destroy(ebbcharClass);                         // remove the device class
    unregister_chrdev(majorNumber, DEVICE_NAME);         // unregister the major number
    printk(KERN_INFO "%s: Goodbye from the LKM!\n", DEVICE_NAME);
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

void pH_profile_data_mem2disk(pH_profile_data *mem, pH_disk_profile_data *disk)
{
        //int i, j;

        disk->sequences = mem->sequences;
        disk->last_mod_count = mem->last_mod_count;
        disk->train_count = mem->train_count;
        printk(KERN_INFO "%s: Successfully completed first block of code in pH_profile_data_mem2disk", DEVICE_NAME);

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
        
        printk(KERN_INFO "%s: Successfully reached end of pH_profile_data_mem2disk function", DEVICE_NAME);
}

void pH_profile_mem2disk(pH_profile *profile, pH_disk_profile *disk_profile)
{
        /* make sure magic is less than PH_FILE_MAGIC_LEN! */
        strcpy(disk_profile->magic, PH_FILE_MAGIC);
        disk_profile->normal = 1234; // Fix this
        disk_profile->frozen = profile->frozen;
        disk_profile->normal_time = profile->normal_time;
        disk_profile->length = profile->length;
        disk_profile->count = profile->count;
        disk_profile->anomalies = profile->anomalies;
        strcpy(disk_profile->filename, "");
        printk(KERN_INFO "%s: Made it through first block of pH_profile_mem2disk", DEVICE_NAME);

        //pH_profile_data_mem2disk(&(profile->train), &(disk_profile->train));
        //pH_profile_data_mem2disk(&(profile->test), &(disk_profile->test));
        
        printk(KERN_INFO "%s: Made it to the end of pH_profile_mem2disk function", DEVICE_NAME);
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

inline void pH_refcount_init(pH_profile *profile, int i)
{
        profile->refcount.counter = i;
}

inline int pH_LFC(pH_task_state *s)
{
        return (s->alf.total);
}

void pH_open_seq_logfile(pH_profile *profile)
{
        char *seq_filename = (char *) __get_free_page(GFP_USER);
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
        free_page((unsigned long) seq_filename);
}

// Called by pH_read_profile, which is called by pH_execve
void pH_add_new_profile(pH_profile *profile, char *filename)
{
        int i;

        profile->normal = 0;  /* we just started - not normal yet! */
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
        
        pH_open_seq_logfile(profile);

        profile->next = pH_profile_list;
        pH_profile_list = profile;
}

inline struct syscall_pair pH_append_call(pH_seq *s, int new_value)
{
        struct syscall_pair pair;
        pair.first_syscall = s->data[s->last];
        pair.second_syscall = new_value;
        
        s->last = (s->last + 1) % (s->length);
        s->data[s->last] = new_value;
        
        return pair;
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

inline void pH_train(pH_task_state *s)
{
        pH_seq *seq = s->seq;
        pH_profile *profile = s->profile;
        pH_profile_data *train = &(profile->train);

        train->train_count++;
        
        pH_add_seq(seq,train);  
        train->sequences++; 
        train->last_mod_count = 0;
}


module_init(ebbchar_init);
module_exit(ebbchar_exit);
