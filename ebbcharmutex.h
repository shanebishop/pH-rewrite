// My definitions
#define TRUE         (1 == 1)
#define FALSE        (!TRUE)

#define  DEVICE_NAME "ebbchar" // The device will appear at /dev/ebbchar using this value
#define  CLASS_NAME  "ebb"     // The device class

#define SEND_DATA 1
#define RETRIEVE_DATA 2

// Anil's definitions
#define PH_NUM_SYSCALLS 256 // Size of array
#define PH_COUNT_PAGE_MAX (PAGE_SIZE / PH_NUM_SYSCALLS)
#define PH_MAX_PAGES (PH_NUM_SYSCALLS / PH_COUNT_PAGE_MAX)
#define PH_MAX_SEQLEN 9
#define PH_MAX_DISK_FILENAME 256
#define PH_LOCALITY_WIN 128
#define PH_FILE_MAGIC_LEN 20
#define PH_LOG_ACTION 3   /* actions pH takes (delays) */
#define PH_EMPTY_SYSCALL 255  /* note: this value is used as the */
                              /* "no system call" marker in sequences */

static int    majorNumber;                  // Store the device number - determined automatically
static char   message[256] = {0};           // Memory for the string that is passed from userspace
static short  size_of_message;              // Used to remember the size of the string stored
static int    numberOpens = 0;              // Counts the number of times the device is opened
static struct class*  ebbcharClass  = NULL; // The device-driver class struct pointer
static struct device* ebbcharDevice = NULL; // The device-driver device struct pointer
char*         test_string = "If this string is returned, that is awesome!!!";

static DEFINE_MUTEX(ebbchar_mutex);	    // Macro to declare a new mutex

typedef int pH_seqflags;

typedef struct pH_disk_profile_data {
        int sequences;  /* # sequences that have been inserted */
                        /*   NOT the number of lookahead pairs */
        unsigned long last_mod_count; /* # syscalls since last modification */
        unsigned long train_count;      /* # syscalls seen during training */
        int empty[PH_NUM_SYSCALLS];
        pH_seqflags entry[PH_NUM_SYSCALLS][PH_NUM_SYSCALLS];
} pH_disk_profile_data;

typedef struct pH_disk_profile {
        char magic[PH_FILE_MAGIC_LEN];  /* file magic: identifier, version */
        int normal;
        int frozen;
        time_t normal_time;
        int length;
        unsigned long count;
        int anomalies;
        pH_disk_profile_data train, test;
        char filename[PH_MAX_DISK_FILENAME];
} pH_disk_profile;
