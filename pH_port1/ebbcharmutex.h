// My definitions
#define TRUE         (1 == 1)
#define FALSE        (!TRUE)

#define  DEVICE_NAME "ebbchar" // The device will appear at /dev/ebbchar using this value
#define  CLASS_NAME  "ebb"     // The device class

// Anil's definitions
#define PH_NUM_SYSCALLS 256 // Size of array
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

// My definitions
#define PATH_MAX 4096
#define BUFFER_LENGTH 256 // The buffer length

static int    majorNumber;                  // Store the device number - determined automatically
static char   message[256] = {0};           // Memory for the string that is passed from userspace
static struct class*  ebbcharClass  = NULL; // The device-driver class struct pointer
static struct device* ebbcharDevice = NULL; // The device-driver device struct pointer
char*         test_string = "If this string is returned, that is awesome!!!";

static DEFINE_MUTEX(ebbchar_mutex);	    // Macro to declare a new mutex

typedef int pH_seqflags;
