#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

#include <signal.h> // For signals

#include "ebbcharmutex.h"
#include "linkedlist.h"

static char receive[BUFFER_LENGTH]; // The receive buffer for the LKM
volatile sig_atomic_t terminated = 0;
void* bin_receive;
int binary_files_created = 0;
char* to_write_back_to_module;
static char nul_string[BUFFER_LENGTH];

// Set terminated to 1 on SIGTERM signal
void term(int signm) {
	terminated = 1;
}

// Directly alters the disk_profiles parameter, which must be alloc'd and dealloc'd elsewhere
// Returns true on success and false on failure - failure MUST be handled
bool find_profile(pH_disk_profile* disk_profile, char* filename) {
	FILE* fp;
	char* input_file;
	int i;
	
	printf("In find_profile with filename [%s]\n", filename);
	
	if (!disk_profile || disk_profile == NULL) {
		printf("In find_profile with NULL disk_profile\n");
		return FALSE;
	}
	
	for (i = 0; i < binary_files_created; i++) {
		printf("In %dth iteration of for\n", (i+1));
		sprintf(input_file, "test%d.bin", i);
		fp = fopen(input_file, "r");
		if (!fp) {
			perror("Unable to open file in find_profile");
			return errno;
		}
		
		fread(disk_profile, sizeof(pH_disk_profile), 1, fp);
		
		if (strcmp(disk_profile->filename, filename) == 0) {
			fclose(fp);
			return TRUE;
		}
	}
	
	printf("Disk profile was not found\n");
	
	//fclose(fp);
	printf("Returning from find_profile...\n");
	return FALSE;
}

int write_profile(pH_disk_profile* disk_profile) {
	char* output_file;
	sprintf(output_file, "test%d.bin", binary_files_created);
	
	FILE* fp = fopen(output_file, "w");
	if (!fp) {
		perror("Unable to open file in write_profile");
		return errno;
	}
	
	fwrite(disk_profile, sizeof(pH_disk_profile), 1, fp);
	
	fclose(fp);
	binary_files_created++;
}

/*
int read_ascii_file(char* input_string, int fd) {
    FILE *fp;
    fp = fopen(input_string, "r");
    if (!fp) {
        perror("Failed to read the requested file");
        return errno;
    }
    char *file_contents;
    long input_file_size;
    fseek(fp, 0, SEEK_END);
    input_file_size = ftell(fp);
    rewind(fp);
    file_contents = (char*) malloc((input_file_size+1) * (sizeof(char)));
    fread(file_contents, sizeof(char), input_file_size, fp);
    fclose(fp); // I think this closes the file, not the device driver
    file_contents[input_file_size] = '\0';

    // Send the string back
    printf("Writing message to the device [%s]\n", file_contents);
    int ret = write(fd, file_contents, strlen(file_contents));
    if (ret < 0) {
        perror("Failed to write the message to the device");
        
        free(file_contents);
        
        return errno;
    }

	free(file_contents);

    return 0;
}
*/

int write_ascii_file(char* input_string, int fd) {
    FILE *fp;
    fp = fopen("binaries.txt", "a");
    if (!fp) {
        perror("Failed to write to the requested file");
        return errno;
    }
    
    // Output text to file
    fprintf(fp, "[%s]\n", input_string);
    fclose(fp);

    return 0;
}

/*
int get_data(int fd) {
	pH_disk_profile p;
	
	int ret = ioctl(fd, RETRIEVE_DATA, &p);
	printf("The ioctl returned %d\n", ret);
	if (ret != 0) {
		perror("Unable to get data");
		return -1;
	}
	
	if (&p == NULL) {
		perror("For some reason disk profile is null");
		return -1;
	}
	
	printf("Retrieved disk profile successfully\n");
	printf("Got normal of %d\n", p.normal);
}

int set_data(int fd) {
	// Not implemented - I might need to discard this function
}
*/

int read_profiles(int fd) {
	int ret;
	
	printf("In read_profiles\n");
	
	FILE* fp = fopen("test.bin", "w");
	if (!fp) {
		perror("Unable to open test.bin");
		return errno;
	}
	
	while (bin_receive != NULL) {
		printf("Performing binary read...\n");
		printf("sizeof(pH_disk_profile) = %ld\n", sizeof(pH_disk_profile));
		ret = read(fd, bin_receive, sizeof(pH_disk_profile));
		if (ret < 0) {
			perror("Failed to read the message from the device");
			close(fd);
			fclose(fp);
			return errno;
		}
		printf("Successfully performed binary read on device.\n");
		
		pH_disk_profile* disk_profile = bin_receive;
		printf("disk_profile->filename = [%s]\n", disk_profile->filename);
		
		fwrite(disk_profile, sizeof(pH_disk_profile), 1, fp);
		//free(disk_profile);
		//disk_profile = NULL;

		ret = read(fd, receive, BUFFER_LENGTH);
		if (ret < 0 || receive == NULL || strlen(receive) < 1) {
			printf("Failed to read the message from the device.%d%d%d\n", ret < 0, receive == NULL, strlen(receive) < 1);
			perror("Failed to read the message from the device");
			close(fd);
			return errno;
		}
		printf("The received message is: [%s]\n", receive);

		if (receive[0] == 's' && receive[1] == 't') return 0;
	}

	fclose(fp);
	
	return 0;
}

int write_profiles(int fd) {
	int ret;
	FILE* fp;
	
	printf("In write_profiles\n");
	
	while (bin_receive != NULL) {
		printf("Performing binary read...\n");
		ret = read(fd, bin_receive, sizeof(pH_disk_profile));
		if (ret < 0) {
			perror("Failed to read the message from the device: Releasing device");
			close(fd);
			fclose(fp);
			return errno;
		}
		printf("Successfully performed binary read on device.\n");
		
		pH_disk_profile* disk_profile = bin_receive;
		printf("disk_profile->filename = [%s]\n", disk_profile->filename);
		
		write_profile(disk_profile);
		
		ret = read(fd, receive, BUFFER_LENGTH);
		if (ret < 0 || receive == NULL || strlen(receive) < 1) {
			perror("Failed to read the message from the device: Releasing device");
			close(fd);
			return errno;
		}
		printf("The received message is: [%s]\n", receive);
		
		if (receive[0] == 's' && receive[1] == 't') return 0;
	}
	
	fclose(fp);
	
	return 0;
}

int main() {
	int ret, fd, i;
	pH_disk_profile* disk_profile;
	
	// Register signals
	signal(SIGINT, term);
	signal(SIGTERM, term);
	signal(SIGKILL, term);
	
	//freopen("test_ouput.txt", "w", stdout); // Changes stdout to ./test_output.txt

	printf("Starting device test code example...\n");
	
	for (i = 0; i < BUFFER_LENGTH; i++) {
		nul_string[i] = '\0';
	}
	
	// Open the device with read/write access
	fd = open("/dev/ebbchar", O_RDWR);
	if (fd < 0) {
	  perror("Failed to open the device");
	  return errno;
	}
	printf("Successfully opened device\n");

	// Allocate memory for bin_receive
	bin_receive = (pH_disk_profile*) malloc(sizeof(pH_disk_profile));
	if (!bin_receive) {
		printf("Unable to allocate memory for receive\n");
		return errno;
	}

	// Get this process's PID
	char pid_as_string[8];
	int this_pid = getpid();
	sprintf(pid_as_string, "%d", getpid());
	printf("The PID of this process is [%s]\n", pid_as_string);

	// Send this process's PID to the device
	printf("Writing PID to kernel module...\n");
	ret = write(fd, pid_as_string, strlen(pid_as_string));
	if (ret < 0) {
		perror("Failed to write this process's PID to the device");
		close(fd);
		return errno;
	}

	bool continueLoop = TRUE;

	while (!terminated && continueLoop) {
		to_write_back_to_module = "success";
		
		strcpy(receive, nul_string);
		for (i = 0; i < BUFFER_LENGTH; i++) {
			receive[i] = '\0';
		}
		
		// Retrieve information from the device
		printf("Reading from the device...\n");
		ret = read(fd, receive, BUFFER_LENGTH);
		if (ret < 0 || receive == NULL || strlen(receive) < 1) {
			printf("Failed to read the message from the device.%d%d%d\n", ret < 0, receive == NULL, strlen(receive) < 1);
			perror("Failed to read the message from the device");
			close(fd);
			return errno;
		}
		printf("The received message is: [%s]\n", receive);

		if (strcmp(receive, "quit") == 0) break;
		/*
		else if (receive[0] == 'r') { // r stands for read
			read_ascii_file(&receive[1], fd);
		}
		*/
		else if (receive[0] == 'r' && receive[1] == 'b') { // rb stands for read binary
			/*
			ret = read(fd, receive, PH_MAX_DISK_FILENAME);
			if (ret < 0) {
				perror("Failed to read the message from the device: Releasing device");
				close(fd);
				return errno;
			}
			printf("Successfully performed binary read on device.\n");
			*/
			
			/* // Commented out until dev_write is added back
			disk_profile = malloc(sizeof(pH_disk_profile));
			if (!disk_profile || disk_profile == NULL) {
				printf("Unable to allocate memory for disk_profile in main\n");
				return errno;
			}
			
			bool profile_found = find_profile(disk_profile, &receive[2]);
			printf("Back from find_profile()\n");
			
			if (!profile_found) {
				printf("Failed to find disk profile\n");
				free(disk_profile);
				disk_profile = NULL;
				to_write_back_to_module = "Failed to find disk profile";
			}
			else {
				printf("Found disk profile\n");
				printf("Writing disk profile to kernel module...\n");
				ret = write(fd, disk_profile, sizeof(disk_profile));
				
				free(disk_profile);
				disk_profile = NULL;
				
				if (ret < 0) {
					perror("Failed to write back to the device");
					close(fd);
					return errno;
				}
			}
			*/
		}
		else if (receive[0] == 'w') { // w stands for write
			write_ascii_file(&receive[1], fd);
		}
		else if (receive[0] == 'p') {
			//read_proc_file(&receive[1]);
		}
		/*
		else if (receive[0] == 'b') { // Add a new binary
			if (!find(&receive[1])) insertFirst(&receive[1], 1);
		}
		else if (receive[0] == 'f') { // Find a binary - returns 1 if binary found, 0 else
			char to_write;
			if (find(&receive[1])) to_write = 1; // Set to_write to 1 if binary is found in llist
			else to_write = 0;                   // Set to_write to 0 otherwise
			char* to_write_ptr = &to_write;
			ret = write(fd, to_write_ptr, sizeof(char));
			if (ret < 0) {
				perror("Failed to write back to the device");
				return errno;
			}
		}
		*/
		else if (receive[0] == 't') { // Perform binary read operation (t stands for transfer)
			/*
			printf("Performing binary read...\n");
			printf("sizeof(pH_disk_profile) = %ld\n", sizeof(pH_disk_profile));
			ret = read(fd, bin_receive, sizeof(pH_disk_profile));
			if (ret < 0 || bin_receive == NULL) {
				printf("Failed to read the message from the device.%d%d\n", ret < 0, bin_receive == NULL);
				perror("Failed to read the message from the device");
				close(fd);
				return errno;
			}
			printf("Successfully performed binary read on device.\n");
			
			pH_disk_profile* disk_profile = bin_receive;
			printf("disk_profile->normal = %d\n", disk_profile->normal);
			*/
			
			if (read_profiles(fd) != 0) break;
			
			//break; // Quit execution after one read for testing purposes
			continue; // Perform next read
		}
		else {
			printf("Received message [%s] was not formatted correctly.\n", receive);
		}			
		
		/*
		ret = get_data(fd);
		if (ret < 0) {
			printf("Failed to read from device");
			return errno;
		}
		*/
		
		// Write back to the device
		printf("Writing to kernel module...\n");
		ret = write(fd, to_write_back_to_module, strlen(to_write_back_to_module));
		if (ret < 0) {
			perror("Failed to write back to the device");
			close(fd);
			return errno;
		}
	}
	
	free(bin_receive);

	printf("No segfault before close\n");
	close(fd);
	printf("No segfault after close\n");

	printf("End of the program\n");
	return 0;
}
