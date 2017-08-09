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

// Set terminated to 1 on SIGTERM signal
void term(int signm) {
	terminated = 1;
}

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

int main(){
	int ret, fd;
	
	//freopen("test_ouput.txt", "w", stdout); // Changes stdout to ./test_output.txt

	printf("Starting device test code example...\n");
	
	// Open the device with read/write access
	fd = open("/dev/ebbchar", O_RDWR);
	if (fd < 0){
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
		return errno;
	}

	bool continueLoop = TRUE;

	while (!terminated && continueLoop) {
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
		else if (receive[0] == 'r') { // r stands for read
			read_ascii_file(&receive[1], fd);
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
		char* to_write = "success";
		ret = write(fd, to_write, strlen(to_write));
		if (ret < 0) {
			perror("Failed to write back to the device");
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
