#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#define MAX_LINES 64

// PMP configuration arrays
uint8_t config_array[MAX_LINES];   // Stores PMP configurations
uint32_t address_array[MAX_LINES]; // Stores PMP address regions

// Function to read the PMP configuration file
void read_config_file(const char *filename, uint8_t *config_array, uint32_t *address_array) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        printf("Error: Could not open configuration file.\n");
        exit(1);
    }

    char line[256];

    // Read the first 64 lines into config_array
    for (int i = 0; i < MAX_LINES; i++) {
        if (fgets(line, sizeof(line), file) == NULL) {
            printf("Error: Unexpected EOF while reading config at line %d.\n", i + 1);
            exit(1);
        }
        unsigned int value;
        sscanf(line, "%x", &value);
        config_array[i] = (uint8_t)value;
    }

    // Read the next 64 lines into address_array
    for (int i = 0; i < MAX_LINES; i++) {
        if (fgets(line, sizeof(line), file) == NULL) {
            printf("Error: Unexpected EOF while reading addresses at line %d.\n", i + 1);
            exit(1);
        }
        unsigned int value;
        sscanf(line, "%x", &value);
        address_array[i] = value;
    }

    fclose(file);
}

// Function to compute NAPOT range
void compute_napot_range(uint32_t addr, uint32_t *base, uint32_t *limit) {
    // If no trailing ones, it is a single address range (NA4)
    if ((addr & 1) == 0) {
        *base = addr;
        *limit = addr + 4;  // NA4 region
        return;
    }

    // Count trailing ones for NAPOT
    int count = 0;
    uint32_t temp = addr;
    while (temp & 1) {
        count++;
        temp >>= 1;
    }

    uint32_t size = 1 << (count + 2);
    *base = addr & ~(size - 1);
    *limit = *base + size;
}

// Function to check PMP access
void pmp_check(uint8_t *config_array, uint32_t *address_array, uint32_t addr, char operation) {
    for (int j = 0; j < MAX_LINES; j++) {
        uint32_t region_addr = address_array[j];
        uint8_t config = config_array[j];

        uint8_t R = config & 1;
        uint8_t W = (config >> 1) & 1;
        uint8_t X = (config >> 2) & 1;
        uint8_t A = (config >> 3) & 3;  // Extract A field (bits 3-4)

        printf("Region %d: A-Field = %d, Config = 0x%X, Address = 0x%X\n", j, A, config, region_addr);

        // Check the type of region
        if (A == 0) {
            printf("Region %d: PMP Disabled\n", j);
            continue;
        }

        uint32_t base = 0, limit = 0;

        if (A == 3) {  // NAPOT
            compute_napot_range(region_addr, &base, &limit);
            printf("Region %d: NAPOT Mode, Base = 0x%X, Limit = 0x%X\n", j, base, limit);
        } else if (A == 1) {  // TOR
            if (j == 0) {
                base = 0;  // First TOR region starts at 0
            } else {
                base = address_array[j - 1];
            }
            limit = region_addr;
            printf("Region %d: TOR Mode, Base = 0x%X, Limit = 0x%X\n", j, base, limit);
        } else if (A == 2) {  // NA4
            base = region_addr;
            limit = region_addr + 4;
            printf("Region %d: NA4 Mode, Base = 0x%X, Limit = 0x%X\n", j, base, limit);
        }

        // Check if the address falls within the region
        if (base <= addr && addr < limit) {
            if ((operation == 'R' && R) || (operation == 'W' && W) || (operation == 'X' && X)) {
                printf("Access Granted: Address 0x%X in region %d\n", addr, j);
                return;
            } else {
                printf("Access Fault: Address 0x%X in region %d\n", addr, j);
                return;
            }
        }
    }

    // Default case: No matching region found
    printf("Access Fault: Address 0x%X (No PMP region found)\n", addr);
}

// Main function to take user input and run PMP check
int main(int argc, char *argv[]) {
    if (argc != 4) {
        printf("Usage: %s <config_file> <address> <operation>\n", argv[0]);
        printf("Example: %s configurations.txt 0x80001000 R\n", argv[0]);
        return 1;
    }

    const char *config_file = argv[1];
    uint32_t addr = strtoul(argv[2], NULL, 16);
    char operation = argv[3][0];

    // Read PMP configuration
    read_config_file(config_file, config_array, address_array);

    // Perform PMP check
    pmp_check(config_array, address_array, addr, operation);

    return 0;
}