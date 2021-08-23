// Hardware Imports
#include "inc/hw_memmap.h" // Peripheral Base Addresses
#include "inc/lm3s6965.h" // Peripheral Bit Masks and Registers
#include "inc/hw_types.h" // Boolean type
#include "inc/hw_ints.h" // Interrupt numbers

// Driver API Imports
#include "driverlib/flash.h" // FLASH API
#include "driverlib/sysctl.h" // System control API (clock/reset)
#include "driverlib/interrupt.h" // Interrupt API
#include "beaverssl.h"

// Application Imports
#include "uart.h"

// Forward Declarations
void load_initial_firmware(void);
void load_firmware(void);
void boot_firmware(void);
long program_flash(uint32_t, unsigned char*, unsigned int);
uint32_t random(uint8_t state);
void rollIV();
void readFrame();
int sha_hmac384(char* key, int key_len, char* data, int len, char* out);

// Firmware Constants
#define METADATA_BASE 0xFC00  // base address of version and firmware size in Flash
#define FW_BASE 0x10000  // base address of firmware in Flash
#define MAX_FIRMWARE_SIZE 30720 // 30 Kibibytes
#define MAX_FIRMWAREBLOB_SIZE 31792 // 30 Kibibyte FW + 1 KB Release Message + 48 byte HMAC Signature

// FLASH Constants
#define FLASH_PAGESIZE 1024
#define FLASH_WRITESIZE 4

// Protocol Constants
#define OK    ((unsigned char)0x00)
#define ERROR ((unsigned char)0x01)
#define UPDATE ((unsigned char)'U')
#define BOOT ((unsigned char)'B')

// Frame Constants
#define SETUP   0
#define DATA    1
#define AUTH    2
#define VERSION 3
#define DATA_DELIM_SIZE 62

// Encryption Constants
#define HMAC_KEY_LENGTH 48
#define HMAC_SIG_LENGTH 48
#define AES_KEY_LENGTH 16
#define AES_IV_LENGTH 16
#define AES_GCM_TAG_LENGTH 16
#define AES_GCM_AAD_LENGTH 16

// Firmware v2 is embedded in bootloader
extern int _binary_firmware_bin_start;
extern int _binary_firmware_bin_size;

// Device metadata
uint16_t *fw_version_address = (uint16_t *) METADATA_BASE;
uint16_t *fw_size_address = (uint16_t *) (METADATA_BASE + 2);
uint8_t *fw_release_message_address;

// Firmware Buffer
unsigned char data[FLASH_PAGESIZE];

// Encryption
char HMAC_KEY[HMAC_KEY_LENGTH] = HMAC;
char AES_KEY [AES_KEY_LENGTH]  = KEY;
char IV      [AES_IV_LENGTH]   = INIT_IV;
char AES_AAD [AES_GCM_AAD_LENGTH] = AAD;

uint32_t random(uint8_t state) {
    uint32_t z = state + 0x6D2B79F5;
    z = (z ^ z >> 15) * (1 | z);
    z ^= z + (z ^ z >> 7) * (61 | z);
    return z ^ z >> 14;
}

// Generates IV after accessing the authentication tag
void rollIV() {
    for (uint8_t i = 0; i < AES_IV_LENGTH; i++) {
        IV[i] = random(IV[i]) % 256;
    }
}

int main(void) {

    // Initialize UART channels
    // 0: Reset
    // 1: Host Connection
    // 2: Debug
    uart_init(UART0);
    uart_init(UART1);
    uart_init(UART2);
    
    // Enable UART0 interrupt
    IntEnable(INT_UART0);
    IntMasterEnable();
    
    load_initial_firmware();
    
    uart_write_str(UART2, "Welcome to the BWSI Vehicle Update Service!\n");
    uart_write_str(UART2, "Send \"U\" to update, and \"B\" to run the firmware.\n");
    uart_write_str(UART2, "Writing 0x20 to UART0 will reset the device.\n");

    fw_release_message_address = (uint8_t *) (FW_BASE + *fw_size_address);
    
    int resp;
    while (1) {
        uint32_t instruction = uart_read(UART1, BLOCKING, &resp);
        if (instruction == UPDATE) {
            uart_write_str(UART1, "U");
            load_firmware();
        } else if (instruction == BOOT){
            uart_write_str(UART1, "B");
            boot_firmware();
        }
    }
}

/*
 * Load initial firmware into flash
 */
void load_initial_firmware(void) {


  if (*((uint32_t*)(METADATA_BASE)) != 0xFFFFFFFF){
    /*
     * Default Flash startup state in QEMU is all zeros since it is
     * secretly a RAM region for emulation purposes. Only load initial
     * firmware when metadata page is all zeros. Do this by checking
     * 4 bytes at the half-way point, since the metadata page is filled
     * with 0xFF after an erase in this function (program_flash()).
     */
    return;
  }

  // Create buffers for saving the release message
  uint8_t temp_buf[FLASH_PAGESIZE];
  char initial_msg[] = "This is the initial release message.";
  uint16_t msg_len = strlen(initial_msg)+1;
  uint16_t rem_msg_bytes;
  
  // Get included initial firmware
  int size = (int)&_binary_firmware_bin_size;
  uint8_t *initial_data = (uint8_t *)&_binary_firmware_bin_start;
  
  // Set version 2 and install
  uint16_t version = 2;
  uint32_t metadata = (((uint16_t) size & 0xFFFF) << 16) | (version & 0xFFFF);
  program_flash(METADATA_BASE, (uint8_t*)(&metadata), 4);
  
  int i;
  
  for (i = 0; i < size / FLASH_PAGESIZE; i++){
       program_flash(FW_BASE + (i * FLASH_PAGESIZE), initial_data + (i * FLASH_PAGESIZE), FLASH_PAGESIZE);
  }
  
  /* At end of firmware. Since the last page may be incomplete, we copy the initial
   * release message into the unused space in the last page. If the firmware fully
   * uses the last page, the release message simply is written to a new page.
   */
  
  uint16_t rem_fw_bytes = size % FLASH_PAGESIZE;
  if (rem_fw_bytes == 0){
    // No firmware left. Just write the release message
    program_flash(FW_BASE + (i*FLASH_PAGESIZE), (uint8_t *)initial_msg, msg_len);
  } else {
    // Some firmware left. Determine how many bytes of release message can fit
    if (msg_len > (FLASH_PAGESIZE-rem_fw_bytes)) {
      rem_msg_bytes = msg_len - (FLASH_PAGESIZE-rem_fw_bytes);
    } else {
      rem_msg_bytes = 0;
    }
    
    // Copy rest of firmware
    memcpy(temp_buf, initial_data + (i*FLASH_PAGESIZE), rem_fw_bytes);
    // Copy what will fit of the release message
    memcpy(temp_buf+rem_fw_bytes, initial_msg, msg_len-rem_msg_bytes);
    // Program the final firmware and first part of the release message
    program_flash(FW_BASE + (i * FLASH_PAGESIZE), temp_buf, rem_fw_bytes+(msg_len-rem_msg_bytes));
    
    // If there are more bytes, program them directly from the release message string
    if (rem_msg_bytes > 0) {
      // Writing to a new page. Increment pointer
      i++;
      program_flash(FW_BASE + (i * FLASH_PAGESIZE), (uint8_t *)(initial_msg+(msg_len-rem_msg_bytes)), rem_msg_bytes);
    }
  }
  
  // Compute release message start address
  fw_release_message_address = (uint8_t*)(FW_BASE+size);
  
}

// This struct specifies the structure of the data frame
typedef struct {
    uint8_t mode: 2;
    uint8_t size: 6;
    uint8_t data[DATA_DELIM_SIZE];
    uint8_t null;
} maFrame;

// This is where the incoming frames will be stores
maFrame frame = {};

// This function is responsible for reading the incoming frame and storing it in the variable frame
void readFrame() {
    int read;
    uint8_t fByte = uart_read(UART1, BLOCKING, &read);
    frame.mode = fByte >> 6;
    frame.size = fByte & (~ 0xC0);
    uart_write_str(UART2, "Frame metadata: ");
    uart_write_hex(UART2, fByte);
    nl(UART2);
    for (unsigned int i = 0; i < DATA_DELIM_SIZE; i++) {
        frame.data[i] = uart_read(UART1, BLOCKING, &read);
    }
    
    frame.null = uart_read(UART1, BLOCKING, &read);
    uart_write(UART1, OK);
}

unsigned char firmwareBlob[MAX_FIRMWAREBLOB_SIZE] = {}; // This array stores the unencrypted firmware blob received from the update tool
unsigned char authTag[AES_GCM_TAG_LENGTH];       // This array stores in our AES GCM auth tag given by the AUTH frame

/** Load the firmware into flash.
 */
void load_firmware(void)
{ 
    uint32_t page_addr = FW_BASE;
    uint32_t version = 0;
    uint32_t size = 0;
    
    readFrame();
    if (frame.mode != VERSION) { // The first frame that is expected is the version frame
        uart_write_str(UART2, "ERROR: First received frame was not a version-mode frame, frame mode recieved was of number: ");
        uart_write_hex(UART2, frame.mode);
        nl(UART2);
        goto RESTART;
    }
    uint16_t old_version = *fw_version_address; // get old version from memory
    
    // The only relevant part of the version frame is the first two bytes of the data delimeter, this will hold the expected version of the firmware
    uint16_t plaintext_version = frame.data[1] << 8 | frame.data[0]; 
    
    if (plaintext_version < old_version && plaintext_version != 0) { // check plaintext version compared to installed version
        uart_write_str(UART2, "ERROR: The version proported in the version frame is older than the current version and not 0, it was: ");
        uart_write_hex(UART2, plaintext_version);
        uart_write_str(UART2, ", while the current version is: ");
        uart_write_hex(UART2, old_version);
        nl(UART2);
        goto RESTART;
    }
    
    // update AAD according to plaintext version
    AES_AAD[0] ^= frame.data[0];
    AES_AAD[1] ^= frame.data[1];

    readFrame();
    if (frame.mode != SETUP) {// The next frame that is expected is the SETUP frame
        uart_write_str(UART2, "ERROR: Second Frame was not of type SETUP, was of type: ");
        uart_write_hex(UART2, frame.mode);
        nl(UART2);
        goto RESTART;
    }
  
    uint16_t firmwareBlobIndex = 0; // for keeping track where to write in firmwareBlob
    
    // The only relevant part of the status frame is the first two bytes of the data delimeter, and this holds the expected amount of bytes for the firmware blob
    uint16_t firmwareBlobSize = (frame.data[1] << 8) | frame.data[0];
    
    if (firmwareBlobSize > MAX_FIRMWAREBLOB_SIZE) { // Make sure that the the expected firmware blob size is smaller than the maximum firmware blob size
        uart_write_str(UART2, "ERROR: Size in setup frame was too big, was size: ");
        uart_write_hex(UART2, firmwareBlobSize);
        nl(UART2);
        goto RESTART;
    }
    
    uint16_t iterations; // Find the number of expected data frames, assuming each is full except for the last one (62 bytes)
    
    if ((firmwareBlobSize % 62) == 0) iterations = firmwareBlobSize / 62; // All the data frames that will be received will be 62 bytes
    else                              iterations = (((uint16_t) firmwareBlobSize/62)+1); // The data frame at the end will be smaller than 62 bytes
    
    for (uint16_t i = 0; i < iterations; i++) { // Get data from data frames
        readFrame();
        if (frame.mode != DATA || frame.size > DATA_DELIM_SIZE) { // check frame is of mode DATA and size is not over 62 bytes (the size of the data portion of a frame)
            uart_write_str(UART2, "ERROR: Non-data-mode frame received when data-mode frame was expected, or data frame size too big.");
            nl(UART2);
            goto RESTART;
        }
        
        for (uint8_t j = 0; j < frame.size; j++) { // write data from data portion from DATA frame to firmwareBlob buffer
            if (firmwareBlobIndex >= firmwareBlobSize) { // make sure that we are not trying to write out of the bounds of the firmwareBlob buffer
                uart_write_str(UART2, "ERROR: More data contained in total in data frames than was expected given size from setup frame.");
                nl(UART2);
                goto RESTART;
            }
            firmwareBlob[firmwareBlobIndex] = frame.data[j];
            firmwareBlobIndex++;
        }
    }
    
    readFrame();
    if (frame.mode != AUTH) { // The last frame that is expected is the AUTH frame
        uart_write_str(UART2, "ERROR: Last frame was not of type AUTH, was of type: ");
        uart_write_hex(UART2, frame.mode);
        nl(UART2);
        goto RESTART;
    }
    
    for (uint8_t i = 0; i < AES_GCM_TAG_LENGTH; i++) { // write data from AUTH-mode frame to authTag buffer
        authTag[i] = frame.data[i];
    }
    
    for(int i = 0; i < plaintext_version; i++) { // roll IV according to plaintext version
        rollIV();
    }
    
    // decrypt data and verify authTag
    if (gcm_decrypt_and_verify(AES_KEY, IV, firmwareBlob, firmwareBlobSize, AES_AAD, AES_GCM_AAD_LENGTH, authTag) != 1) { 
        uart_write_str(UART2, "ERROR: Invalid Authentication Tag.");
        nl(UART2);
        goto RESTART;
    }

    int start = 0; // for keeping track of position in firmwareBlob (first is HMAC signature, second is metadata, third is firmware and message)
    
    // generate hmac signature for everything that is not the hmac signature itself and store that in generated_hmac_sig
    char generated_hmac_sig[HMAC_SIG_LENGTH];
    sha_hmac384(HMAC_KEY, HMAC_KEY_LENGTH, firmwareBlob + HMAC_KEY_LENGTH, firmwareBlobSize - HMAC_KEY_LENGTH, generated_hmac_sig); 
    
    //check if all the bytes in both of the signatures line up
    unsigned char passed = 1;
    for(int i = 0; i < HMAC_SIG_LENGTH; i++) {
        if (firmwareBlob[i] != generated_hmac_sig[i]) {
            passed = 0;
        }
    }
    if (passed != 1) {
        uart_write_str(UART2, "ERROR: Invalid HMAC Signature.");
        nl(UART2);
        goto RESTART;
    }
    
    //hmac signature is no longer needed, move start and reduce size to metadata and firmwareblob
    start += HMAC_SIG_LENGTH;
    firmwareBlobSize -= HMAC_SIG_LENGTH;
       
    // variables for reading in metadata (little endian)
    uint8_t lsb;
    uint8_t msb;
      
    // Get version. 
    lsb = firmwareBlob[start+0];
    msb = firmwareBlob[start+1];
    version = (msb << 8) | lsb;

    uart_write_str(UART2, "Received Firmware Version: ");
    uart_write_hex(UART2, version);
    nl(UART2);

    if(version != plaintext_version) {
        uart_write_str(UART2, "ERROR: Version received in version frame is not the same as authenticated version of firmware. Version in version frame was: ");
        uart_write_hex(UART2, plaintext_version);
        uart_write_str(UART2, ", while authenticated version was: ");
        uart_write_hex(UART2, version);
        nl(UART2);
    }
    
    // Get size.
    lsb = firmwareBlob[start+2];
    msb = firmwareBlob[start+3];
    size = (msb << 8) | lsb;
    
    if (size > MAX_FIRMWARE_SIZE) { //if firmware size is larger than max accommodated size, restart
        uart_write_str(UART2, "ERROR: Size of actual firmware too big, was size: ");
        uart_write_hex(UART2, size);
        nl(UART2);
        goto RESTART;
    }
    
    // now that metadata is stored, move start and decrease firmware size
    start += 4;
    firmwareBlobSize -= 4;

    // Compare to old version and abort if older (note special case for version 0).
    if (version != 0 && version < old_version) {
        uart_write_str(UART2, "ERROR: Incoming version was less than current version, was: ");
        uart_write_hex(UART2, version);
        uart_write_str(UART2, ", while the current version is: ");
        uart_write_hex(UART2, old_version);
        nl(UART2);
        goto RESTART; // Reset device
    } else if (version == 0) {
        // If debug firmware, don't change version
        version = old_version;
    } 

    // Write new firmware size and version to Flash
    // Create 32 bit word for flash programming, version is at lower address, size is at higher address
    uint32_t metadata = ((size & 0xFFFF) << 16) | (version & 0xFFFF);
    program_flash(METADATA_BASE, (uint8_t*)(&metadata), 4);
    fw_release_message_address = (uint8_t *) (FW_BASE + size);

    while(firmwareBlobSize > 0) {
        // if firmwareblob is greater in size than flash_pagesize, use flash_pagesize, otherwise write remaining
        int size_to_write;
        if (firmwareBlobSize >= FLASH_PAGESIZE) {
            size_to_write = FLASH_PAGESIZE;
        } else {
            size_to_write = firmwareBlobSize;
        }
        
        if (program_flash(page_addr, (unsigned char*) &firmwareBlob + start, size_to_write)){ // try and program flash and if that does not work, restart
            uart_write_str(UART2, "ERROR writing flash to memory.");
            uart_write_hex(UART2, firmwareBlobSize);
            nl(UART2);
            goto RESTART;
        }
        
        page_addr += size_to_write; //move pointer to write
        start += size_to_write; // move pointer in firmware
        firmwareBlobSize -= size_to_write; // reduce size
    }
    
    uart_write_str(UART2, "You made it, firmware updated!");
    nl(UART2); 
    goto RESTART;
    return; 
    
    // goto to this part if there is an error and you wish to restart
    RESTART:
        uart_write(UART1, ERROR);
        SysCtlReset();
        return;
}


/*
 * Program a stream of bytes to the flash.
 * This function takes the starting address of a 1KB page, a pointer to the
 * data to write, and the number of byets to write.
 *
 * This functions performs an erase of the specified flash page before writing
 * the data.
 */
long program_flash(uint32_t page_addr, unsigned char *data, unsigned int data_len)
{
  uint32_t word = 0;
  int ret;
  int i;

  // Erase next FLASH page
  FlashErase(page_addr);

  // Clear potentially unused bytes in last word
  // If data not a multiple of 4 (word size), program up to the last word
  // Then create temporary variable to create a full last word
  if (data_len % FLASH_WRITESIZE){
    // Get number of unused bytes
    int rem = data_len % FLASH_WRITESIZE;
    int num_full_bytes = data_len - rem;
    
    // Program up to the last word
    ret = FlashProgram((unsigned long *)data, page_addr, num_full_bytes);
    if (ret != 0) {
      return ret;
    }
    
    // Create last word variable -- fill unused with 0xFF
    for (i = 0; i < rem; i++) {
      word = (word >> 8) | (data[num_full_bytes+i] << 24); // Essentially a shift register from MSB->LSB
    }
    for (i = i; i < 4; i++){
      word = (word >> 8) | 0xFF000000;
    }
    
    // Program word
    return FlashProgram(&word, page_addr+num_full_bytes, 4);
  } else{
    // Write full buffer of 4-byte words
    return FlashProgram((unsigned long *)data, page_addr, data_len);
  }
}

void boot_firmware(void)
{
    uart_write_str(UART2, (char *) fw_release_message_address);

    // Boot the firmware
    __asm(
    "LDR R0,=0x10001\n\t"
    "BX R0\n\t"
    );
}

int sha_hmac384(char* key, int key_len, char* data, int len, char* out) {
    br_hmac_key_context kc;
    br_hmac_context ctx;
    br_hmac_key_init(&kc, &br_sha384_vtable, key, key_len);
    br_hmac_init(&ctx, &kc, 0);
    br_hmac_update(&ctx, data, len);
    br_hmac_out(&ctx, out);

    return 24;
}