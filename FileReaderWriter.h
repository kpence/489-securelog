#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string>
#include <fstream>
#include <sstream>
#include <vector>

using namespace std;

class FileReaderWriter {
  public:
    FileReaderWriter(const string fname,
                     const string _s_key)
      : filename(fname), s_key(_s_key), ctx(NULL)
    {}


		// -- Must call this before use of FileReaderWriter
		// (Returns Error Type)
		int init();

    // Reading/Parsing

    int get_next_record_string(string& result, int chunk_no); // this returns the next chunk number or 0 if integrity failure
    string get_record_string_at(int chunk_no); // (Empty if INTEGRITY VIOLATION) Reads the next record string in the file.
    string get_record_string_before(int chunk_no); // Finds first record before chunk_no.
    int get_num_chunks(); // (Empty if INTEGRITY VIOLATION) Reads the next record string in the file.

    // Writing

		/* ----Append Record-----
		 * This method will return one of the following error messages:
		 *
		 * INVALID_FILE_PATH -- You were given an invalid input
		 * INVALID_INPUT -- The record given to the method was improperly formed
		 * INTEGRITY_VIOLATION -- There was any form of integrity violation
		 *
		 */
    int append_record(string rcd); //records start with ^ and end with {@}$
  protected:
  private:
    // Writing
    /* Instructions
     *  Before we end a record, we insert @s until the end of a byte
     */
    int append_and_encrypt_chunk(string s);

    // Reading/Parsing
    string decrypt_chunk(int chunk_no);
    string get_record_string();
    int parse_record(int chunk_no, int reverse = 0); //records start with ^ and end with {@}$

    // I/O
    /*
     * 1. File directory must exist
     * 2. File directory or file must be able to be written to or else IO error and exit program
     */
    vector<string> file_chunks;
    int load_file(string fname);
    int read_chunk();

    // Verifying
    void check_corruption(string key); // TODO Check for corruption, for now assume
    int validate_record(string rcd); // TODO checks if record_string has correct token attached
    int verify_key(); // returns 0 if intergrity violation


    // Decryption functions (SSL)
    void base64Decode(char* b64message, unsigned char** buffer, size_t* length);
    void base64Encode(const unsigned char* buffer, size_t length, char** base64Text);
    size_t calcDecodeLength(char* b64input);
    string decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv);
    int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext);
    int initAES(const string& pass, unsigned char* salt, unsigned char* key, unsigned char* iv);
    void handleOpenSSLErrors(void);
    EVP_CIPHER_CTX *ctx;

    string s_cipher_base64;
    string filename;
    string s_key;
    ifstream ifs;
    ofstream wfs; // write to file
    int key_verify_status;

    // Parsing recrod members
    string record_string;
};
