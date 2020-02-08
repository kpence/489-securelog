#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string.h>
#include <cstdlib>
#include <unistd.h>
#include <iostream>
#include <string>
#include <fstream>

#include <thread>
#include <chrono>

#include <iterator>
#include <sstream>
#include <iomanip>

#include <random>
#include <functional>
#include <algorithm>

#include "FileReaderWriter.h"

using namespace std;
using ErrorType::UNKNOWN_ERROR;
using ErrorType::INVALID_INPUT;
using ErrorType::INTEGRITY_VIOLATION;
using ErrorType::INVALID_FILE_PATH;
using ErrorType::SUCCESS_NEW_FILE;
using ErrorType::SUCCESS_FILE_EXISTS;
using ErrorType::SUCCESS;

#define KEY_LENGTH 32
#define IV_LENGTH 32
#define RECORD_MAX_SIZE 16*3 - 2
#define DECRYPTED_CHUNK_SIZE 16
#define DECODED_CHUNK_SIZE 32
#define CHUNK_SIZE 64
#define VERIFICATION_CHUNK_STR "!12345abcPzJkqV!"

int handleError(ErrorType errno) {
  switch (errno) {
    case INVALID_INPUT:
      cerr<<"Invalid Input\n";break;
    case INTEGRITY_VIOLATION:
      cerr<<"Integrity violation\n";break;
    case UNKNOWN_ERROR:
      cerr<<"Unknown Error\n";break;
    default: // warning, accepts SUCCESS*
      cerr << "Unknown Error\n";
  }
}

// TODO remove
void p_hex(unsigned char* s, size_t sz) {
  for (int i = 0; i < sz; i++) {
    printf("%x", (char)s[i]);
  }
}


int FileReaderWriter::init() {
  int f = load_file(filename);
  if (f == SUCCESS_FILE_EXISTS) {
    key_verify_status = verify_key();
    if (key_verify_status == 0)
      return INTEGRITY_VIOLATION;
  }
  return SUCCESS;
}


// Writing


/* Instructions
 *  Before we end a record, we insert @s until the end of a byte

 * IMPORTANT This is a public method so we will return whether there was an integrity violation or other kind of error here in the return value.
 */
int FileReaderWriter::append_record(string rcd)
{
  if (rcd.find_first_not_of("01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-") != string::npos) {
    cerr << "FAIL: Append record: Improper record string \n";
    return INVALID_INPUT;
  }

  if (rcd.length() >= RECORD_MAX_SIZE) {
    cerr << "FAIL: Append record: Record too large\n";
    return INVALID_INPUT;
  }
  // TODO (uncomment when done testing ) First verify the record
  record_string = "^"+rcd;
  //if (1 != validate_record())
    //return ret;


  // Append the record with the appropriate number of @ padding signs
  // Example, say decyphered chunk length is 4
  //^123456$
  //^12345@$
  //^1234567@@@$
  //
  // V probably a better way to do this.... but w/e
  int modulo = (rcd.length()+2) % DECRYPTED_CHUNK_SIZE;
  int padAts = (DECRYPTED_CHUNK_SIZE - modulo) % DECRYPTED_CHUNK_SIZE;

  // Get number of chunks to append
  int num = (rcd.length()+2) / DECRYPTED_CHUNK_SIZE;
  if (modulo != 0) ++num;

  record_string += string(padAts,'@') + "$";

  // Make the command has acceptable form and has the token at the start of it.
  // Note: This doesn't check if it has correct parsable form, delegating that to logappend and logread.
  if (validate_record(record_string) == 0) {
    cerr << "FAILURE: Failed to validate record: " << record_string << "\n";
    return INVALID_INPUT;
  }

  // For each of these (if last one, then add the @ padding), encrypt it, and append it to the file,
  int i, status;
  string send = "^";
  if (num == 1) {
    send += rcd;
    if (padAts > 0)
      send += string(padAts,'@');
    send += "$";
    status = append_and_encrypt_chunk(send);
    if (status != SUCCESS) return status;
  }
  else {
    send += rcd.substr(0,DECRYPTED_CHUNK_SIZE-1);
    rcd.erase(0,DECRYPTED_CHUNK_SIZE-1);

    status = append_and_encrypt_chunk(send); // TODO check the status for each of these append chunks, or just throw an exception
    if (status != SUCCESS) return status;

    for (i = 1; i < num; i++) {
      if (i == num-1) {
        send = rcd;
        rcd.erase(0,DECRYPTED_CHUNK_SIZE-1-padAts);
        if (padAts > 0)
          send += string(padAts,'@');
        send += "$";
      }
      else {
        send = rcd.substr(0,DECRYPTED_CHUNK_SIZE);
        rcd.erase(0,DECRYPTED_CHUNK_SIZE);
      }
      status = append_and_encrypt_chunk(send); // TODO check the status for each of these append chunks, or just throw an exception
      if (status != SUCCESS) return status;
    }
  }

  return SUCCESS;
}

/* STEPS:
 * 1. Create the key-stretched key using the authentication token and a randomly generated SALT (Use random SALT and this.initAES method)
 * 2. Perform the AES encryption using the generated key
 * 3. Prepend the encrypted chunk with the SALT
 * 4. Encode in base64
 * 5. Append to file
 */
int FileReaderWriter::append_and_encrypt_chunk(string chunk) {
  // Append to end of the file
  //cout << "Appending chunk: " << chunk << endl;

  size_t cipher_len;

  char* ciphertext_base64;
  unsigned char ciphertext[128];
  unsigned char *prepend_ciphertext;
  unsigned char salt[8];
  ERR_load_crypto_strings();

  unsigned char key[KEY_LENGTH];
  unsigned char iv[IV_LENGTH];

  // Step one (Part A) Generate random size 8 unsigned char* SALT
  memset(salt,'\0',8);
  random_device r;
  seed_seq seed{r(), r(), r(), r(), r(), r(), r(), r()};
  auto rand = bind(uniform_int_distribution<>(0, UCHAR_MAX),
                   mt19937(seed));
  int i;
  for (i = 0; i < 8; i++)
    salt[i]=rand();

  // Step one (Part B) Create the key-stretched key
  int key_size = initAES(s_key.c_str(), salt, key, iv);

  if (key_size != KEY_LENGTH) {
    // ~~~~~~~~~~~ERROR Key stretching failed somehow!~~~~~~~~~~~";

    // INTEGRITY VIOLATION
    ERR_free_strings();
    return INTEGRITY_VIOLATION;
  }

  // Step two Perform the AES encryption
  cipher_len = encrypt((unsigned char*)chunk.c_str(), DECRYPTED_CHUNK_SIZE, key, iv, ciphertext);

  if (cipher_len != DECODED_CHUNK_SIZE) {
    // ~~~~~~~~~~~ERROR Key stretching failed somehow!~~~~~~~~~~~";

    // INTEGRITY VIOLATION
    ERR_free_strings();
    return INTEGRITY_VIOLATION;
  }

  // Step three Prepend the cypher with the SALT
  prepend_ciphertext = (unsigned char*)malloc(cipher_len+16);
  memcpy(prepend_ciphertext,"Salted__",8);
  memcpy(prepend_ciphertext+8,salt,8);
  memcpy(prepend_ciphertext+16,ciphertext,cipher_len);

  //cout <<"prepend_ciphertext ";p_hex(prepend_ciphertext,cipher_len+16);cout<<endl;
  cipher_len += 16;

  // Step four Encode in Base64
  base64Encode(prepend_ciphertext, cipher_len, &ciphertext_base64);

  //free(cipher_alloced_mem);

  // Clean up
  ERR_free_strings();

  // Step five append file with it
  // TODO do we expect the file to exist at this point?
  ofstream _wfs;
  _wfs.open(filename, ios_base::app);
  if (_wfs.is_open())
    _wfs << string((char*)ciphertext_base64, CHUNK_SIZE);
  else {
    cerr << "FAILURE: Writing to invalid file\n";
    return INVALID_FILE_PATH;
  }
  //cout << "CHUNK MADE: " << string((char*)ciphertext_base64, CHUNK_SIZE) << endl;
  return SUCCESS;
}

// Returns 0 if integrity violation
int FileReaderWriter::parse_record() {
  // Read new chunks until you reach a $
  string s = decrypt_next_chunk();
  if (s.empty()) {
    record_string = "";
    return 0;
  }
  record_string.clear();
  //cout << "decrypting: " << s << endl;


  // Read new chunks until record finishes
  while (s[DECRYPTED_CHUNK_SIZE-1] != '$') {
    record_string += s;
    s = decrypt_next_chunk();
    if (s.empty()) {
      record_string = "";
      return 0;
    }
  }
  record_string += s;
  //cout << "decrypting, fin: " << record_string << endl;

  int ret = validate_record(record_string);
  return ret;
}

string FileReaderWriter::get_next_record_string() {
  string s;
  if (parse_record() != 0)
    s = get_record_string();
  return s; // Empty if integrity violation
}

string FileReaderWriter::get_record_string() {
  int i;
  int keylen = s_key.length();
  if ((i = record_string.find_first_of('@')) != string::npos)
    return record_string.substr(1+keylen,i-1-keylen);
  else {
    return record_string.substr(1+keylen,record_string.length()-2-keylen);
  }
}

// TODO Make sure that also there are NO special characters, this all is exploitable
int FileReaderWriter::validate_record(string rcd) {
  if (rcd.empty())
    return 0;
  if (rcd[0] != '^' || rcd.back() != '$')
    return 0;

  // 1. Make sure it contains the key at the start
  if (rcd.compare(1, s_key.length(),s_key) != 0) {
    return 0;
  }
  

  // 2. Make sure the record's length has factor of DECRYPTED_CHUNK_SIZE
  // 3. Make sure that it isn't too long

  // Now cutting off padding ats
  rcd.pop_back(); // remove $
  rcd = rcd.substr(1, rcd.find_last_not_of('@')); // remove ^ start and @ padding

  // 4. Make sure there's no special characters besides slashes
  if (rcd.find_first_not_of("01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-") != string::npos) {
    cout << "Improper record string \n";
    return 0;
  }
  return 1;
}

// Returns 0 if integrity violation
int FileReaderWriter::verify_key() {
  if (read_chunk() == 0)
    return 0;

  // Now decrypt the signature chunk
  string s = decrypt_chunk();

  // If empty, then there's an 
  if (s.empty()) {
    // ~~~~~~~~~~~ERROR Failure to decrypt!~~~~~~~~~~~";

    // INTEGRITY VIOLATION
		return 0;
  }

  // Check if signature is valid
  if (0 != strncmp((char*)s.c_str(),(char*)VERIFICATION_CHUNK_STR,(size_t)DECRYPTED_CHUNK_SIZE)) {
    // ~~~~~~~~~~~ERROR Failure to verify the file signature!~~~~~~~~~~~";

    // INTEGRITY VIOLATION
    return 0;
  }
  
  return 1;
}

int FileReaderWriter::read_chunk() {
  char buffer[CHUNK_SIZE];
  if (ifs.peek() == EOF) {
    return 0;
  }
  ifs.read(buffer, CHUNK_SIZE);
  s_cipher_base64 = string(buffer, CHUNK_SIZE);
  return 1;
}

// Returns ErrorType
int FileReaderWriter::load_file(string fname) {

  // Test if valid writable file
  ofstream _wfs;
  _wfs.open(filename, ios_base::app);
  if (!_wfs.is_open()) {
    cerr << "FAILURE: Invalid file path.\n";
    return INVALID_FILE_PATH;
  }

  // Test if file is empty and whether to write the signature to it
  ifs = ifstream(fname);
  if (ifs.peek() == EOF) {
    append_and_encrypt_chunk(VERIFICATION_CHUNK_STR);
    return SUCCESS_NEW_FILE;
  }
  return SUCCESS_FILE_EXISTS;
}

string FileReaderWriter::decrypt_next_chunk() {
  if (read_chunk() == 0)
    return "";
  //cout << "===Finished reading chunk : " << s_cipher_base64 <<"\n";
  string s = decrypt_chunk();

  // TODO remember: if empty it's an integrity violation
  return s;
}

/* The following method waas originally copied from and modified from this website:
 *
 * https://eclipsesource.com/blogs/2017/01/17/tutorial-aes-encryption-and-decryption-with-openssl/
 *
 */
string FileReaderWriter::decrypt_chunk() {
  // encrypted using aes-256-cbc
  s_cipher_base64.push_back('\n');
  char* ciphertext_base64 = (char*) s_cipher_base64.c_str();
  int decryptedtext_len, ciphertext_len;
  size_t cipher_len;
  unsigned char *ciphertext, *cipher_alloced_mem;
  unsigned char salt[8];
  ERR_load_crypto_strings();
  base64Decode(ciphertext_base64, &ciphertext, &cipher_len);

  if (cipher_len <= 0) {
    // ~~~~~~~~~~~ERROR Cipher file is empty, expected bytes!~~~~~~~~~~~";

    // INTEGRITY VIOLATION

    // Free everything before returning empty
    free(ciphertext);
    return "";
  }

  unsigned char key[KEY_LENGTH];
  unsigned char iv[IV_LENGTH];

  if (strncmp((const char*)ciphertext,"Salted__",8) == 0) {
    memcpy(salt,&ciphertext[8],8);
    cipher_alloced_mem = ciphertext;
    ciphertext += 16;
    cipher_len -= 16;
  }
  else {
    // ~~~~~~~~~~~ERROR Salted not found!~~~~~~~~~~~";

    // INTEGRITY VIOLATION

    // Free everything before returning empty
    free(ciphertext);
    ERR_free_strings();
    return "";
  }
  int key_size = initAES(s_key.c_str(), salt, key, iv);

  if (key_size != KEY_LENGTH) {
    // ~~~~~~~~~~~ERROR Key stretching failed somehow!~~~~~~~~~~~";

    // INTEGRITY VIOLATION

    // Free everything before returning empty
    free(cipher_alloced_mem);
    ERR_free_strings();
    return "";
  }
  string plaintext = decrypt(ciphertext, cipher_len, key, iv);

  if (plaintext.empty()) {
    // ~~~~~~~~~~~ERROR Decrypt returns empty string if error!~~~~~~~~~~~";

    // INTEGRITY VIOLATION

    // Free everything before returning empty
    free(cipher_alloced_mem);
    ERR_free_strings();
    return "";
  }

  // Clean up
  free(cipher_alloced_mem);
  ERR_free_strings();

  return plaintext;
}

void FileReaderWriter::handleOpenSSLErrors(void)
{
  //ERR_print_errors_fp(stderr);
  //abort();
}

/* The following method waas originally copied from this website:
 *
 * https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption#Decrypting_the_message
 *
 */
string FileReaderWriter::decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv ) {

  int len;
  int plaintext_len;
  unsigned char* plaintext = new unsigned char[ciphertext_len];
  bzero(plaintext,ciphertext_len);

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) {
    // ~~~~~~~~~~~ERROR Failure to decrypt!~~~~~~~~~~~";

    // INTEGRITY VIOLATION
    handleOpenSSLErrors();
    delete [] plaintext;
    return "";
  }
  EVP_CIPHER_CTX_set_padding(ctx, 0);

  /* Don't set key or IV right away; we want to check lengths */
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, NULL, NULL)) {
    // ~~~~~~~~~~~ERROR Failure to decrypt!~~~~~~~~~~~";

    // INTEGRITY VIOLATION
    handleOpenSSLErrors();
    EVP_CIPHER_CTX_free(ctx);
    delete [] plaintext;
    return "";
  }

  /* Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
    // ~~~~~~~~~~~ERROR Failure to decrypt!~~~~~~~~~~~";

    // INTEGRITY VIOLATION
    handleOpenSSLErrors();
    EVP_CIPHER_CTX_free(ctx);
    delete [] plaintext;
    return "";
  }

  /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
    // ~~~~~~~~~~~ERROR Failure to decrypt!~~~~~~~~~~~";

    // INTEGRITY VIOLATION
    handleOpenSSLErrors();
    delete [] plaintext;
    return "";
  }

  plaintext_len = len;

  /* Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
    // ~~~~~~~~~~~ERROR Failure to decrypt!~~~~~~~~~~~";

    // INTEGRITY VIOLATION
    handleOpenSSLErrors();
    EVP_CIPHER_CTX_free(ctx);
    delete [] plaintext;
    return "";
  }
  plaintext_len += len;


  /* Add the null terminator */
  plaintext[plaintext_len] = 0;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);
  string ret = (char*)plaintext;
  delete [] plaintext;
  return ret;
}

/* The following method waas originally copied from this website:
 *
 * https://eclipsesource.com/blogs/2017/01/17/tutorial-aes-encryption-and-decryption-with-openssl/
 *
 */
int FileReaderWriter::initAES(const string& pass, unsigned char* salt, unsigned char* key, unsigned char* iv )
{
  bzero(key,sizeof(key));
  bzero(iv,sizeof(iv));

  int key_size = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, (unsigned char*)pass.c_str(), pass.length(), 1, key, iv);
  return key_size;
}

/* The following method waas originally copied from this website:
 *
 * https://eclipsesource.com/blogs/2017/01/17/tutorial-aes-encryption-and-decryption-with-openssl/
 *
 */
size_t FileReaderWriter::calcDecodeLength(char* b64input) {
  size_t len = strlen(b64input), padding = 0;

  if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
    padding = 2;
  else if (b64input[len-1] == '=') //last char is =
    padding = 1;
  return (len*3)/4 - padding;
}



/* The following method waas originally copied from this website:
 *
 * https://eclipsesource.com/blogs/2016/09/07/tutorial-code-signing-and-verification-with-openssl/
 *
 */
void FileReaderWriter::base64Encode(const unsigned char* buffer,
                                    size_t length,
                                    char** base64Text)
{
  BIO *bio, *b64;
  BUF_MEM *bufferPtr;

  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new(BIO_s_mem());
  bio = BIO_push(b64, bio);

  BIO_write(bio, buffer, length);
  BIO_flush(bio);
  BIO_get_mem_ptr(bio, &bufferPtr);
  BIO_set_close(bio, BIO_NOCLOSE);
  BIO_free_all(bio);

  *base64Text=(*bufferPtr).data;
}

/* The following method waas originally copied from this website:
 *
 * https://eclipsesource.com/blogs/2017/01/17/tutorial-aes-encryption-and-decryption-with-openssl/
 *
 */
void FileReaderWriter::base64Decode(char* b64message, unsigned char** buffer, size_t* length) {
  BIO *bio, *b64;

  int decodeLen = calcDecodeLength(b64message);
  *buffer = (unsigned char*)malloc(decodeLen + 1);
  (*buffer)[decodeLen] = '\0';

  bio = BIO_new_mem_buf(b64message, -1);
  b64 = BIO_new(BIO_f_base64());
  bio = BIO_push(b64, bio);

  //BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer
  *length = BIO_read(bio, *buffer, strlen(b64message));
  BIO_free_all(bio);
}

/* The following method waas originally copied from this website:
 *
 * https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption#Encrypting_the_message
 *
 */
int FileReaderWriter::encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
      handleOpenSSLErrors();
      // ~~~~~~~~~~~ERROR Failure to encrypt!~~~~~~~~~~~";
      // INTEGRITY VIOLATION
      return 0;
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    //cout<<"ENC: Key ";p_hex(key,32);cout<<endl;

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
      handleOpenSSLErrors();
      // ~~~~~~~~~~~ERROR Failure to encrypt!~~~~~~~~~~~";
      // INTEGRITY VIOLATION
      EVP_CIPHER_CTX_free(ctx);
      return 0;
    }

    //cout << "ENCRYPT: Key length " << EVP_CIPHER_CTX_key_length(ctx) << endl;


    EVP_CIPHER_CTX_set_key_length(ctx, KEY_LENGTH);


    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
      handleOpenSSLErrors();
      // ~~~~~~~~~~~ERROR Failure to encrypt!~~~~~~~~~~~";
      // INTEGRITY VIOLATION
      EVP_CIPHER_CTX_free(ctx);
      return 0;
    }
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
      handleOpenSSLErrors();
      // ~~~~~~~~~~~ERROR Failure to encrypt!~~~~~~~~~~~";
      // INTEGRITY VIOLATION
      EVP_CIPHER_CTX_free(ctx);
      return 0;
    }
    ciphertext_len += len;

    ciphertext[ciphertext_len] = 0;
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}


/*
int main(int argc, char** argv) {
  std::string key = "secret";
  FileReaderWriter frw("testdir", key);
  frw.init();

  int t;
  int opt = 0;
  while ((opt = getopt(argc, argv, "r:w:k:")) != -1) {
    switch(opt) {
      case 'k':
          key = optarg;break;
      case 'r':
          t = stoi(string(optarg));
          for (int i = 0; i < t; i++) {
            string s = frw.get_next_record_string();
            //this_thread::sleep_for(chrono::seconds(1));
            if (s.empty())
              break;
            cout << "> " << s << endl;
          }
          break;
      case 'w':
          //cout << frw.append_record(key + optarg) << endl;
          frw.append_record(key + optarg);
          break;
      default:
          cerr << "Invalid Command Line Argument\n";
    }
  }


  return 0;
}
*/
