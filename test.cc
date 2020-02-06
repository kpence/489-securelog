#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string.h>
#include <unistd.h>
#include <iostream>
#include <string>
#include <fstream>
using namespace std;

#define DECRYPTED_CHUNK_SIZE 16
#define CHUNK_SIZE 64
#define VERIFY_CHUNK_STR "THE KEY IS GREAT"

class FileReaderWriter {
  public:
    FileReaderWriter(const string fname,
                     const string _s_key)
      : filename(fname), s_key(_s_key), parseRemainder(), command_string()
    {
      load_file(fname);
      verify_key();
    }
    string decrypt_next_chunk();
    string decrypt_chunk(); // TODO every chunk, check if the chunk sig prefix is present
    // Command Parsing from Chunks
    int parse_command(); //commands start with ^ and end with $ remainder dumped to parseRemainder
    string get_command_string();
  protected:
  private:
    void load_file(string fname);
    void check_corruption(string key); // TODO Check for corruption, for now assume
    int verify_command(); // TODO checks if command_string has correct token attached
    int verify_key();
    void read_chunk();


    // Decryption functions (SSL)
    void base64Decode(char* b64message, unsigned char** buffer, size_t* length);
    size_t calcDecodeLength(char* b64input);
    string decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv);
    int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext)
    void initAES(const string& pass, unsigned char* salt, unsigned char* key, unsigned char* iv);



    void handleOpenSSLErrors(void);
    string s_cipher_base64;
    string filename;
    string s_key;
    ifstream ifs;

    // Parsing commands members
    string parseRemainder;
    string command_string;
};

int FileReaderWriter::parse_command() {
  // Read new chunks until you reach a $
  // First test if you find a command in the parseRemainder
  size_t ec;
  if ((ec = parseRemainder.find_first_of('$')) != string::npos) {
    command_string = parseRemainder.substr(0,ec);
    parseRemainder = parseRemainder.substr(ec);

    // VERIFY COMMAND
    int ret = verify_command();
    return ret;
  }
  command_string = parseRemainder;
  parseRemainder.clear();
  // Read chunk
  string s = decrypt_next_chunk();
  while ((ec = s.find_first_of('$')) == string::npos) {
    command_string += s;
    s = decrypt_next_chunk();
  }
  command_string += s.substr(0, ec);
  parseRemainder = s.substr(ec);

  // VERIFY COMMAND
  int ret = verify_command();
  return ret;
}

string FileReaderWriter::get_command_string() {
  return command_string.substr(1);
}

int FileReaderWriter::verify_command() {
  if (get_command_string().compare(0, s_key.length(),s_key) != 0) {
    cout << "This is a bad key for this command! \n";
    return 0;
  }
  return 1;
}

int FileReaderWriter::verify_key() {
  read_chunk();

  // Now decrypt the signature chunk
  string s = decrypt_chunk();

  // Check if signature is valid
  if (0 != strncmp((char*)s.c_str(),(char*)VERIFY_CHUNK_STR,(size_t)DECRYPTED_CHUNK_SIZE)) {
    // Failure, bad file
    return 0;
    cout << "FAILURE: Failed to verify signature, returning -1 and mkae sure to exit with 255 and output Integrity violation\n";
  }
  
  return 1;
}

void FileReaderWriter::read_chunk() {
  char buffer[CHUNK_SIZE];
  ifs.read(buffer, CHUNK_SIZE);
  s_cipher_base64 = string(buffer, CHUNK_SIZE);
}
void FileReaderWriter::load_file(string fname) {
   ifs = ifstream(fname);
}

string FileReaderWriter::decrypt_next_chunk() {
  read_chunk();
  return decrypt_chunk();
}

string FileReaderWriter::decrypt_chunk() {
  // This is the string Hello, World! encrypted using aes-256-cbc with the
  // pasword 12345
  s_cipher_base64.push_back('\n');
  char* ciphertext_base64 = (char*) s_cipher_base64.c_str();
  int decryptedtext_len, ciphertext_len;
  size_t cipher_len;
  unsigned char *ciphertext, *cipher_alloced_mem;
  unsigned char salt[8];
  ERR_load_crypto_strings();
  base64Decode(ciphertext_base64, &ciphertext, &cipher_len);

  unsigned char key[32];
  unsigned char iv[32];

  if (strncmp((const char*)ciphertext,"Salted__",8) == 0) {
    memcpy(salt,&ciphertext[8],8);
    cipher_alloced_mem = ciphertext;
    ciphertext += 16;
    cipher_len -= 16;
  }
  initAES(s_key.c_str(), salt, key, iv);

  string result = decrypt(ciphertext, cipher_len, key, iv);

  free(cipher_alloced_mem);

  // Clean up
  EVP_cleanup();
  ERR_free_strings();

  result.pop_back();
  return result;
}

void FileReaderWriter::handleOpenSSLErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

string FileReaderWriter::decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv ) {

  EVP_CIPHER_CTX *ctx;
  unsigned char *plaintexts;
  int len;
  int plaintext_len;
  unsigned char* plaintext = new unsigned char[ciphertext_len];
  bzero(plaintext,ciphertext_len);

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleOpenSSLErrors();


  /* Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleOpenSSLErrors();

  EVP_CIPHER_CTX_set_key_length(ctx, EVP_MAX_KEY_LENGTH);

 /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleOpenSSLErrors();

  plaintext_len = len;

  /* Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleOpenSSLErrors();
  plaintext_len += len;


  /* Add the null terminator */
  plaintext[plaintext_len] = 0;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);
  string ret = (char*)plaintext;
  delete [] plaintext;
  return ret;
}

void FileReaderWriter::initAES(const string& pass, unsigned char* salt, unsigned char* key, unsigned char* iv )
{
  bzero(key,sizeof(key));
  bzero(iv,sizeof(iv));

  EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, (unsigned char*)pass.c_str(), pass.length(), 1, key, iv);
}

size_t FileReaderWriter::calcDecodeLength(char* b64input) {
  size_t len = strlen(b64input), padding = 0;

  if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
    padding = 2;
  else if (b64input[len-1] == '=') //last char is =
    padding = 1;
  return (len*3)/4 - padding;
}

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

int FileReaderWriter::encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}


int main(int argc, char** argv) {
  std::string key = "secret";
  int opt = 0;
  while ((opt = getopt(argc, argv, "k:")) != -1) {
    switch(opt) {
      case 'k':
          key = optarg;break;
      default:
          std::cerr << "Invalid Command Line Argument\n";
    }
  }

  FileReaderWriter frw("./output.txt", key);
  frw.parse_command();
  cout << frw.get_command_string() << endl;



  return 0;
}
