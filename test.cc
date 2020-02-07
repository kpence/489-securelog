#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string.h>
#include <cstdlib>
#include <unistd.h>
#include <iostream>
#include <string>
#include <fstream>

#include <random>
#include <functional>
#include <algorithm>
using namespace std;

#define DECRYPTED_CHUNK_SIZE 16
#define CHUNK_SIZE 64
#define VERIFY_CHUNK_STR "THE KEY IS GREAT"

class FileReaderWriter {
  public:
    FileReaderWriter(const string fname,
                     const string _s_key)
      : filename(fname), s_key(_s_key), command_string()
    {
      load_file(fname);
      verify_key();
    }

    // Reading
    string decrypt_next_chunk();
    string decrypt_chunk(); // TODO every chunk, check if the chunk sig prefix is present

    // Command Parsing from Chunks
    int parse_command(); //commands start with ^ and end with {@}$
    string get_command_string();
    string get_next_command_string();

    // Writing
    int append_command(string cmd); //commands start with ^ and end with {@}$
  protected:
  private:
    // Writing
    /* Instructions
     *  Before we end a command, we insert @s until the end of a byte
     */
    int append_and_encrypt_chunk(string s);

    // I/O
    void load_file(string fname);
    void read_chunk();

    // Verifying
    void check_corruption(string key); // TODO Check for corruption, for now assume
    int verify_command(); // TODO checks if command_string has correct token attached
    int verify_key();


    // Decryption functions (SSL)
    void base64Decode(char* b64message, unsigned char** buffer, size_t* length);
    void base64Encode(const unsigned char* buffer, size_t length, char** base64Text);
    size_t calcDecodeLength(char* b64input);
    string decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv);
    int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext);
    void initAES(const string& pass, unsigned char* salt, unsigned char* key, unsigned char* iv);
    void handleOpenSSLErrors(void);

    string s_cipher_base64;
    string filename;
    string s_key;
    ifstream ifs;
    ofstream wfs; // write to file

    // Parsing commands members
    string command_string;
};


// Writing
/* STEPS:
 * 1. Create the key-stretched key using the authentication token and a randomly generated SALT (Use random SALT and this.initAES method)
 * 2. Perform the AES encryption using the generated key
 * 3. Prepend the encrypted chunk with the SALT
 * 4. Encode in base64
 * 5. Append to file
 */
int FileReaderWriter::append_and_encrypt_chunk(string chunk) {
  // Append to end of the file
  cout << "Appending chunk: " << chunk << endl;

  size_t cipher_len;

  char* ciphertext_base64;
  unsigned char ciphertext[128];
  unsigned char *prepend_ciphertext;
  unsigned char salt[8];
  ERR_load_crypto_strings();

  unsigned char key[32];
  unsigned char iv[32];

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
  initAES(s_key.c_str(), salt, key, iv);

  // Step two Perform the AES encryption
  cipher_len = encrypt((unsigned char*)chunk.c_str(), DECRYPTED_CHUNK_SIZE, key, iv, ciphertext);

  // Step three Prepend the cypher with the SALT
  prepend_ciphertext = (unsigned char*)malloc(cipher_len+16);
  strcpy( (char*)prepend_ciphertext,"Salted__");
  strncat((char*)prepend_ciphertext,(char*)salt,8);
  strncat((char*)prepend_ciphertext,(char*)ciphertext,cipher_len);
  cipher_len += 16;

  // Step four Encode in Base64
  base64Encode(ciphertext, cipher_len, &ciphertext_base64);

  //free(cipher_alloced_mem);

  // Clean up
  EVP_cleanup();
  ERR_free_strings();

  // Step five append file with it
  wfs << string((char*)ciphertext_base64, CHUNK_SIZE);
  cout << "CHUNK MADE: " << string((char*)ciphertext_base64, CHUNK_SIZE) << endl;
  return 0;
}

/* Instructions
 *  Before we end a command, we insert @s until the end of a byte
 */
int FileReaderWriter::append_command(string cmd)
{
  // TODO (uncomment when done testing ) First verify the command
  command_string = "$"+cmd;
  //if (1 != verify_command())
    //return ret;


  // Append the command with the appropriate number of @ padding signs
  // Example, say decyphered chunk length is 4
  //$123456^
  //$12345@^
  //$1234567@@@^
  //
  // V probably a better way to do this.... but w/e
  int modulo = (cmd.length()+2) % DECRYPTED_CHUNK_SIZE;
  int padAts = (DECRYPTED_CHUNK_SIZE - (modulo) % DECRYPTED_CHUNK_SIZE);

  // Get number of chunks to append
  int num = (cmd.length()+2) / DECRYPTED_CHUNK_SIZE;
  if (modulo != 0) ++num;

  // For each of these (if last one, then add the @ padding), encrypt it, and append it to the file,
  int i;
  string send = "$";
  if (num == 1) {
    send += cmd;
    if (padAts > 0)
      send += string(padAts,'@');
    send += "^";
    append_and_encrypt_chunk(send);
  }
  else {
    send += cmd.substr(0,DECRYPTED_CHUNK_SIZE-1);
    cmd.erase(0,DECRYPTED_CHUNK_SIZE-1);
    append_and_encrypt_chunk(send); // TODO check the status for each of these append chunks, or just throw an exception
    for (i = 1; i < num; i++) {
      if (i == num-1) {
        send = cmd;
        cmd.erase(0,DECRYPTED_CHUNK_SIZE-1-padAts);
        if (padAts > 0)
          send += string(padAts,'@');
        send += "^";
      }
      else {
        send = cmd.substr(0,DECRYPTED_CHUNK_SIZE);
        cmd.erase(0,DECRYPTED_CHUNK_SIZE);
      }
      append_and_encrypt_chunk(send);
    }
  }
}

int FileReaderWriter::parse_command() {
  // Read new chunks until you reach a $
  cout << "Parse: " << endl;
  string s = decrypt_next_chunk();


  // TODO verify the command is correctly formed during parsing

  cout << "Parse s: " << s << endl;

  while (s[DECRYPTED_CHUNK_SIZE-1] != '$') {
    cout << "Parse NOT NOT over, here's the command_string : " << command_string<< endl;
    command_string += s;
    s = decrypt_next_chunk();
    cout << "Parse NOT NOT over, here's the command_string : " << command_string<< endl;
  }
  cout << "Parse NOT over, here's the command_string : " << command_string<< endl;
  command_string += s;

  cout << "Parse over, here's the command_string : " << command_string<< endl;
  int ret = verify_command();
  return ret;
}

string FileReaderWriter::get_next_command_string() {
  cout << "about to parse command: here''s the raw command_string " << command_string <<endl;;
  parse_command();
  cout << "parsed command\n";
  return get_command_string();
}

string FileReaderWriter::get_command_string() {
  int i;
  if ((i = command_string.find_first_of('@')) != string::npos)
    return command_string.substr(1,i-1);
  else
    return command_string.substr(1);
}

// TODO Make sure that also there are NO special characters, this all is exploitable
int FileReaderWriter::verify_command() {
  if (get_command_string().compare(0, s_key.length(),s_key) != 0) {
    cout << "FAILURE: This is a bad key for this command! \n";
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
    cout << "FAILURE: Failed to verify signature, returning -1 and mkae sure to exit with 255 and output Integrity violation\n";
    return 0;
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
   wfs.open(fname, ios_base::app); // append
}

string FileReaderWriter::decrypt_next_chunk() {
  read_chunk();
  cout << "Finished reading chunk : " << s_cipher_base64 <<"\n";
  return decrypt_chunk();
}

string FileReaderWriter::decrypt_chunk() {
  // encrypted using aes-256-cbc with the
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

  cout << "DECODE: \n";
  if (strncmp((const char*)ciphertext,"Salted__",8) == 0) {
    memcpy(salt,&ciphertext[8],8);
    cipher_alloced_mem = ciphertext;
    ciphertext += 16;
    cipher_len -= 16;
  }
  cout << "DECODE 1: \n";
  initAES(s_key.c_str(), salt, key, iv);
  cout << "DECODE 2: \n";

  string result = decrypt(ciphertext, cipher_len, key, iv);
  cout << "DECODE 3: \n";

  free(cipher_alloced_mem);
  cout << "DECODE 4: \n";

  // Clean up
  EVP_cleanup();
  ERR_free_strings();
  cout << "DECODE 5: \n";

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

  cout << "DECRYPT 1: \n";

  EVP_CIPHER_CTX *ctx;
  unsigned char *plaintexts;
  int len;
  int plaintext_len;
  unsigned char* plaintext = new unsigned char[ciphertext_len];
  bzero(plaintext,ciphertext_len);

  cout << "DECRYPT 2: \n";
  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleOpenSSLErrors();

  cout << "DECRYPT 3: \n";

  /* Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleOpenSSLErrors();

  cout << "DECRYPT 4: \n";

  EVP_CIPHER_CTX_set_key_length(ctx, EVP_MAX_KEY_LENGTH);

 /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
  cout << "DECRYPT 5: \n";
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleOpenSSLErrors();
  cout << "DECRYPT 5.2: \n";

  plaintext_len = len;

  /* Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleOpenSSLErrors();
  plaintext_len += len;
  cout << "DECRYPT 6: \n";


  /* Add the null terminator */
  plaintext[plaintext_len] = 0;

  cout << "DECRYPT 7: \n";
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
    cout << "TEST: startin encrypt\n";
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
      handleOpenSSLErrors();

    cout << ciphertext << endl;
    cout << "TEST4: finished encrypt\n";

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
      handleOpenSSLErrors();
    cout << "TEST3: finished encrypt\n";


    EVP_CIPHER_CTX_set_key_length(ctx, EVP_MAX_KEY_LENGTH);


    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    cout << "TESTINFO BEFORE: " << endl;
    cout << "TESTINFO: " << ciphertext << endl;

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
      handleOpenSSLErrors();
    ciphertext_len = len;
    cout << "TEST2: finished encrypt\n";

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
      handleOpenSSLErrors();
    ciphertext_len += len;
    cout << "TEST1: finished encrypt\n";

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    cout << "TEST: finished encrypt\n";
    return ciphertext_len;
}


int main(int argc, char** argv) {
  std::string key = "secret";
  FileReaderWriter frw("./output.txt", key);

  int t;
  int opt = 0;
  while ((opt = getopt(argc, argv, "r:w:k:")) != -1) {
    switch(opt) {
      case 'k':
          key = optarg;break;
      case 'r':
          t = stoi(string(optarg));
          for (int i = 0; i < t; i++) {
            string s = frw.get_next_command_string();
            cout << "HERE'S THE ACTUAL OUTPUT: " << s << endl;
          }
          break;
      case 'w':
          cout << frw.append_command("testing") << endl;
          break;
      default:
          std::cerr << "Invalid Command Line Argument\n";
    }
  }


  return 0;
}
