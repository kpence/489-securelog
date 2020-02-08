#include <iostream>
#include <unistd.h>
#include <string>
#include <string.h>

#include "FileReaderWriter.h"

using namespace std;

int main(int argc, char** argv) {
  string key = "secret";
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
            if (s.empty()) {
              //ErrorType e = ErrorType::INTEGRITY_VIOLATION;
              //handleError(ErrorType::INTEGRITY_VIOLATION);
              frw.handleError(2);
              break;
            }
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
