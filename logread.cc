#include <iostream>
#include <unistd.h>
#include <string>
#include <string.h>

#include "FileReaderWriter.h"
#include "error.h"

#define ERROR_EXIT_CODE 255

using namespace std;

int main(int argc, char** argv) {
  string key = "secret";
  FileReaderWriter frw("log1", key);
  int status = frw.init();
  if (status == INTEGRITY_VIOLATION) {
    cout << "Mess up\n";
  }

  int t;
  int opt = 0;
  string s;
  while ((opt = getopt(argc, argv, "r:w:k:")) != -1) {
    switch(opt) {
      case 'k':
          key = optarg;break;
      case 'r':
          t = stoi(string(optarg));
          s = frw.get_record_string_at(t);
          if (s.empty()) cout<<"fail\n";
          else cout << "b> " << s << endl;
          s = frw.get_record_string_before(t);
          if (s.empty()) cout<<"2fail\n";
          else cout << "a> " << s << endl;
          break;
      case 'w':
          //cout << frw.append_record(key + optarg) << endl;
          frw.append_record(key + optarg);
          break;
      default:
          cerr << "Invalid Command Line Argument\n";
    }
  }
  

    int i = 1;

    // Iterate through the records
    while (i < frw.get_num_chunks()) {
      i = frw.get_next_record_string(s, i);
      if (i == 0 || s.empty()) {
        handleIntegrityViolation();
        exit(ERROR_EXIT_CODE);
      }
      cout << s << endl;
    }


  return 0;
}
