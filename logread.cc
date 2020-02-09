#include <iostream>
#include <unistd.h>
#include <string>
#include <string.h>
#include <map>
#include <utility>

//#include "FileReaderWriter.h"
//#include "error.h"
//#include "EntryParser.h"
#include "hospitalstate.h"

#define ERROR_EXIT_CODE 255

using namespace std;

int main(int argc, char** argv) {
  string key = "secret";
  FileReaderWriter frw("log1", key);
  int status = frw.init();
  if (status == INTEGRITY_VIOLATION) {
		handleIntegrityViolation();
		exit(ERROR_EXIT_CODE);
  }
	
	string name
			 , token
			 , logfile;
	char name_type;
  char read_type = '\0';
  int opt = 0;
  string s;
  while ((opt = getopt(argc, argv, "K:SF:RD:N:")) != -1) {
    switch(opt) {
      case 'K':
					if (!token.empty()) {
						handleInvalidInput();
						exit(ERROR_EXIT_CODE);
					}
					token = optarg;break;
      case 'S':
					if (!name.empty() || read_type != '\0') {
						handleInvalidInput();
						exit(ERROR_EXIT_CODE);
					}
          read_type = 'S';break;
      case 'R':
					if (read_type != '\0') {
						handleInvalidInput();
						exit(ERROR_EXIT_CODE);
					}
          read_type = 'R';break;
      case 'F':
					if (!logfile.empty()) {
						handleInvalidInput();
						exit(ERROR_EXIT_CODE);
					}
          logfile = optarg;break;
      case 'N':
					if (!name.empty()) {
						handleInvalidInput();
						exit(ERROR_EXIT_CODE);
					}
					name_type = 'N';
          name = optarg;break;
      case 'D':
					if (!name.empty()) {
						handleInvalidInput();
						exit(ERROR_EXIT_CODE);
					}
					name_type = 'D';
          name = optarg;break;
      default:
          handleInvalidInput();
          exit(ERROR_EXIT_CODE);
    }
  }
  
	// Validate the input
	if (token.empty() || logfile.empty()) {
		handleInvalidInput();
		exit(ERROR_EXIT_CODE);
	}

	if ( EntryParser::is_token_valid(token)==0
		|| EntryParser::is_filepath_valid(logfile)==0)
	{
		handleInvalidInput();
		exit(ERROR_EXIT_CODE);
	}

	if (read_type != 'S' && read_type !=  'R') {
		handleInvalidInput();
		exit(ERROR_EXIT_CODE);
	}

	if (read_type ==  'S') {
		if (!name.empty()) {
			handleInvalidInput();
			exit(ERROR_EXIT_CODE);
		}
	}
	else {
		if ((name_type != 'D' && name_type != 'N') || name.empty()) {
			handleInvalidInput();
			exit(ERROR_EXIT_CODE);
		}
		if ( EntryParser::is_name_valid(name)==0 ) {
			handleInvalidInput();
			exit(ERROR_EXIT_CODE);
		}
	}

  EntryParser p;

  // This code prints out the rooms of name_type, name
  map<pair<char,string>,person_state> person_states;
  auto to_track = make_pair(name_type, name);
  person_state ps;
  ps.in_hospital = 0;
  ps.touched = 0;
  ps.room_in = "";
  person_states[to_track] = ps;
  string rooms;
  get_hospital_state(frw, p, person_states, rooms, 1);

  cout << rooms << endl;
	// Iterate through the records
	//int i = 1;
  /*
	while (i < frw.get_num_chunks()) {
		i = frw.get_next_record_string(s, i);
		if (i == 0 || s.empty()) {
			handleIntegrityViolation();
			exit(ERROR_EXIT_CODE);
		}
		cout << s << endl;
	}
  */


  return 0;
}
