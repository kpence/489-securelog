#include <iostream>
#include <unistd.h>
#include <string>
#include <utility>
#include <vector>
#include <string.h>

//#include "FileReaderWriter.h"
//#include "EntryParser.h"
//#include "error.h"
#include "hospitalstate.h"

using namespace std;

#define ERROR_EXIT_CODE 255

int test_and_append_entry();
char event_type = '\0'; // arrival/departure
char name_type = '\0'; // doctor/nurse
string timestamp
     , token
     , name
     , roomid
     , logfile;

int main(int argc, char** argv) {
  // Opts
  int non_batch_file_opt = 0;
  string batchfile;

  int t;
  int opt = 0;
  while ((opt = getopt(argc, argv, "T:K:D:N:ALR:F:B:")) != -1) {
    switch(opt) {
      case 'T':
          if (!timestamp.empty()) {
            handleInvalidInput();
            exit(ERROR_EXIT_CODE);
          }
          timestamp = optarg;break;
      case 'K':
          if (!token.empty()) {
            handleInvalidInput();
            exit(ERROR_EXIT_CODE);
          }
          token = optarg;break;
      case 'D':
          if (!name.empty()) {
            handleInvalidInput();
            exit(ERROR_EXIT_CODE);
          }
          name_type = 'D';
          name = optarg;break;
      case 'N':
          if (!name.empty()) {
            handleInvalidInput();
            exit(ERROR_EXIT_CODE);
          }
          name_type = 'N';
          name = optarg;break;
      case 'A':
      case 'L':
          if (event_type != '\0') {
            handleInvalidInput();
            exit(ERROR_EXIT_CODE);
          }
          event_type = opt;break;
      case 'R':
          if (!roomid.empty()) {
            handleInvalidInput();
            exit(ERROR_EXIT_CODE);
          }
          roomid = optarg;break;
      case 'F':
          if (!logfile.empty()) {
            handleInvalidInput();
            exit(ERROR_EXIT_CODE);
          }
          logfile = optarg;break;
      case 'B':
          if (!batchfile.empty()) {
            handleInvalidInput();
            exit(ERROR_EXIT_CODE);
          }
          batchfile = optarg;break;
      default:
          handleInvalidInput();
          exit(ERROR_EXIT_CODE);
    }
  }

  // If batch file and any other arguments are set, then invalid input.
  if (!batchfile.empty() && non_batch_file_opt != 0) {
      handleInvalidInput();
      exit(ERROR_EXIT_CODE);
  }

  // If batch file empty but missing anything necessary, then invalid input.
  if (batchfile.empty() && (timestamp.empty() || token.empty() || name.empty()
        || event_type == '\0' || logfile.empty()))
  {
    handleInvalidInput();
    exit(ERROR_EXIT_CODE);
  }

  // Run_command will use all the variables set at the start
  if (batchfile.empty()) {
    test_and_append_entry();
  }
  else {
    if (EntryParser::is_filepath_valid(batchfile)==0) {
      handleInvalidInput();
      exit(ERROR_EXIT_CODE);
    }


    // TODO Now handle the batch file stuff
  }

  return 0;
}


// This procedure will exit the program with error message if it finds anything wrong with the entry record
int test_and_append_entry() {
  // Now test each of the fields for valid input
  string s;
  int error = 0;
  if (EntryParser::is_name_valid(name)==0) { error=1; }
  else if (EntryParser::is_name_type_valid(name_type)==0) { error=1; }
  else if (EntryParser::is_event_type_valid(event_type)==0) { error=1; }
  else if (EntryParser::is_token_valid(token)==0) { error=1; }
  else if (EntryParser::is_filepath_valid(logfile)==0) { error=1; }
  else if (EntryParser::is_timestamp_valid(timestamp)==0) { error=1; }
  else if (EntryParser::is_roomid_valid(roomid)==0) { error=1; }

  if (error == 1) {
    handleInvalidInput();
    exit(ERROR_EXIT_CODE);
  }

  if (!roomid.empty())
    roomid = EntryParser::parse_roomid(roomid);

  // Create log writer/reader
  FileReaderWriter frw(logfile, token);
  int status = frw.init();
  if (status == INTEGRITY_VIOLATION) {
    handleIntegrityViolation();
    exit(ERROR_EXIT_CODE);
  }

  // Now test to see if the timestamp is a problem OR if it's empty that's ok (1 is empty)
  if (frw.get_num_chunks() > 1) {
    EntryParser p;

    s = frw.get_record_string_before(frw.get_num_chunks()-1);
    if (s.empty()) {
      handleIntegrityViolation();
      exit(ERROR_EXIT_CODE);
    }
    p.load_record(s);
    if (!p.is_record_valid()) {
      handleIntegrityViolation();
      exit(ERROR_EXIT_CODE);
    }
    if (p.compare_timestamp(timestamp) == 0) {
      handleInvalidInput();
      exit(ERROR_EXIT_CODE);
    }

    int touched, in_hospital;
    string room_in;
    get_person_state(frw, p, in_hospital, touched, room_in, name_type, name);

    // After getting the state of the doctor, check if valid entry
    // If the person has never been logged, then only accept roomless arrival
    if (touched == 0) {
      if (!roomid.empty() || event_type=='L') {
        handleInvalidInput();
        exit(ERROR_EXIT_CODE);
      }
    }
    else {
      // Make sure values from get_person_state are right conditions for the record entry
      if (roomid.empty() && event_type=='A') {
        if (!room_in.empty() || in_hospital != 0) {
          handleIntegrityViolation();
          exit(ERROR_EXIT_CODE);
        }
      }
      else if (roomid.empty() && event_type=='L') {
        if (!room_in.empty() || in_hospital == 0) {
          handleIntegrityViolation();
          exit(ERROR_EXIT_CODE);
        }
      }
      else if (!roomid.empty() && event_type=='A') {
        if (!room_in.empty() || in_hospital == 0) {
          handleIntegrityViolation();
          exit(ERROR_EXIT_CODE);
        }
      }
      else if (!roomid.empty() && event_type=='L') {
        if (roomid.compare(room_in) != 0 || in_hospital == 0) {
          handleIntegrityViolation();
          exit(ERROR_EXIT_CODE);
        }
      }

    }

  }
  else {
    // If log file is empty then only accept roomless arrival records
    if (!roomid.empty() || event_type=='L') {
      handleInvalidInput();
      exit(ERROR_EXIT_CODE);
    }
  }

  // PASSED - NOW Append the entry
  s = EntryParser::make_record(token,timestamp,event_type,name_type,name,roomid);
  frw.append_record(s);
}
