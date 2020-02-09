#include <iostream>
#include <algorithm>
#include <string>

#include "EntryParser.h"

#ifdef WINDOWS
#include <direct.h>
#define GetCurrentDir _getcwd
#else
#include <unistd.h>
#define GetCurrentDir getcwd
#endif

using namespace std;




// For each entry field, check if it's valid and return parsed value

// Max sizes
#define MAX_ROOMID_LENGTH 255
#define MAX_TOKEN_LENGTH 255
#define MAX_NAME_LENGTH 255
#define MAX_FILENAME_LENGTH 255
#define MAX_FILEPATH_LENGTH 4096

#define SUCCESSFUL 1


using namespace std;

// Example: -3ADSamuel-R1
//
// If this fails it's an INTEGRITY VIOLATION
int EntryParser::load_record(string rcd) {
  is_valid = 0; // init

  // Make this empty at first
  _roomid = "";


  // smallest example: -3ADa-
  // If too small
  if (rcd.size() < 6) {
    is_valid = 0;
    return 0;
  }

  // make sure it starts with -
  if (rcd[0] != '-') {
    is_valid = 0;
    return 0;
  }

  // If following timestamp isn't valid
  size_t event_type_pos = rcd.find_first_of("AL");
  if (event_type_pos == string::npos) {
    is_valid = 0;
    return 0;
  }
  string ts = rcd.substr(1, event_type_pos - 1);
  if (is_timestamp_valid(ts)==0) {
    is_valid = 0;
    return 0;
  }

  // Make sure not too small
  // smallest example: -3ADa-
  if (rcd.size() < (4 + event_type_pos)) {
    is_valid = 0;
    return 0;
  }

  // Make sure event type and following doctor or nurse is valid
  if (!(rcd[event_type_pos]=='A' || rcd[event_type_pos]=='L')
      || !(rcd[event_type_pos+1]=='D' || rcd[event_type_pos+1]=='N')) {
    is_valid = 0;
    return 0;
  }
  if (!(rcd[event_type_pos]=='A' || rcd[event_type_pos]=='L')) {
    is_valid = 0;
    return 0;
  }

  // Make sure the person's name is valid
  size_t name_end_pos = rcd.find_first_of('-',event_type_pos+2);
  if (name_end_pos == string::npos) {
    is_valid = 0;
    return 0;
  }
  string name = rcd.substr(event_type_pos+2, name_end_pos - event_type_pos - 2);
  if (is_name_valid(name)==0) {
    is_valid = 0;
    return 0;
  }

  // Now we see if there's a room indicated or not

  // Check to see if too large then a room must be indicated
  if (rcd.size() > (name_end_pos + 1)) {
    // Make sure not too small
    // smallest example: -3ADa-R1
    if (rcd.size() < (name_end_pos + 3)) {
      is_valid = 0;
      return 0;
    }

    if (rcd[name_end_pos+1] != 'R') {
      is_valid = 0;
      return 0;
    }

    // make sure room id is valid
    string roomid = rcd.substr(name_end_pos+2);
    if (is_roomid_valid(roomid)==0) {
      is_valid = 0;
      return 0;
    }

    _roomid = roomid;
  }

  _event_type = rcd[event_type_pos];
  _name_type = rcd[event_type_pos+1];
  _timestamp = ts;
  _name = name;

  is_valid = 1;
  return 0;
}
int EntryParser::is_record_valid() {
  return is_valid;
}

// Returns 0 if argument is smaller or equal to _timestamp
int EntryParser::compare_timestamp(string timestamp) {
  long int myts = stol(_timestamp);
  long int newts = stol(timestamp);
  return (newts > myts) ? 1 : 0;
}

int EntryParser::same_person(char name_type, string name) {
  if (name_type == _name_type && name.compare(_name) == 0)
    return 1;
  else
    return 0;
}

char EntryParser::get_event_type() { return _event_type; }
char EntryParser::get_name_type() { return _name_type; }
string EntryParser::get_roomid() { return _roomid; }
string EntryParser::get_timestamp() { return _timestamp; }

// Assuming these have been verified
string EntryParser::make_record(string token, string timestamp, char event_type, char name_type
    , string name, string roomid) {
  string s = token;
  s += '-';
  s += timestamp;
  s += event_type;
  s += name_type;
  s += name;
  s += '-';
  if (!roomid.empty()) {
    s += 'R';
    s += roomid;
  }
  return s;
}

/*
 * -------------------------------------------
 *  Validators of field values -- If any of these fail, programs shall throw INVALID_INPUT
 */

// File Path
//
// All log files and batch files must be located in the same directory from which logappend and logread are invoked, or in a sub-directory.
// So i need to get the current working directory in a string

int EntryParser::is_filepath_valid(string path) {
  if (path.length() > MAX_FILEPATH_LENGTH || path.empty())
    return 0;

	// This is in the specifications but it's gonna make it difficult to use on windows because of the prevalence of spaces in their filesystem
  if (path.find_first_not_of("./_0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
        != string::npos)
    return 0;

	// Let's disallow .. in the filepath
	if (path.find("..") != string::npos)
		return 0;

  // Now the file name
  size_t first_char = path.find_last_of('/');
  if (first_char == string::npos) // If no /s then just filename
    first_char = 0;

  if (path.length() - first_char > MAX_FILENAME_LENGTH) // If filename too large
    return 0;

	if (first_char == 0)
		return SUCCESSFUL; // If no /s, we're done here.

	// Get current working directory
	char buff[MAX_FILEPATH_LENGTH];
	GetCurrentDir(buff, MAX_FILEPATH_LENGTH);
	string cwd(buff);
	replace(cwd.begin(), cwd.end(), '\\', '/');
	
	// Now let's check if it's in the same directory as CWD, or subdir
	if (cwd.compare(0,cwd.length(), path) != 0)
		return 0;
	

  return SUCCESSFUL;
}


// Event types
int EntryParser::is_event_type_valid(char et) {
  if (et != 'A' && et != 'L')
    return 0;
  return SUCCESSFUL;
}

// Name types
int EntryParser::is_name_type_valid(char nt) {
  if (nt != 'D' && nt != 'N')
    return 0;
  return SUCCESSFUL;
}

// Names
int EntryParser::is_name_valid(string name) {
  if (name.length() > MAX_NAME_LENGTH || name.empty())
    return 0;
  if (name.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
        != string::npos)
    return 0;
  return SUCCESSFUL;
}


// Tokens
int EntryParser::is_token_valid(string token) {
  if (token.length() > MAX_TOKEN_LENGTH || token.empty())
    return 0;
  if (token.find_first_not_of("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
        != string::npos)
    return 0;
  return SUCCESSFUL;
}

// Time stamps
int EntryParser::is_timestamp_valid(string ts) {
  if (ts.find_first_not_of("0123456789") != string::npos)
    return 0;
  if (ts.find_first_not_of('0') == string::npos)
    return 0;
  if (ts.length() > 10)
    return 0;
  if (ts.length() == 10) {
    if (ts.compare("4294967293") > 0)
      return 0;
  }
  return SUCCESSFUL;
}

// Room IDs
string EntryParser::parse_roomid(string room) {
  size_t first_char = room.find_first_not_of('0');
  if (first_char == string::npos)
    return "0";
  else
    return room.substr(first_char);
}
int EntryParser::is_roomid_valid(string room) {
  // Must be only numeric
  if (room.find_first_not_of("0123456789") != string::npos)
    return 0;

  // Making sure it's not too big
  if (room.length() > MAX_ROOMID_LENGTH)
    return 0;

  // Making sure it's 32 bit non-negative number, max is 4294967292
  // If only zeros it's still non-negative
  size_t first_char = room.find_first_not_of('0');
  if (first_char == string::npos)
    return 1;

  // If not only zeros, make sure it's not too big
  string nozeros = room.substr(first_char);
  if (nozeros.length() > 10)
    return 0;
  if (nozeros.length() == 10) {
    if (nozeros.compare("4294967292") > 0)
      return 0;
  }

  // otherwise good
  return SUCCESSFUL;
}



