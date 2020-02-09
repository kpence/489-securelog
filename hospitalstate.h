#include <map>
#include <vector>
#include <string>
#include <utility>
#include <iostream>

#include "EntryParser.h"
#include "FileReaderWriter.h"
#include "error.h"

#define ERROR_EXIT_CODE 255

using namespace std;

// This file contains a function that determines the state of the hospital, or if specified the state of a single doctor, and if specified prints the state out
//

/*
 * Takes:
 * 1. vector of person_states, person_state is a struct (room_in, touched, in_hospital)
 * 2. vector of pair<char, string> (the pair<char,string> is { name_type, name }, which indicates the persons to track their state
 */

struct person_state {
  int in_hospital;
  int touched;
  string room_in;
};

int get_hospital_state(FileReaderWriter& frw, EntryParser& p,
    map<pair<char,string>,person_state>& person_states,
    string& rooms, int track_rooms = 0);

int get_person_state(FileReaderWriter& frw, EntryParser& p, int& in_hospital, int& touched, string& room_in, char name_type, string name) {
  map<pair<char,string>,person_state> ps;
  auto pair = make_pair(name_type,name);
  ps[pair] = person_state({in_hospital, touched, room_in});
  string emptystr;
  get_hospital_state(frw, p, ps, emptystr);

  auto person = ps[pair];
  in_hospital = person.in_hospital;
  touched = person.touched;
  room_in = person.room_in;
  return 1;
}

// The map will be empty if the caller of the function wants to grab all names
int get_hospital_state(FileReaderWriter& frw, EntryParser& p, map<pair<char,string>,person_state>& person_states, string& rooms, int track_rooms) {
  // Check if you need to track the rooms
  rooms.clear();

  // Now iterate through the records
  int i = 1, in_hospital = 0, touched = 0;
  string room_in, s;

  for (auto& ps : person_states) {
    ps.second.in_hospital = 0;
    ps.second.touched = 0;
    ps.second.room_in = "";
  }

  string timestamp = "0";

  while (i < frw.get_num_chunks()) {
    i = frw.get_next_record_string(s, i);
    if (s.empty()) {
      handleIntegrityViolation();
      exit(ERROR_EXIT_CODE);
    }

    // Load to record parser
    p.load_record(s);
    if (!p.is_record_valid()) {
      handleIntegrityViolation();
      exit(ERROR_EXIT_CODE);
    }

    // Make sure the timestamp is valid or else Integrity Violation
    if (p.compare_timestamp(timestamp) != 0) { // Record timestamp must be larger than previously read one
      handleIntegrityViolation();
      exit(ERROR_EXIT_CODE);
    }
    timestamp = p.get_timestamp();

    // Check if name of record matches any in map OR if map is empty (which is defined to grab every person)
    int match = 0;
    char name_type;
    string name;

    if (!person_states.empty()) {
      for (auto& ps : person_states) {
        name_type = ps.first.first;
        name = ps.first.second;
        if (p.same_person(name_type, name)!=0) {
          match = 1;break;
        }
      }
      if (match==0)
        continue;
    }


    // Set the in_hospital and touched values
    if (person_states.count(make_pair(name_type, name)) == 0) {
      person_states[make_pair(name_type,name)] = {0, 1, ""};
      in_hospital = 0;
      room_in = "";
    }
    else {
      person_states[make_pair(name_type,name)].touched = 1;
      in_hospital = person_states[make_pair(name_type,name)].in_hospital;
      room_in = person_states[make_pair(name_type,name)].room_in;
    }

    // check with parse whether it's an arrival or departure to/from room/hospital, and keep track if that's logical in this scope
    if (p.get_event_type() == 'A' && p.get_roomid().empty()) {
      if (in_hospital != 0) {
        handleIntegrityViolation();
        exit(ERROR_EXIT_CODE);
      }
      in_hospital = 1;
    }
    else if (p.get_event_type() == 'L' && p.get_roomid().empty()) {
      if (in_hospital == 0 || !room_in.empty()) {
        handleIntegrityViolation();
        exit(ERROR_EXIT_CODE);
      }
      in_hospital = 0;
    }
    else if (p.get_event_type() == 'A' && !p.get_roomid().empty()) {
      if (in_hospital == 0 || !room_in.empty()) {
        handleIntegrityViolation();
        exit(ERROR_EXIT_CODE);
      }
      room_in = p.get_roomid();
      // If tracking rooms, append this room to the string
      if (track_rooms == 1) {
        rooms += room_in;
        rooms += ",";
      }
    }
    else if (p.get_event_type() == 'L' && !p.get_roomid().empty()) {
      if (in_hospital == 0 || room_in.empty()) {
        handleIntegrityViolation();
        exit(ERROR_EXIT_CODE);
      }
      // Make sure leaving the correct room
      if (in_hospital == 0 || room_in.compare(p.get_roomid())!=0) {
        handleIntegrityViolation();
        exit(ERROR_EXIT_CODE);
      }
      room_in.clear();
    }

    // Also this shouldn't be possible (throw error just in case)
    if (!room_in.empty() && in_hospital == 0) {
      handleIntegrityViolation();
      exit(ERROR_EXIT_CODE);
    }

    // Set the values of the person_state back into the map.
    person_states[make_pair(name_type,name)] = {in_hospital, 1, room_in};
  }

  // If tracking rooms, remove the trailing comma at the end
  rooms.pop_back();
  return 1;
}
