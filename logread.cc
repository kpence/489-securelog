#include <iostream>
#include <unistd.h>
#include <string>
#include <string.h>
#include <map>
#include <utility>
#include <queue>
#include <functional>

//#include "FileReaderWriter.h"
//#include "error.h"
//#include "EntryParser.h"
#include "hospitalstate.h"

#define ERROR_EXIT_CODE 255

using namespace std;

int main(int argc, char** argv) {
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

  FileReaderWriter frw(logfile, token);
  int status = frw.init();
  if (status == INTEGRITY_VIOLATION) {
		handleIntegrityViolation();
		exit(ERROR_EXIT_CODE);
  }
	
  EntryParser p;

  // This code prints out the rooms of name_type, name
  if (read_type == 'R') {
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
  }
  else
  {
    map<pair<char,string>,person_state> person_states;
    string empty_str;
    get_hospital_state(frw, p, person_states, empty_str, 0);

    // Get list of doctors and nurses currently in hospital
    // I don't know why typedef isn't working
    priority_queue<pair<char,string>,vector<pair<char,string>>,greater<pair<char,string>>> pq;

    // room_id => list of person's name
    // convert room_ids to long ints with stol
    map<long int,priority_queue<string,vector<string>,greater<string>>> persons_in_room;

    long int ts_li;
    for (auto m : person_states) {
      if (m.second.in_hospital==1) {
        //cout << "Person still in hospital: " << m.first.second << endl;
        pq.push(m.first);
        if (!m.second.room_in.empty()) {
          ts_li = stol(m.second.room_in);

          // Push the name of person to the priority queue for this room
          if (persons_in_room.count(ts_li) == 0) {
            persons_in_room[ts_li] = priority_queue<string,vector<string>,greater<string>>();
            persons_in_room[ts_li].push(m.first.second);
          }
          else
            persons_in_room[ts_li].push(m.first.second);
        }
      }
    }

    // First print the names of doctors and nurses in hospital
    // doctors
    int nl = 0, fd = 0, fn = 0;
    while (!pq.empty()) {
      if (pq.top().first=='D') {
        if (fd==0) fd = 1;
        else cout<<", ";
        s = pq.top().second;
        cout << s;pq.pop();
        nl = 1;
      }
      if (pq.top().first=='N') {
        //cout << "\nNurses"<<nl <<"\n";
        if (nl == 1) { nl = 0; cout<<endl; }
        if (fn==0) fn = 1;
        else cout<<", ";
        s = pq.top().second;
        cout << s;pq.pop();
      }
    }

    cout<<endl;

    // Now for each room with people in it, in order, print all the people
    priority_queue<string,vector<string>,greater<string>> pq2;
    for (auto it = persons_in_room.begin(); it != persons_in_room.end(); it++) {
      // Until the pq is empty, print and pop
      cout << it->first << ": ";
      pq2 = it->second;
      fd = 0;
      while (!pq2.empty()) {
        if (fd==0) fd = 1;
        else cout << ", ";
        cout << pq2.top();pq2.pop();
      }
      cout<<endl;
    }
  }
#ifdef DEV_MODE
	// Iterate through the records
	int i = 1;
	while (i < frw.get_num_chunks()) {
		i = frw.get_next_record_string(s, i);
		if (i == 0 || s.empty()) {
			handleIntegrityViolation();
			exit(ERROR_EXIT_CODE);
		}
		cout << s << endl;
	}
#endif

  return 0;
}
