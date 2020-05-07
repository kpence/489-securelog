#ifndef ENTRYPARSER_H_
#define ENTRYPARSER_H_
/*
MIT License

Copyright (c) 2020 Kyle Pence

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
#include <string>

using namespace std;

/*
 *
 * The maximum record size is 158 (we could increase that by N*16 if needed)
 *
 * The password can be at most 16
 *
 * Examples of unparsed records
 *  token-3ADSamuel-R1
 *  token-3LDSamuel-R1
 *
 *
 * I'll have the logread and logappend programs validate their input, but they'll use this program to check:
 *
 * Doctor/Nurse Name
 * Filename
 * Validate the Batch file (cannot contain -b)
 * Key Token
 * Timestamp
 * Room ID
 *
*/

//
//
// the room names and stuff


// For each field:
// 1. Parsers from Input Fields
// 2. Extracters from Record
// 3. Extracters from program input
// 4. Translators to Record
// 5. Validators of Input Fields
// 6. Validate program input
// 7. Parse program input
//
//
// Fields:
// 1. Key Token
// 2. Time Stamp
// 3. Room Number
// 4. Arrival/Departure
// 5. Filenames
// 6. Filenames

class EntryParser {
  public:
    static int is_name_valid(string name); // alphabetic
    static int is_name_type_valid(char nt); // alphabetic
    static int is_event_type_valid(char et); // alphabetic
    static int is_token_valid(string token); //alphanumeric
    static int is_filepath_valid(string path);
    static int is_timestamp_valid(string path);

    // Room IDs
    static int is_roomid_valid(string room); // numeric
    static string parse_roomid(string room);

    // Extraction stuff
    static string make_record(string token, string timestamp, char event_type, char name_type, string name, string roomid);

    int load_record(string rcd);
    int is_record_valid();

    static int compare_timestamps(string timestamp1, string timestamp2);
    int compare_timestamp(string timestamp);
    int same_person(char name_type, string name);
    char get_event_type();
    char get_name_type();
    string get_name();
    string get_roomid();
    string get_timestamp();

  protected:
  private:
    int is_valid;
    char _event_type; // arrival/departure
    char _name_type; // doctor/nurse
    string _timestamp;
    //string _token;
    string _name;
    string _roomid;
    //string _logfile;
};


#endif // ENTRYPARSER_H_
