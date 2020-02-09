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

    int compare_timestamp(string timestamp);
    int same_person(char name_type, string name);
    char get_event_type();
    char get_name_type();
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

