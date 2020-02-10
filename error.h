#include <iostream>
#include "errortype.h"

/*
 * I'm getting the most inconceivable issue with c++......
 *
 *
 * logappend.cc:34:29: error: invalid conversion from ‘int’ to ‘int* (*)()’ [-fpermissive]
               handleError2(2);
 * void handleError2(int errno) { }
 * 
 *
 * For some reason it keeps implicitly changing the parameter types to function pointers
 * Anyways I'm just going to give in for now
 *
 */

void handleIntegrityViolation() { cerr<<"integrity violation\n"; }
void handleInvalidInput() { cerr<<"invalid\n"; }
void handleUnknownError() { cerr<<"unknown error\n"; }


/*
void handleError(int __ignorethis__, int errno) {
  switch (errno) {
    case INVALID_INPUT:
      cerr<<"Invalid Input\n";break;
    case INTEGRITY_VIOLATION:
      cerr<<"Integrity violation\n";break;
    case UNKNOWN_ERROR:
      cerr<<"Unknown Error\n";break;
    default: // warning, accepts SUCCESS*
      cerr << "Unknown Error\n";
  }
}
*/
