#ifndef ERROR_H_
#define ERROR_H_
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
#include <iostream>
#include "./errortype.h"

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

#endif // ERROR_H_
