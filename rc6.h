/*
// RC6 & RC5 block cipher supporting unusual block sizes.
//
// Written by Ted Krovetz (ted@krovetz.net). Modified April 10, 2018.
//
// RC6 and RC5 were both patented and trademarked around the time
// each was invented. The author of this code believes the patents
// have expired and that the trademarks may still be in force. Seek
// legal advice before using RC5 or RC6 in any project.
//
// This is free and unencumbered software released into the public
// domain.
//
// Anyone is free to copy, modify, publish, use, compile, sell, or
// distribute this software, either in source code form or as a
// compiled binary, for any purpose, commercial or non-commercial,
// and by any means.
//
// In jurisdictions that recognize copyright laws, the author or
// authors of this software dedicate any and all copyright interest
// in the software to the public domain. We make this dedication for
// the benefit of the public at large and to the detriment of our
// heirs and successors. We intend this dedication to be an overt act
// of relinquishment in perpetuity of all present and future rights
// to this software under copyright law.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
// OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
// CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// For more information, please refer to <http://unlicense.org/>
*/

/* Some implementations place restrictions on how the following
 * functions are used. Some may place restrictions on w/r/b or
 * may require pointers to be aligned to (w/8)-byte boundaries
 * to avoid errors or improve performance. Consult your
 * implementation's documentation to see if this applies to you.
 */
 
/* rc6_setup returns 0 iff the implementation supports the actual
 * parameters supplied and rkey is filled successfully. rkey and
 * key should point to (w/8)*(2r+4) and b byte buffers respectively.
 */
int rc6_setup(void *rkey, int w, int r, int b, void *key);
void rc6_encrypt(void *rkey, int w, int r, void *pt, void *ct);
void rc6_decrypt(void *rkey, int w, int r, void *ct, void *pt);

/* rc5_setup returns 0 iff the implementation supports the actual
 * parameters supplied and rkey is filled successfully. rkey and
 * key should point to (w/8)*(2r+2) and b byte buffers respectively.
 */
int rc5_setup(void *rkey, int w, int r, int b, void *key);
void rc5_encrypt(void *rkey, int w, int r, void *pt, void *ct);
void rc5_decrypt(void *rkey, int w, int r, void *ct, void *pt);
