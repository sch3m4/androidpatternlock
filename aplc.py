#!/usr/bin/env python
#
#  Copyright (c) 2012, Chema Garcia
#  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or
#  without modification, are permitted provided that the following
#  conditions are met:
#
#     * Redistributions of source code must retain the above
#       copyright notice, this list of conditions and the following
#       disclaimer.
#
#     * Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
#     * Neither the name of the SafetyBits nor the names of its contributors may
#       be used to endorse or promote products derived from this software
#       without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
#  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
#  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
#  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
#  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
#  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
#  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
#  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
#  POSSIBILITY OF SUCH DAMAGE.
#
# Author: Chema Garcia
# Date: 03/2015
# Homepage: http://safetybits.net
# Email: chema@safetybits.net
# Twitter: @sch3m4
#

import os
import sys
import time
import multiprocessing
import hashlib
import binascii
import itertools

MATRIX_SIZE = [3,3]
MAX_LEN = MATRIX_SIZE[0]*MATRIX_SIZE[1]
MIN_POSITIONS_NUMBER = 3
FOUND = multiprocessing.Event()

def lookup(param):
    global FOUND
    lenhash = param[0]
    target = param[1]
    positions = param[2]

    if FOUND.is_set() is True:
        return None

    # get all possible permutations
    perms = itertools.permutations(positions, lenhash)
    # for each permutation
    for item in perms:
        # build the pattern string
        if FOUND.is_set() is True:
            return None
        pattern = ''.join(str(v) for v in item)
        # convert the pattern to hex (so the string '123' becomes '\x01\x02\x03')
        key = binascii.unhexlify(''.join('%02x' % (ord(c) - ord('0')) for c in pattern))
        # compute the hash for that key
        sha1 = hashlib.sha1(key).hexdigest()
        # pattern found
        if sha1 == target:
            FOUND.set()
            return pattern
    # pattern not found
    return None

def show_pattern(pattern):
    """
    Shows the pattern "graphically"
    """

    gesture = [None, None, None, None, None, None, None, None, None]

    cont = 1
    for i in pattern:
        gesture[int(i)] = cont
        cont += 1

    print ("[+] Gesture:\n")
    for i in range(0, 3):
        val = [None, None, None]
        for j in range(0, 3):
            val[j] = " " if gesture[i * 3 + j] is None else str(gesture[i * 3 + j])

        print ('  -----  -----  -----')
        print ('  | %s |  | %s |  | %s |  ' % (val[0], val[1], val[2]))
        print ('  -----  -----  -----')

def crack(target_hash):
    ncores = multiprocessing.cpu_count()
    pool = multiprocessing.Pool(ncores)
    # generates the matrix positions IDs
    positions = [i for i in range(MAX_LEN)]
    
    # sets the length for each worker
    generate_worker_params = lambda x: [x, target_hash, positions]
    params = [generate_worker_params(i) for i in range(MIN_POSITIONS_NUMBER, MAX_LEN + 1)]
    
    result = pool.map(lookup,params)
    pool.close()
    pool.join()
    
    ret = None
    for r in result:
        if r is not None:
            ret = r
            break
    return ret

def main():
    print ('')
    print ('################################')
    print ('# Android Pattern Lock Cracker #')
    print ('#             v0.2             #')
    print ('# ---------------------------- #')
    print ('#  Written by Chema Garcia     #')
    print ('#     http://safetybits.net    #')
    print ('#     chema@safetybits.net     #')
    print ('#          @sch3m4             #')
    print ('################################\n')

    print ('[i] Taken from: http://forensics.spreitzenbarth.de/2012/02/28/cracking-the-pattern-lock-on-android/\n')
    
    # check parameters
    if len(sys.argv) != 2:
        print ('[+] Usage: %s /path/to/gesture.key\n' % sys.argv[0])
        sys.exit(0)
    
    # check gesture.key file
    if not os.path.isfile(sys.argv[1]):
        print ("[e] Cannot access to %s file\n" % sys.argv[1])
        sys.exit(-1)
        
    # load SHA1 hash from file
    f = open(sys.argv[1], 'rb')
    gest = f.read(hashlib.sha1().digest_size).hex()
    f.close()

    # check hash length
    if len(gest) / 2 != hashlib.sha1().digest_size:
        print ("[e] Invalid gesture file?\n")
        sys.exit(-2)

    # try to crack the pattern
    t0 = time.time()
    pattern = crack(gest)
    t1 = time.time()

    if pattern is None:
        print ("[:(] The pattern was not found...")
        rcode = -1
    else:
        print ("[:D] The pattern has been FOUND!!! => %s\n" % pattern)
        show_pattern(pattern)
        print ("")
        print ("It took: %.4f seconds" % (t1-t0))
        rcode = 0

    sys.exit(rcode)

if __name__ == "__main__":
    main()
    
