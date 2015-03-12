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
# Date: 08/2012
# Homepage: Http://safetybits.net
# Email: chema@safetybits.net
# Twitter: @sch3m4
#

import os
import sys
import binascii

try:
    import hashlib
    import itertools
except ImportError, ie:
    print "[e] %s" % ie
    sys.exit(-1)


MIN_PATTERN = 3  # Min. pattern length
MAX_PATTERN = 9  # Max. pattern length


def crack_pattern(sha1sum):
    """
    http://forensics.spreitzenbarth.de/2012/02/28/cracking-the-pattern-lock-on-android/

    Java Source:
    ------------
    private static byte[] patternToHash(List pattern) {
        if (pattern == null) {
            return null;
        }

        final int patternSize = pattern.size();
        byte[] res = new byte[patternSize];
        for (int i = 0; i < patternSize; i++) {
            LockPatternView.Cell cell = pattern.get(i);
            res[i] = (byte) (cell.getRow() * 3 + cell.getColumn());
        }
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] hash = md.digest(res);
            return hash;
        } catch (NoSuchAlgorithmException nsa) {
            return res;
        }
    }
    """

    # for each length
    print "[+] Checking length:  " ,
    for i in range(MIN_PATTERN, MAX_PATTERN + 1):
        sys.stdout.write('\b')
        print "%d" % i ,
        sys.stdout.flush()
        # get all possible permutations
        perms = itertools.permutations([0, 1, 2, 3, 4, 5, 6, 7, 8], i)
        # for each permutation
        for item in perms:
            # build the pattern string
            pattern = ''.join(str(v) for v in item)
            # convert the pattern to hex (so the string '123' becomes '\x01\x02\x03')
            key = binascii.unhexlify(''.join('%02x' % (ord(c) - ord('0')) for c in pattern))
            # compute the hash for that key
            sha1 = hashlib.sha1(key).hexdigest()

            # pattern found
            if sha1 == sha1sum:
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

    print "[+] Gesture:\n"

    for i in range(0, 3):
        val = [None, None, None]
        for j in range(0, 3):
            val[j] = " " if gesture[i * 3 + j] is None else str(gesture[i * 3 + j])

        print '  -----  -----  -----'
        print '  | %s |  | %s |  | %s |  ' % (val[0], val[1], val[2])
        print '  -----  -----  -----'


if __name__ == "__main__":

    print ''
    print '################################'
    print '# Android Pattern Lock Cracker #'
    print '#             v0.1             #'
    print '# ---------------------------- #'
    print '#  Written by Chema Garcia     #'
    print '#     http://safetybits.net    #'
    print '#     chema@safetybits.net     #'
    print '#          @sch3m4             #'
    print '################################\n'

    print '[i] Taken from: http://forensics.spreitzenbarth.de/2012/02/28/cracking-the-pattern-lock-on-android/\n'

    # check parameters
    if len(sys.argv) != 2:
        print '[+] Usage: %s /path/to/gesture.key\n' % sys.argv[0]
        sys.exit(0)

    # check gesture.key file
    if not os.path.isfile(sys.argv[1]):
        print "[e] Cannot access to %s file\n" % sys.argv[1]
        sys.exit(-1)

    # load SHA1 hash from file
    f = open(sys.argv[1], 'rb')
    gest = f.read(hashlib.sha1().digest_size).encode('hex')
    f.close()

    # check hash length
    if len(gest) / 2 != hashlib.sha1().digest_size:
        print "[e] Invalid gesture file?\n"
        sys.exit(-2)

    # try to crack the pattern
    pattern = crack_pattern(gest)
    print ''

    if pattern is None:
        print "[:(] The pattern was not found..."
    else:
        print "[:D] The pattern has been FOUND!!! => %s\n" % pattern
        show_pattern(pattern)

    print ''
    sys.exit(0)
