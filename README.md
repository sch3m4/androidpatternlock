## Android Pattern Lock Cracker
This is a little tool to crack the pattern lock on Android devices.


## How does the pattern lock works?

Really, the pattern lock is the SHA1 hash sequence of digits (0-8) with length from 3 (4 since Android 2.3.3) to 8.

Since Android does not allows the pattern to repeat "balls" and it does not use a salt when computing the SHA1 hash, it really takes a very short period of time to crack the hash and get the pattern.

The gesture board is a 3x3 matrix, and can be repressented as follows (each digit represents a "ball"):

    -------------------
    | 0 |  | 1 |  | 2 |
    -------------------
    | 3 |  | 4 |  | 5 |
    -------------------
    | 6 |  | 7 |  | 8 |
    -------------------

So if you set the pattern lock to 0 -> 1 -> 2 -> 5 -> 4, the SHA1 hash will be output of SHA1("\x00\x01\x02\x05\x04"), and that is the hash to be cracked by this tool.


## Where can I find the hash?

The hash is stored at "/data/system/gesture.key", and (From a rooted device) can be downloaded as follows:

    ~$ android-sdk-linux/platform-tools/adb pull /data/system/gesture.key
    0 KB/s (20 bytes in 0.071s)
    ~$ ls -l gesture.key
    -rw-r--r-- 1 sch3m4 sch3m4 20 ago 21 15:21 gesture.key
    ~$


## How does this tool works?

Let's see a basic output:

    ~$ python aplc.py 
    
    ################################
    # Android Pattern Lock Cracker #
    #             v0.2             #
    # ---------------------------- #
    #  Written by Chema Garcia     #
    #     http://safetybits.net    #
    #     chema@safetybits.net     #
    #          @sch3m4             #
    ################################
    
    [i] Taken from: http://forensics.spreitzenbarth.de/2012/02/28/cracking-the-pattern-lock-on-android/
    
    [+] Usage: aplc.py /path/to/gesture.key
    
    ~$ 

And now the output with a given gesture.key:

    ~$ python aplc.py gesture.sample.key 
    
    ################################
    # Android Pattern Lock Cracker #
    #             v0.2             #
    # ---------------------------- #
    #  Written by Chema Garcia     #
    #     http://safetybits.net    #
    #     chema@safetybits.net     #
    #          @sch3m4             #
    ################################
    
    [i] Taken from: http://forensics.spreitzenbarth.de/2012/02/28/cracking-the-pattern-lock-on-android/
    
    [:D] The pattern has been FOUND!!! => 210345876
    
    [+] Gesture:
    
    -----  -----  -----
    | 3 |  | 2 |  | 1 |  
    -----  -----  -----
    -----  -----  -----
    | 4 |  | 5 |  | 6 |  
    -----  -----  -----
    -----  -----  -----
    | 9 |  | 8 |  | 7 |  
    -----  -----  -----
    
    It took: 0.8151 seconds
    ~$


## Research & Credits

The information above has been taken from http://forensics.spreitzenbarth.de/2012/02/28/cracking-the-pattern-lock-on-android/


## There is nothing new

Of course this is not the first tool to crack the pattern lock, many Mobile Forensic Frameworks such as ADE deal with this task and much more, but this tool is mine ;-)
