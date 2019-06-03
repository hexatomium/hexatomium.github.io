---
layout: post
title: How to find files by MD5 using YARA
comments: true
---


A little-known feature of Yara is its powerful hash module, which you can easily use to search your sample library (or any other directory) for a given MD5 hash. Here's how:

    // rule file (save as "md5_match.yara")

    import "hash" 
    
    rule REALNOTEPAD {
    
        meta:
            description = "REAL NOTEPAD"
    
        strings:
            $m0 = { 4D 5A } // wide ascii
    
        condition:
            $m0 at 0   and 
            filesize < 350KB and
            hash.md5(0, filesize) == "e30299799c4ece3b53f4a7b8897a35b6"     
    }
	
	
Now use the following command to search the current path for hash:

    yara -f md5_match.yara .


But how to search for a whole set of hashes rather than just one? Well, it's just as simple:

    import "hash" 
    
    rule MSFT_WHITELIST {
    
        meta:
            description = "Genuine Microsoft"
    
        condition:
            uint16(0) == 0x5A4D and
            filesize < 1MB and
            hash.md5(0, filesize) == "e30299799c4ece3b53f4a7b8897a35b6"   or  
            hash.md5(0, filesize) == "897a35b6e30299799c4ece3b53f4a7b8"   or 
            hash.md5(0, filesize) == "6462c8c3b51e302997897a35ba7b8846"   or 
            hash.md5(0, filesize) == "e30f4a7b8897219799c4ece3b4ece377"   or 
            hash.md5(0, filesize) == "9c4ece3b53f4a7b8897e3063379a35b6"   or  
            hash.md5(0, filesize) == "a45f7fcc14b9b6462c8c3b51623c4301"     
    }
