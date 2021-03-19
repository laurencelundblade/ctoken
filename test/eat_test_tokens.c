/* This file is automatically generated from CBOR-diag format 
 * files by the script t2c.sh. 
 */


const unsigned char completely_empty_token[] = {
  0xa0
};

const unsigned char minimal_submod_token[] = {
  0xa1, 0x14, 0xa2, 0x66, 0x73, 0x75, 0x62, 0x6d, 0x6f, 0x64, 0xa0, 0x66,
  0x6e, 0x65, 0x73, 0x74, 0x65, 0x64, 0x6f, 0x7b, 0x22, 0x75, 0x65, 0x69,
  0x64, 0x22, 0x2c, 0x20, 0x22, 0x78, 0x79, 0x7a, 0x22, 0x7d
};

/*
The -76006 claim in the submodule "bad" has a simple value that is not
well formed.
{
    -76006: 10,
    -76000: {
        "jj": "{ uptime: 40}",
        "bad": {
            -76006: NOT-WELL FORMED simple(01)
        }
    }
}


*/

const char not_well_formed_submod[] = {
    0xa2, 0x3a, 0x00, 0x01, 0x28, 0xe5, 0x0a, 0x3a,
    0x00, 0x01, 0x28, 0xdf, 0xa2, 0x62, 0x6a, 0x6a,
    0x6d, 0x7b, 0x20, 0x75, 0x70, 0x74, 0x69, 0x6d,
    0x65, 0x3a, 0x20, 0x34, 0x30, 0x7d, 0x63, 0x62,
    0x61, 0x64, 0xf8, 0x01
};


/*
The submod section is 0x1c a n-w-f integer instead of a map
*/

const char not_well_formed_submod_section[] = {
    0xa1, 0x14a, 0x1c, 
};


const unsigned char some_submods_token[] = {
  0xa2, 0x3a, 0x00, 0x01, 0x24, 0xff, 0x44, 0x05, 0x08, 0x33, 0x99, 0x3a,
  0x00, 0x01, 0x28, 0xdf, 0xa1, 0x64, 0x73, 0x75, 0x62, 0x31, 0xa2, 0x3a,
  0x00, 0x01, 0x25, 0x00, 0x46, 0xa4, 0x68, 0x23, 0x99, 0x00, 0x01, 0x3a,
  0x00, 0x01, 0x28, 0xdf, 0xa2, 0x64, 0x6a, 0x73, 0x6f, 0x6e, 0x6f, 0x7b,
  0x20, 0x22, 0x75, 0x65, 0x69, 0x64, 0x22, 0x2c, 0x20, 0x22, 0x78, 0x79,
  0x7a, 0x22, 0x66, 0x73, 0x75, 0x62, 0x73, 0x75, 0x62, 0xa1, 0x3a, 0x00,
  0x01, 0x28, 0xe0, 0x46, 0x14, 0x18, 0x13, 0x19, 0x10, 0x01
};
