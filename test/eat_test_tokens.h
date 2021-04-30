/* This file is automatically generated from CBOR-diag format 
 * files by the script t2c.sh. 
 */


/* Useful macro to convert test to a UsefulBuf */
#define TEST2UB(test_name) ((struct q_useful_buf_c){test_name##_bytes, test_name##_size})

/* A completely empty UCCS token. */
/* It has no tags and no claims. */
extern const unsigned char completely_empty_bytes[];
#define completely_empty_size 1


extern const unsigned char some_submods_bytes[];
#define some_submods_size 82


/* An invalid HW Board version claim -- bstr instead of tstr */
extern const unsigned char hw_version_invalid_board_version_bytes[];
#define hw_version_invalid_board_version_size 16


/* An invalid HW Chip version claim; float instead of tstr */
extern const unsigned char hw_version_invalid_chip_version_bytes[];
#define hw_version_invalid_chip_version_size 21


/* An invalid HW device version claim; array instead of tstr */
extern const unsigned char hw_version_invalid_device_version_bytes[];
#define hw_version_invalid_device_version_size 16


/* EAN HW version is a byte string rather than a text string */
extern const unsigned char hw_version_invalid_ean_board_version_bytes[];
#define hw_version_invalid_ean_board_version_size 14


/* The value of the hw version is 0x1f an integer with an indefinite */
/* length. This not-well-formed CBOR that should be caught at the lowest */
/* layer in the decoder and bubbled up to some top-level error. This is */
/* to test that path of bubbling up errors. There are lots of other ways */
/* that CBOR can be invalid here. This is just one to test the error */
/* propagation. */
extern const unsigned char hw_version_invalid_nwf_bytes[];
#define hw_version_invalid_nwf_size        7

/* A valid HW Board version claim */
extern const unsigned char hw_version_invalid_version_scheme_bytes[];
#define hw_version_invalid_version_scheme_size 18


/* Version scheme is invalid because it is 'true' rather than an integer */
extern const unsigned char hw_version_invalid_version_scheme_type_bytes[];
#define hw_version_invalid_version_scheme_type_size 18


/* Version scheme is -257. It should be greater than -256 */
extern const unsigned char hw_version_invalid_version_scheme_value_bytes[];
#define hw_version_invalid_version_scheme_value_size 20


/* A valid HW Board version claim */
extern const unsigned char hw_version_valid_board_version_bytes[];
#define hw_version_valid_board_version_size 18


/* A valid HW Chip version claim */
extern const unsigned char hw_version_valid_chip_version_bytes[];
#define hw_version_valid_chip_version_size 18


/* A valid HW device version claim */
extern const unsigned char hw_version_valid_device_version_bytes[];
#define hw_version_valid_device_version_size 19


/* A valid HW Board EAN version claim */
extern const unsigned char hw_version_valid_ean_board_version_bytes[];
#define hw_version_valid_ean_board_version_size 20


/* A valid HW Chip EAN version claim */
extern const unsigned char hw_version_valid_ean_chip_version_bytes[];
#define hw_version_valid_ean_chip_version_size 20


/* A valid HW device EAN version claim */
extern const unsigned char hw_version_valid_ean_device_version_bytes[];
#define hw_version_valid_ean_device_version_size 20


/* There ae two claims with the profile label of 18 */
extern const unsigned char profile_invalid_dup_bytes[];
#define profile_invalid_dup_size       23

/* The value of the profile is 0x1f an integer with an indefinite */
/* length. This not-well-formed CBOR that should be caught at the lowest */
/* layer in the decoder and bubbled up to some top-level error. This is */
/* to test that path of bubbling up errors. There are lots of other ways */
/* that CBOR can be invalid here. This is just one to test the error */
/* propagation. */
extern const unsigned char profile_invalid_nwf_bytes[];
#define profile_invalid_nwf_size        3

/* A profile that is invalid because it is the wrong type */
extern const unsigned char profile_invalid_type_bytes[];
#define profile_invalid_type_size 3


/* A valid URI-format profile claim */
/* 1.3.6.1.4.1.90000.4, a somewhat randomly picked OID for test prupose only */
extern const unsigned char profile_valid_oid_bytes[];
#define profile_valid_oid_size 14


/* A valid URI-format profile claim */
extern const unsigned char profile_valid_uri_bytes[];
#define profile_valid_uri_size 28


/* This is an invalid SW components claim because the measure value is */
/* a text string rather than a byte string.                            */
extern const unsigned char psa_swcomponents_invalid_measurement_value_bytes[];
#define psa_swcomponents_invalid_measurement_value_size 60


/* This is an invalid SW components because it is missing the array level. */
extern const unsigned char psa_swcomponents_invalid_missing_array_bytes[];
#define psa_swcomponents_invalid_missing_array_size 81


/* This is invalid because it has both a sw components claim and the    */
/* indictor for no sw components.                                       */
extern const unsigned char psa_swcomponents_invalid_no_and_claim_bytes[];
#define psa_swcomponents_invalid_no_and_claim_size 88


/* This is an invalid SW components claim because it is missing the */
/* measurement value.                                               */
extern const unsigned char psa_swcomponents_invalid_no_measurement_bytes[];
#define psa_swcomponents_invalid_no_measurement_size 77


/* This is invalid because it has neither a sw components claim nor the    */
/* indictor for no sw components.  It is just an empt token.               */
extern const unsigned char psa_swcomponents_invalid_no_nor_claim_bytes[];
#define psa_swcomponents_invalid_no_nor_claim_size 1


/* This is an invalid SW components claim because it is missing the signer_id */
extern const unsigned char psa_swcomponents_invalid_no_signer_id_bytes[];
#define psa_swcomponents_invalid_no_signer_id_size 77


/* The no-sw-components claim is a boolean rather than an integer */
extern const unsigned char psa_swcomponents_invalid_no_type_bytes[];
#define psa_swcomponents_invalid_no_type_size 7


/* The value of the no sw components claim is 2 rather than 1 */
extern const unsigned char psa_swcomponents_invalid_no_value_bytes[];
#define psa_swcomponents_invalid_no_value_size 7


/* The value of the signer ID in sw components claim is 0x1f, an */
/* integer with an indefinite length. This not-well-formed CBOR */
/* should be caught at the lowest layer in the decoder and bubbled up */
/* to some top-level error. This is to test that path of bubbling up */
/* errors. There are lots of other ways that CBOR can be invalid */
/* here. This is just one to test the error propagation. */
extern const unsigned char psa_swcomponents_invalid_nwf_signer_id_bytes[];
#define psa_swcomponents_invalid_nwf_signer_id_size       50

/* The value of the sw components claim is 0x1f, an integer with an */
/* indefinite length. This not-well-formed CBOR should be caught */
/* at the lowest layer in the decoder and bubbled up to some top-level */
/* error. This is to test that path of bubbling up errors. There are */
/* lots of other ways that CBOR can be invalid here. This is just one */
/* to test the error propagation. */
extern const unsigned char psa_swcomponents_invalid_nwf_swc_bytes[];
#define psa_swcomponents_invalid_nwf_swc_size        7

/* This is an invalid SW components claim because the signer ID is an */
/* integer rather than a byte string. */
extern const unsigned char psa_swcomponents_invalid_signer_id_bytes[];
#define psa_swcomponents_invalid_signer_id_size 50


/* A basic valid PSA SW components claim. It has two SW components.     */
/*                                                                      */
/* This is just for testing the SW components claim in isolation.  When */
/* taken as a whole, this is actual an invalid PSA token because it is  */
/* missing claims that PSA token requires in all tokens.                */
extern const unsigned char psa_swcomponents_valid_basic_bytes[];
#define psa_swcomponents_valid_basic_size 187


/* The only valid way to have no SW components.  This is just for testing */
/* the no SW components claim in isolation.  When taken as a whole, this  */
/* is actual an invalid PSA token because it is missing required claims   */
extern const unsigned char psa_swcomponents_valid_no_bytes[];
#define psa_swcomponents_valid_no_size 7


/* The secboot claim with a value of null which is not allowed. There are */
/*  many ways secboot can be invalid. This is just one. It is picked because */
/* it is very similar to the value of true and false, but still invalid. */
extern const unsigned char secboot_invalid1_bytes[];
#define secboot_invalid1_size 3


/* A secboot claim with a value that is an integer which is not allowed. */
/* There are  many ways secboot can be invalid. This is just one. */
/* It is picked because some might consider the integer 0 to be false. */
extern const unsigned char secboot_invalid2_bytes[];
#define secboot_invalid2_size 3


/* The value of secboot is 0x1f an integer with an indefinite */
/* length. This not-well-formed CBOR that should be caught at the lowest */
/* layer in the decoder and bubbled up to some top-level error. This is */
/* to test that path of bubbling up errors. There are lots of other ways */
/* that CBOR can be invalid here. This is just one to test the error */
/* propagation. */
extern const unsigned char secboot_invalid3_bytes[];
#define secboot_invalid3_size        3

/* A secboot claim with value the text "false". It is supposed to be a */
/* true Boolean value, not a text string. */
extern const unsigned char secboot_invalid4_bytes[];
#define secboot_invalid4_size 8


/* A secboot claim with value the text "truee". It is supposed to be a */
/* true Boolean value, not a text string. */
extern const unsigned char secboot_invalid5_bytes[];
#define secboot_invalid5_size 7


/* A valid secboot claim with a value of true */
/* The expected result from decoding this the value true */
extern const unsigned char secboot_valid1_bytes[];
#define secboot_valid1_size 3


/* A valid secboot claim with a value of false */
/* The expected results from decoding this is the value false */
extern const unsigned char secboot_valid2_bytes[];
#define secboot_valid2_size 3


/* This has two submods labeled "submod" and two nested tokens labeled */
/* "nested".  A map with two items with the same label is considered */
/* invalid in CBOR. This is good for testing duplicate detection. A */
/* decoder should error out on this. */
/* The first occurance of "submod" */
/* The first occurance of "nested" */
/* The second occurance of "submod" */
/* The second occurance of "nested" */
extern const unsigned char submods_invalid_duplicate_bytes[];
#define submods_invalid_duplicate_size       73

/* Both types of submod is incorrectly an array, rather than a map and string */
extern const unsigned char submods_invalid_is_array_bytes[];
#define submods_invalid_is_array_size 19


/* This has a submod section with two simple submodules */
/* One is empty and the other is a nested JSON token */
extern const unsigned char submods_invalid_non_string_label_bytes[];
#define submods_invalid_non_string_label_size 28


/* The submod section is an integer with an indefinite length instead */
/* of a map.  Such an integer is not well formed (and not really an */
/* integer). Decoders should error out on this. */
extern const unsigned char submods_invalid_nwf_section_bytes[];
#define submods_invalid_nwf_section_size        3

/* The submod named "submod" is an integer with an indefinite length */
/* instead of a map.  Such an integer is not well formed (and not */
/* really an integer). Decoders should error out on this. */
extern const unsigned char submods_invalid_nwf_sumbod_bytes[];
#define submods_invalid_nwf_sumbod_size       11

/* Five nested levels of submodules with a distinct nonce at each level. */
/* Each level also has a nested token. TODO: make the nested tokens real */
/* A good test to perform on this is to traverse the whole tree getting */
/* the nonces and the nested tokens and validating their values. */
/* Note that nested tokens must be signed. They can't be UCCS per */
/* the EAT standard, so when this is filled in they will be larger */
/* and not so straight forward to validate */
extern const unsigned char submods_valid_deeply_nested_bytes[];
#define submods_valid_deeply_nested_size 130


/* An empty submodule (which is of course legal) */
extern const unsigned char submods_valid_empty_bytes[];
#define submods_valid_empty_size 11


/* This has a submod section with two simple submodules */
/* One is empty and the other is a nested JSON token */
extern const unsigned char submods_valid_minimal_bytes[];
#define submods_valid_minimal_size 40


