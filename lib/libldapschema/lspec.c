
/*
 *  LDAP Utilities
 *  Copyright (C) 2012, 2019 David M. Syzdek <david@syzdek.net>.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are
 *  met:
 *
 *     1. Redistributions of source code must retain the above copyright
 *        notice, this list of conditions and the following disclaimer.
 *
 *     2. Redistributions in binary form must reproduce the above copyright
 *        notice, this list of conditions and the following disclaimer in the
 *        documentation and/or other materials provided with the distribution.
 *
 *     3. Neither the name of the copyright holder nor the names of its
 *        contributors may be used to endorse or promote products derived from
 *        this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 *  IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 *  THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 *  PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 *  CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 *  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 *  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 *  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/**
 *   @file src/ldapschema/lerror.c  contains error functions and variables
 */
#define _LIB_LIBLDAPSCHEMA_LSPEC_C 1
#include "lspec.h"

///////////////
//           //
//  Headers  //
//           //
///////////////
#pragma mark - Headers

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>


/////////////////
//             //
//  Variables  //
//             //
/////////////////
#pragma mark - Variables

// RFC 4530                     LDAP entryUUID                    June 2006
//
// 4.3.2. Syntax Object Identifiers
//
//    Syntaxes for use with LDAP are named by OBJECT IDENTIFIERs, which are
//    dotted-decimal strings.  These are not intended to be displayed to
//    users.
//
//    noidlen = numericoid [ "{" len "}" ]
//
//    len     = numericstring
//
//    The following table lists some of the syntaxes that have been defined
//    for LDAP thus far.  The H-R column suggests whether a value in that
//    syntax would likely be a human readable string.  Clients and servers
//    need not implement all the syntaxes listed here, and MAY implement
//    other syntaxes.
//
//    Other documents may define additional syntaxes.  However, the
//    definition of additional arbitrary syntaxes is strongly deprecated
//    since it will hinder interoperability: today's client and server
//    implementations generally do not have the ability to dynamically
//    recognize new syntaxes.  In most cases attributes will be defined
//    with the syntax for directory strings.
//
//    Value being represented        H-R OBJECT IDENTIFIER
//    =================================================================
//    ACI Item                        N  1.3.6.1.4.1.1466.115.121.1.1
//    Access Point                    Y  1.3.6.1.4.1.1466.115.121.1.2
//    Attribute Type Description      Y  1.3.6.1.4.1.1466.115.121.1.3
//    Audio                           N  1.3.6.1.4.1.1466.115.121.1.4
//    Binary                          N  1.3.6.1.4.1.1466.115.121.1.5
//    Bit String                      Y  1.3.6.1.4.1.1466.115.121.1.6
//    Boolean                         Y  1.3.6.1.4.1.1466.115.121.1.7
//    Certificate                     N  1.3.6.1.4.1.1466.115.121.1.8
//    Certificate List                N  1.3.6.1.4.1.1466.115.121.1.9
//    Certificate Pair                N  1.3.6.1.4.1.1466.115.121.1.10
//    Country String                  Y  1.3.6.1.4.1.1466.115.121.1.11
//    DN                              Y  1.3.6.1.4.1.1466.115.121.1.12
//    Data Quality Syntax             Y  1.3.6.1.4.1.1466.115.121.1.13
//    Delivery Method                 Y  1.3.6.1.4.1.1466.115.121.1.14
//    Directory String                Y  1.3.6.1.4.1.1466.115.121.1.15
//    DIT Content Rule Description    Y  1.3.6.1.4.1.1466.115.121.1.16
//    DIT Structure Rule Description  Y  1.3.6.1.4.1.1466.115.121.1.17
//    DL Submit Permission            Y  1.3.6.1.4.1.1466.115.121.1.18
//    DSA Quality Syntax              Y  1.3.6.1.4.1.1466.115.121.1.19
//    DSE Type                        Y  1.3.6.1.4.1.1466.115.121.1.20
//    Enhanced Guide                  Y  1.3.6.1.4.1.1466.115.121.1.21
//    Facsimile Telephone Number      Y  1.3.6.1.4.1.1466.115.121.1.22
//    Fax                             N  1.3.6.1.4.1.1466.115.121.1.23
//    Generalized Time                Y  1.3.6.1.4.1.1466.115.121.1.24
//    Guide                           Y  1.3.6.1.4.1.1466.115.121.1.25
//    IA5 String                      Y  1.3.6.1.4.1.1466.115.121.1.26
//    INTEGER                         Y  1.3.6.1.4.1.1466.115.121.1.27
//    JPEG                            N  1.3.6.1.4.1.1466.115.121.1.28
//    LDAP Syntax Description         Y  1.3.6.1.4.1.1466.115.121.1.54
//    LDAP Schema Definition          Y  1.3.6.1.4.1.1466.115.121.1.56
//    LDAP Schema Description         Y  1.3.6.1.4.1.1466.115.121.1.57
//    Master And Shadow Access Points Y  1.3.6.1.4.1.1466.115.121.1.29
//    Matching Rule Description       Y  1.3.6.1.4.1.1466.115.121.1.30
//    Matching Rule Use Description   Y  1.3.6.1.4.1.1466.115.121.1.31
//    Mail Preference                 Y  1.3.6.1.4.1.1466.115.121.1.32
//    MHS OR Address                  Y  1.3.6.1.4.1.1466.115.121.1.33
//    Modify Rights                   Y  1.3.6.1.4.1.1466.115.121.1.55
//    Name And Optional UID           Y  1.3.6.1.4.1.1466.115.121.1.34
//    Name Form Description           Y  1.3.6.1.4.1.1466.115.121.1.35
//    Numeric String                  Y  1.3.6.1.4.1.1466.115.121.1.36
//    Object Class Description        Y  1.3.6.1.4.1.1466.115.121.1.37
//    Octet String                    Y  1.3.6.1.4.1.1466.115.121.1.40
//    OID                             Y  1.3.6.1.4.1.1466.115.121.1.38
//    Other Mailbox                   Y  1.3.6.1.4.1.1466.115.121.1.39
//    Postal Address                  Y  1.3.6.1.4.1.1466.115.121.1.41
//    Protocol Information            Y  1.3.6.1.4.1.1466.115.121.1.42
//    Presentation Address            Y  1.3.6.1.4.1.1466.115.121.1.43
//    Printable String                Y  1.3.6.1.4.1.1466.115.121.1.44
//    Substring Assertion             Y  1.3.6.1.4.1.1466.115.121.1.58
//    Subtree Specification           Y  1.3.6.1.4.1.1466.115.121.1.45
//    Supplier Information            Y  1.3.6.1.4.1.1466.115.121.1.46
//    Supplier Or Consumer            Y  1.3.6.1.4.1.1466.115.121.1.47
//    Supplier And Consumer           Y  1.3.6.1.4.1.1466.115.121.1.48
//    Supported Algorithm             N  1.3.6.1.4.1.1466.115.121.1.49
//    Telephone Number                Y  1.3.6.1.4.1.1466.115.121.1.50
//    Teletex Terminal Identifier     Y  1.3.6.1.4.1.1466.115.121.1.51
//    Telex Number                    Y  1.3.6.1.4.1.1466.115.121.1.52
//    UTC Time                        Y  1.3.6.1.4.1.1466.115.121.1.53
//
//    A suggested minimum upper bound on the number of characters in value
//    with a string-based syntax, or the number of bytes in a value for all
//    other syntaxes, may be indicated by appending this bound count inside
//    of curly braces following the syntax name's OBJECT IDENTIFIER in an
//    Attribute Type Description.  This bound is not part of the syntax
//    name itself.  For instance, "1.3.6.4.1.1466.0{64}" suggests that
//    server implementations should allow a string to be 64 characters
//    long, although they may allow longer strings.  Note that a single
//    character of the Directory String syntax may be encoded in more than
//    one byte since UTF-8 is a variable-length encoding.
//
#pragma mark const struct ldapschema_syntax_spec syntax_spec
const struct ldapschema_spec ldapschema_spec[] =
{
   {
      // RFC 4530                     LDAP entryUUID                    June 2006
      //
      // 2.1.  UUID Syntax
      //
      //    A Universally Unique Identifier (UUID) [RFC4122] is a 16-octet (128-
      //    bit) value that identifies an object.  The ASN.1 [X.680] type UUID is
      //    defined to represent UUIDs as follows:
      //
      //        UUID ::= OCTET STRING (SIZE(16))
      //              -- constrained to an UUID [RFC4122]
      //
      //    In LDAP, UUID values are encoded using the [ASCII] character string
      //    representation described in [RFC4122].  For example,
      //    "597ae2f6-16a6-1027-98f4-d28b5365dc14".
      //
      //    The following is an LDAP syntax description suitable for publication
      //    in subschema subentries.
      //
      //        ( 1.3.6.1.1.16.1 DESC 'UUID' )
      //
      .oid           =  "1.3.6.1.1.16.1",
      .name          =  NULL,
      .desc          =  "UUID",
      .flags         =  LDAPSCHEMA_O_READABLE,
      .type          =  LDAPSCHEMA_SYNTAX | LDAPSCHEMA_CLASS_ASCII,
      .def           =  "( 1.3.6.1.1.16.1 DESC 'UUID' )",
      .abnf          =  "UUID               = time-low \"-\"\n"
                        "                     time-mid \"-\"\n"
                        "                     time-high-and-version \"-\"\n"
                        "                     clock-seq-and-reserved\n"
                        "                     clock-seq-low \"-\" node\n"
                        "time-low               = 4hexOctet\n"
                        "time-mid               = 2hexOctet\n"
                        "time-high-and-version  = 2hexOctet\n"
                        "clock-seq-and-reserved = hexOctet\n"
                        "clock-seq-low          = hexOctet\n"
                        "node                   = 6hexOctet\n"
                        "hexOctet               = hexDigit hexDigit\n"
                        "hexDigit = \"0\" / \"1\" / \"2\" / \"3\" / \"4\" /\n"
                        "           \"5\" / \"6\" / \"7\" / \"8\" / \"9\" /\n"
                        "           \"a\" / \"b\" / \"c\" / \"d\" / \"e\" / \"f\" /\n"
                        "           \"A\" / \"B\" / \"C\" / \"D\" / \"E\" / \"F\"\n",
      .re_posix      =  "^([[:xdigit:]]{8,8}(-[[:xdigit:]]{4,4}){3,3}-[[:xdigit:]]{12,12})$",
      .re_pcre       =  NULL,
      .source        =  "RFC 4530 Section 2.1",
      .spec_type     =  LDAPSCHEMA_SPEC_RFC,
      .spec_name     =  "4530",
      .spec_section  =  "2.1",
      .examples      =  (const char *[]){ "597ae2f6-16a6-1027-98f4-d28b5365dc14", NULL },
   },
   {
      // RFC 2252 Section 4.3.2: Syntax Object Identifiers
      .oid           =  "1.3.6.1.4.1.1466.115.121.1.1",
      .name          =  NULL,
      .desc          =  "ACI Item",
      .flags         =  LDAPSCHEMA_O_DEPRECATED,
      .type          =  LDAPSCHEMA_SYNTAX | LDAPSCHEMA_CLASS_UNKNOWN,
      .def           =  NULL,
      .abnf          =  NULL,
      .re_posix      =  NULL,
      .re_pcre       =  NULL,
      .source        =  "RFC 2252 Section 4.3.2",
      .spec_type     =  LDAPSCHEMA_SPEC_RFC,
      .spec_name     =  "2252",
      .spec_section  =  "4.3.2",
      .examples      =  NULL,
   },
   {
      // RFC 2252 Section 4.3.2: Syntax Object Identifiers
      .oid           =  "1.3.6.1.4.1.1466.115.121.1.2",
      .name          =  NULL,
      .desc          =  "Access Point",
      .flags         =  LDAPSCHEMA_O_READABLE | LDAPSCHEMA_O_DEPRECATED,
      .type          =  LDAPSCHEMA_SYNTAX | LDAPSCHEMA_CLASS_ASCII,
      .def           =  NULL,
      .abnf          =  NULL,
      .re_posix      =  NULL,
      .re_pcre       =  NULL,
      .source        =  "RFC 2252 Section 4.3.2",
      .spec_type     =  LDAPSCHEMA_SPEC_RFC,
      .spec_name    =  "2252",
      .spec_section  =  "4.3.2",
      .examples      =  NULL,
   },
   {
      .oid           =  NULL,
      .name          =  NULL,
      .desc          =  NULL,
      .flags         =  0,
      .def           =  NULL,
      .abnf          =  NULL,
      .re_posix      =  NULL,
      .re_pcre       =  NULL,
      .source        =  NULL,
      .spec_type     =  0,
      .spec_name     =  NULL,
      .spec_section  =  NULL,
      .examples      =  NULL,
   },
};

/////////////////
//             //
//  Functions  //
//             //
/////////////////
#pragma mark - Functions


/* end of source file */
