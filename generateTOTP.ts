/* 
  Generates a 6 digit TOTP from a 32 characters base32 secret
  Refer to RFC 6238 https://tools.ietf.org/html/rfc6238
  Ng Chiang Lin
  Nov 2020

*/

import * as base32 from "https://deno.land/std@0.76.0/encoding/base32.ts";
import { createHash } from "https://deno.land/std@0.76.0/hash/mod.ts";


/* 

 Function to generate a SHA1 HMAC.
 Takes a byte array key and byte array input as parameters.
 Returns an array of bytes containing a SHA1 HMAC for the key and input.

 Based on pseudo code description at 
 https://en.wikipedia.org/wiki/HMAC

*/
function hmacSHA1(key:Uint8Array, input:Uint8Array)
{
    const blksize = 64; //64 bytes block size for sha1
    let pkey = key;

    /* Shortens key if it is longer than blksize */
    if (pkey.length > blksize)
    {
        const sha1 = createHash("sha1");
        sha1.update(pkey);
        pkey = new Uint8Array(sha1.digest());
      
    }
    
    if (pkey.length < blksize)
    { //pad to blocksize long with zeros on the right
        let tmpkey = new Uint8Array(blksize);
        for(let i=0; i<blksize; i++)
        {
            if(i < pkey.length)
            {
                tmpkey[i] = pkey[i];
            }
            else
            {
                tmpkey[i] = 0;
            }

        }

        pkey = tmpkey;
    }

    let outer_pkey  = new Uint8Array(blksize);
    let inner_pkey = new Uint8Array(blksize);

    for(let i = 0 ; i < blksize; i++)
    {
        outer_pkey[i] = pkey[i] ^ 0x5c;
        inner_pkey[i] = pkey[i] ^ 0x36;
    }

    let sha1 = createHash("sha1");
    sha1.update(inner_pkey);
    sha1.update(input);
    let sha1_digest = new Uint8Array(sha1.digest());
    

    sha1 = createHash("sha1");
    sha1.update(outer_pkey);
    sha1.update(sha1_digest);
    sha1_digest = new Uint8Array(sha1.digest());

    return sha1_digest;

}


/*
 Converts a hexadcimal string to a byte array
*/
function hexToBytes(hexstr:string)
{

    if(hexstr.length % 2 != 0)
    {
        return null;
    }

    let bytes = new Uint8Array(hexstr.length/2);
    let index = 0; 
    hexstr = hexstr.toLowerCase();

    for(let i=0; i < hexstr.length; i+=2)
    {
        let hbyte = [];
        hbyte.push(hexstr.charAt(i));
        hbyte.push(hexstr.charAt(i+1));
 
        let hexvalue = 0; 

        for(let j=0; j<2;j++)
        {
            switch (hbyte[j])
            {
                case '0':
                    hexvalue |= 0x00;
                    break;
                case '1':
                    hexvalue |= 0x01;
                    break; 
                case '2':
                    hexvalue |= 0x02;
                    break; 
                case '3':
                    hexvalue |= 0x03;
                    break; 
                case '4':
                    hexvalue |= 0x04;
                    break; 
                case '5':
                    hexvalue |= 0x05;
                    break; 
                case '6':
                    hexvalue |= 0x06;
                    break; 
                case '7':
                    hexvalue |= 0x07;
                    break; 
                case '8':
                    hexvalue |= 0x08;
                    break; 
                case '9':
                    hexvalue |= 0x09;
                    break; 
                case 'a':
                    hexvalue |= 0x0a;
                    break; 
                case 'b':
                    hexvalue |= 0x0b;
                    break; 
                case 'c':
                    hexvalue |= 0x0c;
                    break; 
                case 'd':
                    hexvalue |= 0x0d;
                    break; 
                case 'e':
                    hexvalue |= 0x0e;
                    break; 
                case 'f':
                    hexvalue |= 0x0f;
                    break;
                default:
                    console.log("Invalid hex value");
                    return null;
            }

            if(j == 0)
            {
                hexvalue = hexvalue << 4; 
            }

        }

        bytes[index] = hexvalue & 0x00ff;
        index++;

    }

   return bytes;
}


/*
Generates TOTP 
*/
function generateTOTP(secret:string, currenttime:number)
{
   
    if(isBase32Secret(secret) === false)
    {
        console.error("Invalid base32 TOTP secret");
        Deno.exit(1);

    }

    const bin_secret = base32.decode(secret);

    let time_input = Math.floor(Math.trunc((currenttime / 1000 )) /30);
    let time_hexvalue = time_input.toString(16);

    let num_padding = 16 - time_hexvalue.length;
    let padding = '';
    for(let i = 0 ; i<num_padding; i++)
    {
        padding += '0';
    }

    time_hexvalue = padding + time_hexvalue;
    const input_bytes = hexToBytes(time_hexvalue);

    if(input_bytes == null)
    {
        console.error("Error cannot convert time to input bytes");
        Deno.exit(1);
    }

    let hmac_arr = hmacSHA1(bin_secret,input_bytes);
    let last_hash_byte = hmac_arr[hmac_arr.length -1];

    let fa_index = last_hash_byte & 0x0f;

    let fa_code = 0;
    fa_code = fa_code | ( (hmac_arr[fa_index] & 0x7f) << 24 );
    fa_code = fa_code | ( (hmac_arr[fa_index + 1] & 0xff ) << 16 );
    fa_code = fa_code | ( (hmac_arr[fa_index + 2] & 0xff ) << 8 );
    fa_code = fa_code | ( (hmac_arr[fa_index + 3] & 0xff ));

    return fa_code % 1000000; 

}

/* Check for a valid base32 totp secret string */
function isBase32Secret(secret:string)
{
    /* An TOTP secret string needs to be 32 in length*/
    if(secret.length!=32)
    {
        return false;
    }

    for(let i=0; i<secret.length;i++)
    {
        let c = secret.charAt(i);
        if (!isBase32Char(c))
        {
            return false
        }

    }

    return true; 

}

/* 
Check if character is allowed under base32. Note, base32 special character for padding
is not considered. 
*/
function isBase32Char(c:string)
{
    if(c.length != 1)
    {
        console.error("Function only accepts a single string character");
        return false;
    }

    /* 
       Valid Base32 characters without considering special case for padding 
       A-Z 2-7 which is 
       65 to 90  and 50 to 55 in ascii code. Ascii code is also valid in unicode. 
       
    */

    let charcode = c.charCodeAt(0);
    if ( (charcode>=65 && charcode<=90) || (charcode>=50 && charcode<=55) )
    {
        return true;
    }

    return false;
}

/* Format human readable TOTP base32 string for Base32 decoding*/
function formatBase32(humansecret:string)
{
    if(humansecret.length != 39)
    {
        console.error("Secret needs to be in the format xxxx xxxx xxxx xxxx xxxx xxxx xxxx xxxx ");
        console.error("xxxx are base32 characters");
        Deno.exit(1);
    }


    let up_secret = '';
    for(let i=0; i< humansecret.length; i++)
    {
        let c = humansecret.charAt(i);
        if(c != ' ')
        {
            up_secret += c;
        }
    }

    up_secret = up_secret.toUpperCase();     
    return up_secret;

}


if (Deno.args.length != 1)
{
    console.log("Usage:  deno run generateTOTP.ts \"secret\"");
    Deno.exit(1);
}

const currenttime = Date.now();

let secret = formatBase32(Deno.args[0]);
let twofactor = generateTOTP(secret, currenttime);
let time_remaining = Math.trunc((currenttime / 1000 )) %30;
console.log("Time remaining: ", 30 - time_remaining);
console.log(twofactor);