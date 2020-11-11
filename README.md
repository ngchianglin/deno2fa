# deno2fa
Simple 2 Factor Authentication using Deno


## Introduction

Simple typescript programs to generate TOTP code using [Deno](https://deno.land/), a secure runtime for javascript and typescript.
The programs use Deno built in functions and Deno standard library.  

generateTOTP.js generates a 6 digit TOTP code valid for 30 seconds. It takes a base32 secret as a command line argument. 

generateSecret.ts creates a base32 secret key that can be used for generating TOTP. The secret key can be entered into Google Authenticator as well. To get the random bytes required, generateSecret.ts uses the /dev/urandom device on Linux. 



## Running the programs

To generate a base32 secret key

    deno run --allow-read=/dev/urandom generateSecret.ts

To generate a 6 digit TOTP code

    deno run generateTOTP.ts "xxxx xxxx xxxx xxxx xxxx xxxx xxxx xxxx"

"xxxx ... " is the base32 secret. 

The code in these 2 programs can be easily integrated into other Deno applications that requires 2 factor authentication. 


## Further Details
Refer to
[https://nighthour.sg/articles/2020/two-factor-authentication-using-deno.html](https://nighthour.sg/articles/2020/two-factor-authentication-using-deno.html)
for more details.

## Source signature
Gpg Signed commits are used for committing the source files.

> Look at the repository commits tab for the verified label for each commit, or refer to [https://www.nighthour.sg/git-gpg.html](https://www.nighthour.sg/git-gpg.html) for instructions on verifying the git commit.
>
> A userful link on how to verify gpg signature is available at [https://github.com/blog/2144-gpg-signature-verification](https://github.com/blog/2144-gpg-signature-verification)
