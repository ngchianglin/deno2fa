/* 
  Creates a 32 characters base32 secret (160 bits/20bytes) for TOTP
  Ng Chiang Lin
  Nov 2020

*/

async function getRandomBytes(size:number)
{
    if(size <= 0)
    {
        console.error("Size cannot be zero or negative");
        return null;
    }

    const randevice = await Deno.open("/dev/urandom");
    const buf = new Uint8Array(size);
    const numRead = await Deno.read(randevice.rid, buf);
    Deno.close(randevice.rid);

    if(numRead != size)
    {
        console.error("Unable to get enough bytes from /dev/urandom");
        return null;
    }

    return buf;
}


/* 
Generates a 32 characters base32 secret
*/
async function genSecret()
{
    const base32string = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    const random_bytes = await getRandomBytes(32); 

    if(random_bytes === null)
    {
        console.error("Error getting 32 random bytes");
        Deno.exit(1);
    }

    let index=0;
    let secret='';

    for(let i = 0; i < random_bytes.length; i++)
    {
        index = random_bytes[i] % base32string.length;
        secret += base32string.charAt(index);
    }

    return secret; 
}


function formatSecret(secret:string)
{
    let formatted = '';
    for(let i = 0; i < secret.length; i++)
    {
        formatted += secret.charAt(i); 

        if( (i + 1) % 4 === 0)
        {
            formatted += ' ';
        }

    }

    return formatted.toLowerCase(); 

}

let secret = await genSecret();

console.log(secret);
console.log(formatSecret(secret)); 



