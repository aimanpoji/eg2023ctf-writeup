# eg2023ctf writeup

# Programming

## RIGOROUS

Extracting flag.zip we will get 5 txt files named and content respectively:

- [^a-zA-Z0-9_].apk.txt
```
^(\\S+)\\s+(\\S+)$ || D'`;M#8n<;G3zx6Te@,PqMo:n%*#(4hffBA.~}+{)9rqvutsl2pohPle+ihJIedcb[!_^@VUTYRQPtTSRQ3ONGkjW
```

- [^a-zA-Z0-9_].exe.txt
```
^(\\S+)\\s+(\\S+)$ || D'`%_9"=[l:{8VC54uQ>0).:]%$ki!g21{"cx}O<)srwp6tsrkpongf,jiKgf_%F\[`_^]VzZ<;WVOsMRQJnH0LEJCBf)?DC<;_L
```

-  [^a-zA-Z0-9_].ipa.txt
```
^(\\S+)\\s+(\\S+)$ || D'``_9"n[HX9ih6fe3,sN)LoJ87jGX~DeASc~a_N):rqvutsl2johgfkjc)gIH^]\"`_A@\Uy<;QPt76LpP2NMLKDhHGF?>bO
```

- [^a-zA-Z0-9_].osx.txt
```
^(\\S+)\\s+(\\S+)$ || D'`N@9>~ZZXXyV6Tuu2rNM;:&+H6GiWfBTzcaP|N)y[wpunsl2pohglkjiba'edFb[!_^@?UTxRQPOTSLpP2NMLEDhU
```

- Formula.txt
```
apk: f(x) = sin(x^2 + 1) + 1
ipa: 2
exe: 3
osx: 4
```

After doing some googling using the hint given, i found out that it is a programming language written in malbolge. So using malbolge online [compiler](https://www.tutorialspoint.com/execute_malbolge_online.php) to see the output of each code:

```
apk: RUd7TT
exe: NfMVNfSD
ipa: RMQjBMRz
osx: RSRH0
```

The output is in base64. So we will need to decrypt the strings but first look at Formula.txt. There is an equation at apk that equal to 1. It seems like we need to put the base64 strings in order.

```
apk -> ipa -> exe -> osx
```

So the base64 string would be like this:
```
RUd7TTRMQjBMRzNfMVNfSDRSRH0
```

Decrypt the base64 strings and we get the flag.



# Crypto
## Super Secure Encryption

Question:
```
seead%3L%2Q%2Qjzfef.mp%2QL8514L7O0N7N5724L545712M031P42O5M545O5023N1P96M49924079N219041PM5MPO7M4PQ52568612N9M0M12877P43293LNM5892P1NO75P88327N095MN3398P4

secret key = ryvgrtubfggggggg
```

<img width="576" alt="Pasted image 20230114161521" src="https://user-images.githubusercontent.com/34196370/212496363-df4d7e89-f8ff-4f12-a24e-c4b074427025.png">

In flag.txt, there are  long strings and secretkey. Also we were given an image. Looking at that image given we know that it is the Visualization of the AES round function after some googling. So we need to decrypt the aes cipher in the text file. But, the long strings provided is not a valid aes cipher because it does not appear to be a properly encoded ciphertext, as it contains a mix of letters, numbers and special characters. 

From the hint given, I found out that the strings was rotated and the result is:
```
https%3A%2F%2Fyoutu.be%2FA8514A7D0C7C5724A545712B031E42D5B545D5023C1E96B49924079C219041EB5BED7B4EF52568612C9B0B12877E43293ACB5892E1CD75E88327C095BC3398E4
```

It turns out that it is a youtube link but url encoded. Lets url decode it:

```
https://youtu.be/A8514A7D0C7C5724A545712B031E42D5B545D5023C1E96B49924079C219041EB5BED7B4EF52568612C9B0B12877E43293ACB5892E1CD75E88327C095BC3398E4
```

but it is not a valid youtube link because as I know that a valid one would be not as long as that. Seems like it is an aes chipher text. I tried to decrypt it using the key given but failed. Turns out that the key is also rotated and after decoding the key, we can decrypt the cipher text:

```
Cipher: A8514A7D0C7C5724A545712B031E42D5B545D5023C1E96B49924079C219041EB5BED7B4EF52568612C9B0B12877E43293ACB5892E1CD75E88327C095BC3398E4

Secret Key: eliteghosttttttt

```

Result after decrypting the aes cipher text and we will get a base64 string:
```
TVRFMUlEWTJJREV4TnlBeE1UQWdNVEUwSURVMElEY3dJRGN3SURVM0lEZ3hJRGc1Q2c9PQ==
```

Decode the base64 string we get decimals:
```
115 66 117 110 114 54 70 70 57 81 89
```

Convert the decimals to ASCII:
```
sBunr6FF9QY
```

The valid youtube link would be like this:
```
https://youtu.be/sBunr6FF9QY
```

The link lands to a video titled [The Feeling That Never Gets Old.](https://youtu.be/sBunr6FF9QY) The flag is at 2:25 where a pastebin link will pop up very fast. I got it using my sharingan eye xp


<img width="836" alt="Pasted image 20230114164349" src="https://user-images.githubusercontent.com/34196370/212496414-4a451462-260d-43a3-a30a-f255c70dc2e1.png">


## Bitcoin
Question:
```
password = formula = cut •(0,2.646) , cut •(0,-2.646)  → av = ascii value  → av7331 + 1337.
```

In password.btc there is a formula. This appears to be a formula for generating a password.  The formula starts with two points given, which needed to find an alphabet from a graph later and calculates the ASCII value of the alphabet. Then the password would be the ascii value multiply with 7331 and add 1337 to it. The password later will be used to extract the flag in _Bitcoin.jpg_.

First we need to find the value of elliptic curve cryptography(ECC) for bitcoin. 
After doing some research, I found that the ECC used in Bitcoin's cryptography is called secp256k1 which uses this equation:

```
y²=x³+7
```

Using this equation, we can get the shape of the curve for ECC in bitcoin:

<img width="403" alt="Pasted image 20230114170129" src="https://user-images.githubusercontent.com/34196370/212496435-553487b3-3921-49bb-9c1b-9d5c4b8788b1.png">


From the formula, we can see that there are two graph points were given (x,y) as follows:

```
(0,2.646)
(0,-2.646)
```

Then plot the lines for these two points where first line x=0, y= 2.646 and second line x=0,y=-2.646. Result:

<img width="673" alt="Pasted image 20230114170516" src="https://user-images.githubusercontent.com/34196370/212496449-0f4b768b-b8b5-4115-a3bb-01cc2f4db8af.png">

It turns out the alphabet is letter _C_. The ascii value of C is 67. Then we can include it into the next calculation to get the password:

```
av=70
67(7331)+1337= 492514
```

Use the result from the calculation to extract the flag in Bitcoin.jpg using steghide.

```
> steghide --extract -sf Bitcoin.jpg
Enter passphrase: 492514
wrote extracted data to "steganopayload3550.txt"
```

## Vault2.0
Question
```
HAI 1.2CAN H…BYE
UNV->;?PN[-UN`-`aQV\LV-UN`-N-N-Vag->@@DV-UN`-N-O-Vag-D@@>V-UN`-N-P-Vag->E?@V-UN`-N-Q-Vag-?D@CV-UN`-N-R-Vag-?@D=V-UN`-N-S-Vag-FFFFV-UN`-N-]N``P\QR]N``P\QR-_-`bZ-\S-N-N[-O9-QVSS-\S-P-N[-Q9-]_\QbXa-\S-N-N[-O9-^b\`Ub[a-\S-R-N[-ScV`VOYR-/aur-}n☺☺p|qr-v☺G-/-N[-]N``P\QRV-UN`-N-e-Vag-@;>AVZ-V[-f_-Y\\]-b]]V[-f_-e-aVY-O\aU-`NRZ-e-N[-A;>A--VZ-V[-f_-Y\\]-b]]V[-f_-e-aVY-O\aU-`NRZ-e-N[-A;>A--f_-e-_-`bZ-\S-e-N[-=;=>VZ-\baaN-f_-Y\\]TVZZRU-eXaUeOfR
```

We are given 2 attachments, flag.zip which is password protected and passcode.txt
Opening the passcode.txt gives us a long strings.
From the hint, the code was some [lolcode](https://en.wikipedia.org/wiki/LOLCODE) and it have been encoded in some way. Turns out the strings was encoded using [ascii-shift-cipher](https://www.dcode.fr/ascii-shift-cipher). Result:

```
HAI 1.2CAN HAS STDIO?I HAS A A ITZ 1337I HAS A B ITZ 7331I HAS A C ITZ 1823I HAS A D ITZ 2736I HAS A E ITZ 2370I HAS A F ITZ 9999I HAS A PASSCODEPASSCODE R SUM OF A AN B, DIFF OF C AN D, PRODUKT OF A AN B, QUOSHUNT OF E AN FVISIBLE "The pacode i: " AN PASSCODEI HAS A X ITZ 3.14IM IN YR LOOP UPPIN YR X TIL BOTH SAEM X AN 4.14  IM IN YR LOOP UPPIN YR X TIL BOTH SAEM X AN 4.14  YR X R SUM OF X AN 0.01IM OUTTA YR LOOPGIMMEH XKTHXBYE
```

 Beautify the plaintext code, and here's the result:
 
```
HAI 1.2
CAN HAS STDIO?
I HAS A A ITZ 1337
I HAS A B ITZ 7331
I HAS A C ITZ 1823
I HAS A D ITZ 2736
I HAS A E ITZ 2370
I HAS A F ITZ 9999
I HAS A PASSCODE
PASSCODE R SUM OF A AN B, DIFF OF C AN D, PRODUKT OF A AN B, QUOSHUNT OF E AN F 
VISIBLE "The pacode i: " AN PASSCODE
I HAS A X ITZ 3.14
IM IN YR LOOP UPPIN YR X TIL BOTH SAEM X AN 4.14  
IM IN YR LOOP UPPIN YR X TIL BOTH SAEM X AN 4.14 YR 
X R SUM OF X AN 0.01
IM OUTTA YR LOOP
IM OUTTA YR LOOP
GIMMEH X
KTHXBYE
```

We want the passcode, hence we can ignore the code from line 12 until line 17 as it held nothing to solving the passcode. The passcode consist of 4 equations and the values respectively:

```
SUM OF A AN B = 8668

DIFF OF C AN D = -913

PRODUKT OF A AN B = 9801547

QUOSHUNT OF E AN F = 0.2370237
```

Apparently from the description, we were given a format for the password:

```
xxxx--xxx-xxxxxxx-x.xxxxxxx
```

Put the numbers accordingly and use the passcode to extract the flag in flag.zip

```
8668--913-9801547-0.2370237
```

## Nikola Tesla
Question
```
Formula:

(x,y,z) , n = 27, fp = final position, av = ascii value.

(x,y,z) = fp. • (x,y,z), • (x+23,y+0,z+(5x4)).

av1337 = r . → r = n%r

[password](https://eliteghost.tech/ctf/nikolaTeslaPass/pass.txt)= 

r(7331) + r(1337) + r^4
```

We need to find the password for the zip file named flag.zip. From the formula above we know that (x,y,z) represents coordinate to plot in a 3d graph. From the hints given we will need to find the alphabet in the graph and then converts it to ascii value.


We were given an asm file named coordinate.asm and calculate the value for each registers(x,y,z):

```
mov x, 5
mov y, 6
mov z, 7
add x, y = 11
mul x, z = 77
sub z, x = -70
div z, y = -11.66
```

So the value for our first coordinate is:

```
(x,y,z)
(77,6,-11.66)
```

Then includes the values into the next formula to find the next coordinate. From hints given, we know that the both z axis are -ve direction:

```
(x+23,y+0,z+(5x4))
(77+23,6+0,-(11.66+(5x4)))
(100,6,-31.66)
```

So the graph will look like this:

<img width="776" alt="Pasted image 20230114184603" src="https://user-images.githubusercontent.com/34196370/212496468-0a322fb9-7e80-41c6-954a-ee27ebc11ccb.png">

From this graph we know that av = "F" in ascii value it will be 70. Since we have the value of av, we can proceed to the next formula to find the initial value of r:

```
av1337 = r 
70(1337)= r
93590 = r
```

Then find the new r where n = 27 which included in the formula:

```
. → r = n%r
r = 27%93590
93,590 / 27 = 3,466 remainder = 8 = r
```

After that we just includes the value of the new r into the last formula which is the password:

```
password = r(7331) + r(1337) + r^4
password = 8(7331) +8(1337) + 8^4 = 73440
```

The [password](https://eliteghost.tech/ctf/nikolaTeslaPass/pass.txt) format is given in the description. So the final password is:

```
Az09KANnxjhs-73440-Reverse-Engineering
```

Use the password to extract the flag in flag.zip.

# Web
## FunFair

We were given a website [https://eliteghost.tech/fun-fair/](https://eliteghost.tech/fun-fair/).

<img width="1603" alt="Pasted image 20230114190949" src="https://user-images.githubusercontent.com/34196370/212496481-b4f3ae0f-5c3a-477c-9180-6fccb0bbd066.png">

Lets check for any error if we give wrong input:

<img width="1143" alt="Pasted image 20230114191051" src="https://user-images.githubusercontent.com/34196370/212496492-fb57352d-e9f4-4ed7-ba9b-5f7b441ba806.png">

Aha, so we need to give the correct phrase. To find the correct phrase we will need to intercept the request send it to intruder and start bruteforcing:

<img width="536" alt="Pasted image 20230114200626" src="https://user-images.githubusercontent.com/34196370/212496508-0035c66d-6665-4103-abb2-254046670b9a.png">

We got the correct phrase which is `success`. But now it gives us new error:

<img width="890" alt="Pasted image 20230114200750" src="https://user-images.githubusercontent.com/34196370/212496522-666c61d8-edec-40e6-a807-50651abfd4e9.png">

So we know now we gonna need a valid token. Now lets check for other directories using dirb and we get:

```
https://eliteghost.tech/fun-fair/cookies/
https://eliteghost.tech/fun-fair/hacking/
```

Lets check what is in cookies/

<img width="963" alt="Pasted image 20230114201816" src="https://user-images.githubusercontent.com/34196370/212496550-f7d1e543-6a5c-4e8c-9720-95dfe1c6af8a.png">

Aha, so we need to set the cookie to:

```
cookie name: FunFair
value: horsewheel
```

Then let’s check on hacking/

<img width="1175" alt="Pasted image 20230114201856" src="https://user-images.githubusercontent.com/34196370/212496561-b80691f4-7f03-4938-a7c5-ffb4ad1c5d58.png">

So the valid token is in this site. Now lets check the source code. The site doesnt allow us to right click to inspect element. But, we can bypass this by adding `view-source` at the beginning of the url and we get the source code. Scroll down untill u see a long base64 strings:

```
view-source:https://eliteghost.tech/fun-fair/hacking/
```

<img width="1476" alt="Pasted image 20230114202208" src="https://user-images.githubusercontent.com/34196370/212496571-617ec75b-5997-4a3c-af05-991e0179aff2.png">

Decode the strings and put it into token input and click generate token. Now everything is set:

<img width="599" alt="Pasted image 20230114202733" src="https://user-images.githubusercontent.com/34196370/212496580-a1cf4c7c-88ac-47af-80c8-aec0108f2fcb.png">

Send the request and we get the flag which is in base64:

<img width="1451" alt="Pasted image 20230114202757" src="https://user-images.githubusercontent.com/34196370/212496590-86c5e96a-2d71-4c08-87a7-9d00b9567b95.png">


## Digital Karma
Going to the link will land us to a login page:

<img width="450" alt="Pasted image 20230114203523" src="https://user-images.githubusercontent.com/34196370/212496604-0067a6f5-f764-4168-b2e1-6ffdde0e398c.png">

If we give the wrong input the page redirect us to [https://eliteghost.tech/ctf/web/sourceorsauce/](https://eliteghost.tech/ctf/web/sourceorsauce/) with 404 not found page:

<img width="708" alt="Pasted image 20230114203737" src="https://user-images.githubusercontent.com/34196370/212496613-b3a43eed-dfac-4801-a05f-17748fc417cd.png">

So I check for the source code for any authentication checking but got nothing. To check the source we cannot right click to inspect element, we can use the same method as we do for funfair challenge or intercept response request on burp.
We can see that it only checks if the user or/and password field is empty. Also the page is disabling the ability for  user to select text, as well as disabling the right-click context menu:

<img width="463" alt="Pasted image 20230114204553" src="https://user-images.githubusercontent.com/34196370/212496620-7958d325-2017-4848-affe-c1e90c71a912.png">

<img width="490" alt="Pasted image 20230114204411" src="https://user-images.githubusercontent.com/34196370/212496638-bdaae22d-145b-4413-97ac-9cad74184b93.png">


After that i decided to  fuzz the directory using dirb, we get /admin page that has directory listing:

<img width="650" alt="Pasted image 20230114204912" src="https://user-images.githubusercontent.com/34196370/212496712-66398080-ba48-41c7-9c9e-e57f75558254.png">

But the content in both directory returns:

<img width="168" alt="Pasted image 20230114204937" src="https://user-images.githubusercontent.com/34196370/212496724-86645126-454b-4f0e-ae83-2542ef3886c0.png">

From the hint, we know that there is js script somewhere. So we can fuzz recursively for js file using ffuf with this [wordlist]([https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/SVNDigger/cat/Language/js.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/SVNDigger/cat/Language/js.txt)) at admin/user/ and admin/pass/. Aha, we got a hit at admin/user/ there is a file named `script.js`:

<img width="452" alt="Pasted image 20230114205312" src="https://user-images.githubusercontent.com/34196370/212497025-d3e0fa80-d99d-4e3c-a58b-09fd91e1ec68.png">

Lets view the content of `script.js` file and we found strings which could be the username and password for the login page:

<img width="1012" alt="Pasted image 20230114205616" src="https://user-images.githubusercontent.com/34196370/212496659-7c5db2fb-5621-4bcf-916f-059ca16a91ba.png">

Test the credential found at the login page and we will be redirected to different page sourceorsauce/memberjaya.php:

<img width="444" alt="Pasted image 20230114205914" src="https://user-images.githubusercontent.com/34196370/212496674-181ac551-f825-4f8b-a984-92956e860367.png">

<img width="836" alt="Pasted image 20230114210112" src="https://user-images.githubusercontent.com/34196370/212496683-9494cb4e-1bfc-44af-bec3-07f7c87045b4.png">

Go to  `digitalkarma/memberjaya.php` instead of `sourceorsauce/memberjaya.php`and we are through:

<img width="774" alt="Pasted image 20230114210516" src="https://user-images.githubusercontent.com/34196370/212496691-1c7508a5-070d-4860-9e72-6d6b55d4e09f.png">

<img width="362" alt="Pasted image 20230114210556" src="https://user-images.githubusercontent.com/34196370/212496700-334b0f53-d087-457c-86d2-caa141a00e2a.png">
