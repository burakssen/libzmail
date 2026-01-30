# libzmail

A low-level Zig email library (SMTP, IMAP, POP3) backed by **libcurl** for robust TLS and networking. Designed for explicit control and predictable memory usage, this is a **protocol and authentication layer**, not a rendering engine.

**Current Support**

* **Protocols:** 
    - [x] Smtp
    - [ ] Imap
    - [ ] POP3
* **Auth:** 
    - [x] Basic
    - [x] OAuth2
        - [x] Google
        - [x] Microsoft
    - [ ] SAML/SSO
