# pam-auth

Safe Rust bindings to Linux Pluggable Authentication Modules (PAM).
Currently only support basic username/password authentication.

## Usage
1. Add `pam-auth` to your Cargo.toml:
```toml
[dependencies]
pam-auth = "0.0.4-pre1"
```
2. Use the static function to login
```rust
extern crate pam_auth;
pub fn main() {
    let service: "<yourapp>";
    let user: "<user>";
    let password: "<pass>";

    let success = pam_auth::login(service, user, pass);
    if success {
        println!("Login succeded!");
    }
    else {
        println!("Login failed =(");
    }
}
```

## TODO:
  - [x] Implement basic user/password authentication
  - [ ] Verify current `conv` does not leak memory
  - [ ] Allow custom `conv` functions to be passed (in pam-sys?)
  - [ ] Code cleanup
