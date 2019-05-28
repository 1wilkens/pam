use std::io::{stdin, stdout, Write};
use std::os::unix::process::CommandExt;
use std::process::Command;

use pam::Authenticator;
use rpassword::read_password_from_tty;
use users::get_user_by_name;

// A simple program that requests a login and a password and then spawns /bin/bash as the
// user who logged in.
//
// Note that this proto-"sudo" is very insecure and should not be used in any production setup,
// it is just an example to show how the PAM api works.

fn main() {
    // First, prompt the user for a login and a password
    print!("login: ");
    stdout().flush().unwrap();
    let mut login = String::new();
    stdin().read_line(&mut login).unwrap();
    login.pop(); // remove the trailing '\n'
    let password = read_password_from_tty(Some("password: ")).unwrap();

    // Now, setup the authenticator, we require the basic "system-auth" service
    let mut authenticator =
        Authenticator::with_password("system-auth").expect("Failed to init PAM client!");
    authenticator
        .handler_mut()
        .set_credentials(login.clone(), password);
    authenticator
        .authenticate()
        .expect("Authentication failed!");
    authenticator
        .open_session()
        .expect("Failed to open a session!");

    // we now try to spawn `/bin/bash` as this user
    // note that setting the uid/gid is likely to fail if this program is not already run as the
    // proper user or as root
    let user = get_user_by_name(&login).unwrap();
    let error = Command::new("/bin/bash")
        .uid(user.uid())
        .gid(user.primary_group_id())
        .exec();
    // if exec() returned, this means there was an error:
    println!("Error spawning bash: {:?}", error);
}
