Highly experimental learning project for Rust, drawing from parts of 1Password's [security design whitepaper](https://1passwordstatic.com/files/security/1password-white-paper.pdf). Warning: code is very much in the 'get it working', pre-cleanup/refactor phase.

Implements the various cryptographic exchanges (e.g. `SRP`) necessary for basic (non-OAuth) registration and logging in, with a default user vault created at registration time. Currently working on CRUD for vault items.

Project name translates to 'some passwords' in Esperanto :)

```shell
> mkdir ~/.kelkaj-pasvortoj
```

# Backend
```shell
> cd backend
> docker-compose up -d
> cargo run
```

# CLI
```shell
> cd cli
> cargo run register foobar@example.com
Sending registration request...
Sent! Check backend console for the following:

Invitation ID: 018ce1a5-29d7-7d65-b3df-562900afcf5d
Acceptance token: 4d88e30a75d6d707844506efa79c8819
Account ID: MCVDBE

And now choose your password: ********
...
Registration successful!

> cargo run login foobar@example.com
Enter password: ********
...
Session: 018ce1a7-e278-7eb5-90d3-730b44540ff5
```
