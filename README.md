# samlogin
[![Build Status](https://travis-ci.org/bgshacklett/samlogin.svg?branch=master)](https://travis-ci.org/bgshacklett/samlogin)  
This tool uses Puppeteer (https://github.com/GoogleChrome/puppeteer) to
intercept SAML logins to AWS and store the credentials in a credentials file.

`samlogin` was inspired heavily by the SAML to STS Keys extension
(https://github.com/prolane/samltoawsstskeys) by G.T.C. (Gerard) Laan.

## Installation
1. Install Node.js (tested on v8.11.4).
2. Clone the project repository to your preferred location.
3. Navigate to the project directory.
4. Install the package dependencies with `yarn install` or `npm install`.
5. Create your configuration file in the project directory.

## Configuration
Configuration is managed with a yaml file. samlogin will attempt to find the
configuration file in the following paths (in order):
  1. An exact path specified by the `--config` parameter
  2. `%LOCALAPPDATA\samlogin\config.yaml`
  3. `$XDG_CONFIG_HOME/samlogin/config.yaml`
  4. `$HOME/Library/Preferences/samlogin/config.yaml`
  5. `~/.samlogin.yaml`

### Configuration Keys
* `AuthUrl` - The URL of your Identity Provider which accepts your credentials
* `AccountAliases` - A sequence of maps from account number to alias
* `DurationSeconds` - A number of seconds (less then the configured max duration) for the session to be active for

An example configuration:
```
---
# Example Configuration File

AuthUrl:  # The login URL of your IDP - E.g.:
          # https://accounts.google.com/o/saml2/init.sso?...

# Use "Prod" in place of 123456789012 and Dev in place of 210987654321in the
# profile name.
AccountAliases:
  - AccountNumber: '123456789012'
    Alias: Prod
  - AccountNumber: '210987654321'
    Alias: Dev
    DurationSeconds: 28800
```

## Usage
`samlogin [--config <path>]`

Calling the command will launch an embedded instance of Chromium and navigate
to `AuthUrl`. Once you log in, your IDP will forward the browser to the AWS
SAML endpoint and the credentials will be intercepted and written to
`~/.aws/credentials`.
